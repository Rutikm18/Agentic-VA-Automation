"""
Unit tests for the Active Directory assessment module (Prompt 5).

All directory/Kerberos/SMB access is mocked, so these tests run without ldap3,
impacket, neo4j, or a live domain. They exercise the pure logic: UAC parsing,
ESC detection, signing posture, and Finding generation (MITRE/CWE/repro/
detection/remediation contract).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.ad.adcs import ADCSChecker, CertTemplate
from app.ad.asreproast import ASREPRoastChecker
from app.ad.bloodhound import BloodHoundCollector
from app.ad.findings import (
    UAC_DONT_REQ_PREAUTH,
    UAC_SERVER_TRUST_ACCOUNT,
    build_ad_finding,
)
from app.ad.kerberoast import KerberoastChecker
from app.ad.ldap_enum import ACE, ADUser, LDAPEnumerator, _domain_to_base_dn
from app.ad.ntlm_relay import NTLMRelayChecker
from app.models.enums import FindingSeverity, FindingStatus


# ── Fake ldap3 entry plumbing ─────────────────────────────────────────────────

class _FakeAttr:
    def __init__(self, value):
        self.value = value


class _FakeEntry:
    def __init__(self, attrs: dict, dn: str = ""):
        self._attrs = attrs
        self.entry_dn = dn

    def __getitem__(self, key):
        return _FakeAttr(self._attrs.get(key))


def _enum_with_entries(entries):
    enum = LDAPEnumerator()
    enum._base_dn = "DC=corp,DC=local"
    enum._domain = "corp.local"
    enum._conn = MagicMock()
    enum._search = MagicMock(return_value=entries)
    return enum


# ═══════════════════════════════════════════════════════════════════════════════
# build_ad_finding contract
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildADFinding:

    def test_required_fields_present(self):
        f = build_ad_finding(
            title="t", severity="high", description="d",
            mitre_techniques=["T1558.003"], reproduction=["step"],
            detection_opportunity="detect", remediation="fix", cwe="CWE-522",
        )
        assert f["severity"] == FindingSeverity.high
        assert f["status"] == FindingStatus.open
        assert f["mitre_techniques"] == ["T1558.003"]
        assert f["remediation"] == "fix"
        ev = f["evidence"]
        assert ev["cwe"] == "CWE-522"
        assert ev["reproduction_steps"] == ["step"]
        assert ev["detection_opportunity"] == "detect"
        assert ev["category"] == "active_directory"

    def test_invalid_severity_falls_back_to_info(self):
        f = build_ad_finding(
            title="t", severity="bogus", description="d",
            mitre_techniques=[], reproduction=[], detection_opportunity="x",
            remediation="y",
        )
        assert f["severity"] == FindingSeverity.info

    def test_attack_narrative_carried_in_evidence(self):
        f = build_ad_finding(
            title="t", severity="high", description="d", mitre_techniques=[],
            reproduction=[], detection_opportunity="x", remediation="y",
            attack_narrative="ntlmrelayx.py ...",
        )
        assert f["evidence"]["attack_narrative"] == "ntlmrelayx.py ..."


# ═══════════════════════════════════════════════════════════════════════════════
# LDAPEnumerator parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestLDAPEnumeratorParsing:

    def test_domain_to_base_dn(self):
        assert _domain_to_base_dn("corp.local") == "DC=corp,DC=local"
        assert _domain_to_base_dn("a.b.c.d") == "DC=a,DC=b,DC=c,DC=d"

    def test_get_users_parses_uac_and_spn(self):
        entry = _FakeEntry({
            "sAMAccountName": "svc_sql",
            "objectSid": "S-1-5-21-1-1-1100",
            "memberOf": ["CN=Domain Admins,..."],
            "servicePrincipalName": ["MSSQLSvc/sql01:1433"],
            "userAccountControl": UAC_DONT_REQ_PREAUTH,  # pre-auth not required
            "adminCount": 1,
        }, dn="CN=svc_sql,DC=corp,DC=local")
        enum = _enum_with_entries([entry])

        users = enum.get_users()
        assert len(users) == 1
        u = users[0]
        assert u.samaccountname == "svc_sql"
        assert u.no_preauth is True
        assert u.admin_count is True
        assert u.spn == ["MSSQLSvc/sql01:1433"]
        assert u.enabled is True

    def test_get_users_disabled_account(self):
        entry = _FakeEntry({
            "sAMAccountName": "old",
            "userAccountControl": 0x2,  # ACCOUNTDISABLE
        })
        users = _enum_with_entries([entry]).get_users()
        assert users[0].enabled is False
        assert users[0].no_preauth is False

    def test_get_computers_flags_dc(self):
        dc = _FakeEntry({
            "dNSHostName": "DC01.corp.local",
            "operatingSystem": "Windows Server 2022",
            "userAccountControl": UAC_SERVER_TRUST_ACCOUNT,
            "primaryGroupID": 516,
        })
        member = _FakeEntry({
            "dNSHostName": "WS01.corp.local",
            "operatingSystem": "Windows 11",
            "userAccountControl": 0x1000,
            "primaryGroupID": 515,
        })
        comps = _enum_with_entries([dc, member]).get_computers()
        by_host = {c.hostname: c for c in comps}
        assert by_host["DC01.corp.local"].is_dc is True
        assert by_host["WS01.corp.local"].is_dc is False

    def test_get_groups_marks_privileged(self):
        g1 = _FakeEntry({"sAMAccountName": "Domain Admins", "member": ["CN=a"]})
        g2 = _FakeEntry({"sAMAccountName": "Helpdesk", "member": []})
        groups = _enum_with_entries([g1, g2]).get_groups()
        by_name = {g.name: g for g in groups}
        assert by_name["Domain Admins"].is_privileged is True
        assert by_name["Helpdesk"].is_privileged is False

    def test_search_without_connection_raises(self):
        enum = LDAPEnumerator()
        with pytest.raises(Exception):
            enum.get_users()


# ═══════════════════════════════════════════════════════════════════════════════
# KerberoastChecker
# ═══════════════════════════════════════════════════════════════════════════════

class TestKerberoastChecker:

    def setup_method(self):
        self.checker = KerberoastChecker()

    def _ldap_with_users(self, users):
        ldap = MagicMock()
        ldap.get_users.return_value = users
        ldap.connection = None
        return ldap

    def test_get_spn_accounts_filters_krbtgt_and_no_spn(self):
        users = [
            ADUser(samaccountname="svc_web", spn=["HTTP/web01"]),
            ADUser(samaccountname="krbtgt", spn=["kadmin/changepw"]),
            ADUser(samaccountname="alice", spn=[]),
        ]
        accounts = self.checker.get_spn_accounts(self._ldap_with_users(users))
        names = [a["username"] for a in accounts]
        assert names == ["svc_web"]

    def test_finding_critical_when_privileged(self):
        accounts = [{"username": "svc_da", "spn": ["x"], "admin_count": True}]
        f = self.checker.generate_finding(accounts)
        assert f["severity"] == FindingSeverity.critical
        assert f["mitre_techniques"] == ["T1558.003"]
        assert f["exploitable"] is True
        assert "not cracked" in f["evidence"]["note"]

    def test_finding_high_when_not_privileged(self):
        accounts = [{"username": "svc_web", "spn": ["x"], "admin_count": False}]
        f = self.checker.generate_finding(accounts)
        assert f["severity"] == FindingSeverity.high

    def test_no_finding_when_empty(self):
        assert self.checker.generate_finding([]) is None

    def test_request_tgs_without_impacket_returns_none(self, monkeypatch):
        monkeypatch.setattr("app.ad.kerberoast._HAS_IMPACKET", False)
        out = self.checker.request_tgs("svc", "HTTP/x", "10.0.0.1", "corp.local", {})
        assert out is None


# ═══════════════════════════════════════════════════════════════════════════════
# ASREPRoastChecker
# ═══════════════════════════════════════════════════════════════════════════════

class TestASREPRoastChecker:

    def setup_method(self):
        self.checker = ASREPRoastChecker()

    def test_get_no_preauth_accounts(self):
        ldap = MagicMock()
        ldap.get_users.return_value = [
            ADUser(samaccountname="vuln", no_preauth=True, enabled=True),
            ADUser(samaccountname="safe", no_preauth=False, enabled=True),
            ADUser(samaccountname="disabled", no_preauth=True, enabled=False),
        ]
        assert self.checker.get_no_preauth_accounts(ldap) == ["vuln"]

    def test_finding_shape(self):
        f = self.checker.generate_finding(["vuln1", "vuln2"])
        assert f["severity"] == FindingSeverity.high
        assert f["mitre_techniques"] == ["T1558.004"]
        assert f["evidence"]["accounts"] == ["vuln1", "vuln2"]

    def test_no_finding_when_empty(self):
        assert self.checker.generate_finding([]) is None

    def test_request_asrep_without_impacket(self, monkeypatch):
        monkeypatch.setattr("app.ad.asreproast._HAS_IMPACKET", False)
        assert self.checker.request_asrep("u", "10.0.0.1", "corp.local") is None


# ═══════════════════════════════════════════════════════════════════════════════
# NTLMRelayChecker
# ═══════════════════════════════════════════════════════════════════════════════

class TestNTLMRelayChecker:

    def setup_method(self):
        self.checker = NTLMRelayChecker()

    def test_smb_signing_without_impacket_marks_unreachable(self, monkeypatch):
        monkeypatch.setattr("app.ad.ntlm_relay._HAS_IMPACKET", False)
        result = self.checker.check_smb_signing(["10.0.0.5", "10.0.0.6"])
        assert result["10.0.0.5"]["reachable"] is False
        assert result["10.0.0.5"]["signing_required"] is False

    def test_finding_includes_ntlmrelayx_command(self):
        f = self.checker.generate_finding(["10.0.0.5", "10.0.0.6"])
        assert f["mitre_techniques"] == ["T1557.001"]
        assert "ntlmrelayx" in f["evidence"]["ntlmrelayx_command"]
        assert "ntlmrelayx" in f["evidence"]["attack_narrative"]
        assert f["evidence"]["unsigned_hosts"] == ["10.0.0.5", "10.0.0.6"]

    def test_finding_for_ldap_signing_only(self):
        f = self.checker.generate_finding([], ldap_signing_enforced=False)
        assert f is not None
        assert "LDAP signing" in f["title"]

    def test_no_finding_when_all_secure(self):
        assert self.checker.generate_finding([], ldap_signing_enforced=True) is None


# ═══════════════════════════════════════════════════════════════════════════════
# ADCSChecker — ESC1 / ESC4 / ESC8
# ═══════════════════════════════════════════════════════════════════════════════

class TestADCSChecker:

    def setup_method(self):
        self.checker = ADCSChecker()

    def test_esc1_positive(self):
        t = CertTemplate(
            name="VulnTemplate",
            enrollee_supplies_subject=True,
            client_auth=True,
            enrollment_principals=["S-1-5-11"],  # Authenticated Users
        )
        assert self.checker.check_esc1(t) is True

    def test_esc1_negative_when_manager_approval(self):
        t = CertTemplate(
            name="Safe", enrollee_supplies_subject=True, client_auth=True,
            enrollment_principals=["S-1-5-11"], requires_manager_approval=True,
        )
        assert self.checker.check_esc1(t) is False

    def test_esc1_negative_without_low_priv_enrollment(self):
        t = CertTemplate(
            name="AdminOnly", enrollee_supplies_subject=True, client_auth=True,
            enrollment_principals=["S-1-5-21-x-512"],  # Domain Admins
        )
        assert self.checker.check_esc1(t) is False

    def test_esc4_positive(self):
        t = CertTemplate(
            name="WritableTemplate",
            aces=[ACE(trustee_sid="S-1-5-11", ace_type="ALLOW", rights=["GenericAll"])],
        )
        assert self.checker.check_esc4(t) is True

    def test_esc4_negative_when_deny_ace(self):
        t = CertTemplate(
            name="T",
            aces=[ACE(trustee_sid="S-1-5-11", ace_type="DENY", rights=["GenericAll"])],
        )
        assert self.checker.check_esc4(t) is False

    def test_esc8_positive(self):
        assert self.checker.check_esc8({
            "web_enrollment": True, "ntlm_enabled": True,
            "epa_enforced": False, "https_only": False,
        }) is True

    def test_esc8_negative_with_epa_and_https(self):
        assert self.checker.check_esc8({
            "web_enrollment": True, "ntlm_enabled": True,
            "epa_enforced": True, "https_only": True,
        }) is False

    def test_esc8_negative_no_web_enrollment(self):
        assert self.checker.check_esc8({"web_enrollment": False}) is False

    def test_generate_findings_produces_esc1_and_esc8(self):
        esc1 = CertTemplate(
            name="V", enrollee_supplies_subject=True, client_auth=True,
            enrollment_principals=["S-1-5-11"],
        )
        findings = self.checker.generate_findings(
            [esc1], ca_config={"web_enrollment": True, "ntlm_enabled": True,
                               "epa_enforced": False, "https_only": False},
        )
        titles = " ".join(f["title"] for f in findings)
        assert "ESC1" in titles
        assert "ESC8" in titles
        for f in findings:
            assert f["mitre_techniques"]  # all carry a MITRE technique
            assert f["remediation"]


# ═══════════════════════════════════════════════════════════════════════════════
# BloodHoundCollector finding generation
# ═══════════════════════════════════════════════════════════════════════════════

class TestBloodHoundCollector:

    def setup_method(self):
        self.bh = BloodHoundCollector()

    def test_da_path_finding_critical_when_short(self):
        paths = [{"start": "USER", "end": "DOMAIN ADMINS", "length": 2,
                  "nodes": ["USER", "GROUP", "DOMAIN ADMINS"]}]
        f = self.bh.generate_finding(paths)
        assert f["severity"] == FindingSeverity.critical
        assert f["evidence"]["shortest_hops"] == 2

    def test_da_path_finding_high_when_long(self):
        paths = [{"start": "U", "end": "DA", "length": 5, "nodes": ["U", "a", "b", "c", "DA"]}]
        f = self.bh.generate_finding(paths)
        assert f["severity"] == FindingSeverity.high

    def test_no_finding_without_paths(self):
        assert self.bh.generate_finding([]) is None

    def test_query_da_paths_without_driver(self):
        assert self.bh.query_da_paths() == []

    def test_import_without_neo4j(self, monkeypatch):
        monkeypatch.setattr("app.ad.bloodhound._HAS_NEO4J", False)
        out = self.bh.import_to_neo4j(["f.json"], "bolt://x", "neo4j", "pw")
        assert out == {"nodes": 0, "relationships": 0}
