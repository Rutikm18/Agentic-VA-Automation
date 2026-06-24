"""
ADAssessmentRunner — runs the full Active Directory assessment pipeline and
returns a list of Finding-compatible dicts.

Pipeline:
  1. LDAP bind + enumeration (users / computers / groups).
  2. Anonymous-bind misconfiguration check.
  3. Kerberoast + AS-REP roast (evidence-only hash capture).
  4. NTLM relay posture (SMB/LDAP signing).
  5. AD CS template analysis (ESC1 / ESC4 / ESC8).
  6. Optional BloodHound collection + shortest-path-to-DA analysis.

Each stage is independently guarded: a failure (or a missing optional
dependency) in one stage logs a warning and is recorded under
``errors`` without aborting the rest of the assessment.
"""
from __future__ import annotations

from typing import Any

import structlog

from app.ad.adcs import ADCSChecker
from app.ad.asreproast import ASREPRoastChecker
from app.ad.bloodhound import BloodHoundCollector
from app.ad.findings import (
    ADConnectionError,
    DependencyMissingError,
    build_ad_finding,
)
from app.ad.kerberoast import KerberoastChecker
from app.ad.ldap_enum import LDAPEnumerator
from app.ad.ntlm_relay import NTLMRelayChecker
from app.models.enums import FindingSeverity

logger = structlog.get_logger()


class ADAssessmentRunner:
    """Coordinates all AD checkers for a single engagement."""

    def __init__(self) -> None:
        self.ldap = LDAPEnumerator()
        self.kerberoast = KerberoastChecker()
        self.asrep = ASREPRoastChecker()
        self.ntlm = NTLMRelayChecker()
        self.adcs = ADCSChecker()
        self.bloodhound = BloodHoundCollector()

    async def run(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        *,
        use_kerberos: bool = False,
        capture_hashes: bool = False,
        run_bloodhound: bool = False,
        ca_config: dict[str, Any] | None = None,
        neo4j: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Returns {findings: [...], stats: {...}, errors: [...]}.
        Never raises for per-stage failures — only for an unrecoverable LDAP bind
        when no other stage can proceed.
        """
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        stats: dict[str, Any] = {}
        creds = {"username": username, "password": password}

        # 1 — LDAP bind + enumeration
        try:
            self.ldap.connect(dc_ip, domain, username, password, use_kerberos=use_kerberos)
        except (ADConnectionError, DependencyMissingError) as exc:
            logger.error("ad.assess.ldap_connect_failed", error=str(exc))
            return {"findings": [], "stats": {}, "errors": [f"ldap_connect: {exc}"]}

        users = computers = groups = []
        try:
            users = self.ldap.get_users()
            computers = self.ldap.get_computers()
            groups = self.ldap.get_groups()
            stats.update(users=len(users), computers=len(computers), groups=len(groups))
        except Exception as exc:
            errors.append(f"enumeration: {exc}")
            logger.warning("ad.assess.enum_failed", error=str(exc))

        # 2 — anonymous bind
        try:
            if self.ldap.check_anonymous_bind(dc_ip):
                findings.append(self._anonymous_bind_finding(dc_ip))
        except Exception as exc:
            errors.append(f"anon_bind: {exc}")

        # 3a — kerberoast
        try:
            spn_accounts = self.kerberoast.get_spn_accounts(self.ldap)
            if capture_hashes:
                for acc in spn_accounts:
                    spn = acc["spn"][0] if acc.get("spn") else None
                    if spn:
                        acc["tgs_hash"] = self.kerberoast.request_tgs(
                            acc["username"], spn, dc_ip, domain, creds
                        )
            f = self.kerberoast.generate_finding(spn_accounts)
            if f:
                findings.append(f)
            stats["kerberoastable"] = len(spn_accounts)
        except Exception as exc:
            errors.append(f"kerberoast: {exc}")
            logger.warning("ad.assess.kerberoast_failed", error=str(exc))

        # 3b — AS-REP roast
        try:
            no_preauth = self.asrep.get_no_preauth_accounts(self.ldap)
            if capture_hashes:
                hashes = {u: self.asrep.request_asrep(u, dc_ip, domain) for u in no_preauth}
                stats["asrep_hashes_captured"] = sum(1 for v in hashes.values() if v)
            f = self.asrep.generate_finding(no_preauth)
            if f:
                findings.append(f)
            stats["asrep_roastable"] = len(no_preauth)
        except Exception as exc:
            errors.append(f"asreproast: {exc}")
            logger.warning("ad.assess.asrep_failed", error=str(exc))

        # 4 — NTLM relay posture
        try:
            host_ips = [c.ip for c in computers if c.ip]
            ldap_enforced = self.ntlm.check_ldap_signing(dc_ip, domain)
            unsigned: list[str] = []
            if host_ips:
                signing = self.ntlm.check_smb_signing(host_ips)
                unsigned = [
                    ip for ip, r in signing.items()
                    if r.get("reachable") and not r.get("signing_required")
                ]
            f = self.ntlm.generate_finding(unsigned, ldap_signing_enforced=ldap_enforced)
            if f:
                findings.append(f)
            stats["smb_unsigned_hosts"] = len(unsigned)
            stats["ldap_signing_enforced"] = ldap_enforced
        except Exception as exc:
            errors.append(f"ntlm_relay: {exc}")
            logger.warning("ad.assess.ntlm_failed", error=str(exc))

        # 5 — AD CS
        try:
            templates = self.adcs.enumerate_templates(self.ldap)
            findings.extend(self.adcs.generate_findings(templates, ca_config))
            stats["cert_templates"] = len(templates)
        except Exception as exc:
            errors.append(f"adcs: {exc}")
            logger.warning("ad.assess.adcs_failed", error=str(exc))

        # 6 — BloodHound (optional, slow)
        if run_bloodhound:
            try:
                json_files = await self.bloodhound.run_collection(
                    dc_ip, domain, creds, collection_methods=["All"]
                )
                if json_files and neo4j:
                    self.bloodhound.import_to_neo4j(
                        json_files, neo4j["uri"], neo4j["user"], neo4j["password"]
                    )
                    da_paths = self.bloodhound.query_da_paths()
                    f = self.bloodhound.generate_finding(da_paths)
                    if f:
                        findings.append(f)
                    stats["da_paths"] = len(da_paths)
                stats["bloodhound_files"] = len(json_files)
            except Exception as exc:
                errors.append(f"bloodhound: {exc}")
                logger.warning("ad.assess.bloodhound_failed", error=str(exc))
            finally:
                self.bloodhound.close()

        self.ldap.unbind()
        stats["findings_total"] = len(findings)
        logger.info("ad.assess.done", **{k: v for k, v in stats.items() if isinstance(v, int)})
        return {"findings": findings, "stats": stats, "errors": errors}

    @staticmethod
    def _anonymous_bind_finding(dc_ip: str) -> dict[str, Any]:
        return build_ad_finding(
            title="Anonymous LDAP bind allowed on Domain Controller",
            severity=FindingSeverity.medium,
            description=(
                f"The Domain Controller at {dc_ip} accepts anonymous LDAP binds "
                "that can read directory data. This lets an unauthenticated "
                "attacker enumerate users, groups, and other objects, aiding "
                "password-spraying and roasting attacks."
            ),
            mitre_techniques=["T1087.002"],  # Account Discovery: Domain Account
            cwe="CWE-285",
            reproduction=[
                f"ldapsearch -x -H ldap://{dc_ip} -b 'DC=domain,DC=local' '(objectClass=user)'",
                "Observe directory objects returned without credentials.",
            ],
            detection_opportunity=(
                "Audit LDAP bind events for anonymous/null binds and monitor for "
                "bulk directory reads from unauthenticated sources."
            ),
            remediation=(
                "Set dsHeuristics to deny anonymous operations and ensure "
                "'LDAP server signing requirements' is set to 'Require signing'. "
                "Remove ANONYMOUS LOGON from any directory read ACLs."
            ),
            evidence_extra={"dc_ip": dc_ip},
        )
