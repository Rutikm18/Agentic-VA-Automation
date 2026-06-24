"""
NTLMRelayChecker — detect missing SMB/LDAP signing that enables NTLM relay.

NTLM relay (MITRE T1557.001) lets an attacker who can coerce or capture a
victim's NTLM authentication forward it to another host. If SMB signing is not
*required* on the target (or LDAP signing/channel binding is not enforced on the
DC), the relayed session is accepted. This module only *probes* the signing
posture — it never performs a relay.
"""
from __future__ import annotations

from typing import Any

import structlog

from app.ad.findings import build_ad_finding
from app.models.enums import FindingSeverity

logger = structlog.get_logger()

try:
    from impacket.smbconnection import SMBConnection, SessionError

    _HAS_IMPACKET = True
except ImportError:  # pragma: no cover
    _HAS_IMPACKET = False
    SessionError = Exception  # type: ignore


class NTLMRelayChecker:
    """Probe SMB/LDAP signing posture across a host list."""

    MITRE = ["T1557.001"]
    CWE = "CWE-294"  # Authentication Bypass by Capture-replay

    # ── check_smb_signing ─────────────────────────────────────────────────────────

    def check_smb_signing(self, ip_list: list[str], timeout: int = 5) -> dict[str, dict[str, bool]]:
        """
        For each IP, returns {signing_enabled, signing_required}.

        A host is relay-vulnerable when signing_required is False. Hosts that
        cannot be reached are reported with both flags False and a "reachable"
        marker so callers can distinguish "no SMB" from "signing off".
        """
        results: dict[str, dict[str, bool]] = {}
        if not _HAS_IMPACKET:
            logger.warning("ad.ntlm.no_impacket", hint="pip install impacket")
            for ip in ip_list:
                results[ip] = {"signing_enabled": False, "signing_required": False, "reachable": False}
            return results

        for ip in ip_list:
            results[ip] = self._probe_smb_host(ip, timeout)
        unsigned = [ip for ip, r in results.items() if r.get("reachable") and not r["signing_required"]]
        logger.info("ad.ntlm.smb_signing", total=len(ip_list), unsigned=len(unsigned))
        return results

    @staticmethod
    def _probe_smb_host(ip: str, timeout: int) -> dict[str, bool]:
        try:
            conn = SMBConnection(remoteName=ip, remoteHost=ip, sess_port=445, timeout=timeout)
            # impacket negotiates signing during connect; flags are exposed via
            # the negotiated dialect. isSigningRequired() is the authoritative bit.
            required = bool(conn.isSigningRequired())
            # signing_enabled: server advertised signing capability even if not required
            enabled = required or bool(getattr(conn, "_SMBConnection", None) and
                                       getattr(conn._SMBConnection, "_Capabilities", 0))
            conn.close()
            return {"signing_enabled": enabled, "signing_required": required, "reachable": True}
        except SessionError as exc:
            logger.debug("ad.ntlm.smb_session_error", ip=ip, error=str(exc))
            return {"signing_enabled": False, "signing_required": False, "reachable": True}
        except Exception as exc:
            logger.debug("ad.ntlm.smb_unreachable", ip=ip, error=str(exc))
            return {"signing_enabled": False, "signing_required": False, "reachable": False}

    # ── check_ldap_signing ────────────────────────────────────────────────────────

    def check_ldap_signing(self, dc_ip: str, domain: str) -> bool:
        """
        Returns True if the DC *enforces* LDAP signing / channel binding.

        We attempt a plaintext (unsigned) simple bind on 389. If the DC rejects
        unsigned binds with 'strongerAuthRequired', signing is enforced (good).
        If the unsigned bind is accepted, signing is NOT enforced (relay-prone).
        """
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL
            from ldap3.core.exceptions import LDAPException
        except ImportError:
            logger.warning("ad.ntlm.no_ldap3", hint="pip install ldap3")
            return True  # fail safe — assume enforced rather than flag falsely

        try:
            server = Server(dc_ip, port=389, get_info=ALL)
            conn = Connection(server, authentication=ldap3.ANONYMOUS, auto_bind=False)
            ok = conn.bind()
            result_desc = (conn.result or {}).get("description", "") if conn.result else ""
            conn.unbind()
            if "strongerAuthRequired" in result_desc or "confidentialityRequired" in result_desc:
                logger.info("ad.ntlm.ldap_signing", dc=dc_ip, enforced=True)
                return True
            logger.info("ad.ntlm.ldap_signing", dc=dc_ip, enforced=not ok)
            return not ok
        except Exception as exc:
            logger.debug("ad.ntlm.ldap_signing_error", dc=dc_ip, error=str(exc))
            return True

    # ── generate_finding ──────────────────────────────────────────────────────────

    def generate_finding(
        self,
        unsigned_hosts: list[str],
        ldap_signing_enforced: bool | None = None,
    ) -> dict[str, Any] | None:
        """
        Build a Finding for hosts missing SMB signing. The attack_narrative
        includes a ready-to-run ntlmrelayx command targeting the unsigned hosts.
        Returns None when nothing is relay-vulnerable.
        """
        ldap_issue = ldap_signing_enforced is False
        if not unsigned_hosts and not ldap_issue:
            return None

        narrative = (
            "1. Write relay targets to a file (one per line):\n"
            f"   {chr(10).join(unsigned_hosts) if unsigned_hosts else '<unsigned-host>'}\n"
            "2. Start the relay listener:\n"
            "   ntlmrelayx.py -tf targets.txt -smb2support -socks\n"
            "3. Coerce or wait for authentication (e.g. PetitPotam / PrinterBug) so a\n"
            "   privileged account's NTLM auth is relayed to an unsigned host, yielding\n"
            "   code execution or an authenticated SMB/LDAP session."
        )

        title = f"SMB signing not required on {len(unsigned_hosts)} host(s) — NTLM relay possible"
        if ldap_issue and not unsigned_hosts:
            title = "LDAP signing / channel binding not enforced on Domain Controller"

        return build_ad_finding(
            title=title,
            severity=FindingSeverity.high,
            description=(
                "Hosts that do not *require* SMB signing (and/or a DC that does not "
                "enforce LDAP signing) allow an attacker to relay captured NTLM "
                "authentication to them, gaining an authenticated session as the "
                "victim without ever knowing the password. "
                + (f"Unsigned hosts: {', '.join(unsigned_hosts[:15])}." if unsigned_hosts else "")
                + (" LDAP signing is NOT enforced on the DC." if ldap_issue else "")
            ),
            mitre_techniques=self.MITRE,
            cwe=self.CWE,
            reproduction=[
                "Identify hosts where SMB signing is not required (this scan).",
                "Run: ntlmrelayx.py -tf targets.txt -smb2support",
                "Trigger NTLM authentication from a privileged account (coercion).",
                "Observe the relayed authenticated session against an unsigned host.",
            ],
            detection_opportunity=(
                "Detect authentication coercion (MS-EFSRPC / MS-RPRN calls), and "
                "alert on logons where the source workstation does not match the "
                "account's host. Monitor Event ID 4624 logon type 3 from anomalous "
                "sources and NTLM auth to multiple hosts in quick succession."
            ),
            remediation=(
                "Enforce SMB signing on all hosts (GPO: 'Microsoft network server: "
                "Digitally sign communications (always)') and require LDAP signing + "
                "LDAP channel binding on Domain Controllers. Disable NTLM where "
                "possible and apply patches for known coercion vectors (PetitPotam, "
                "PrinterBug)."
            ),
            exploitable=True,
            attack_narrative=narrative,
            evidence_extra={
                "unsigned_hosts": unsigned_hosts,
                "ldap_signing_enforced": ldap_signing_enforced,
                "ntlmrelayx_command": "ntlmrelayx.py -tf targets.txt -smb2support -socks",
            },
        )
