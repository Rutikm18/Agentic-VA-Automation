"""
Shared building blocks for the Active Directory assessment module.

Every AD checker emits *Finding-compatible dicts* (same shape the Nuclei and
Nessus scanners produce — see ``app/vuln/nuclei.py``) so the router can persist
them straight into the ``findings`` table without per-checker special casing.

The Finding model has no dedicated columns for CWE, reproduction steps, the
detection opportunity, or the attack narrative, so those required fields are
carried inside the ``evidence`` JSONB blob. ``remediation`` and
``mitre_techniques`` map onto real columns.
"""
from __future__ import annotations

from typing import Any

from app.models.enums import FindingSeverity, FindingStatus


# ── Exceptions ─────────────────────────────────────────────────────────────────

class ADError(Exception):
    """Base class for Active Directory assessment errors."""


class ADConnectionError(ADError):
    """Raised when an LDAP/Kerberos/SMB connection to the DC fails."""


class DependencyMissingError(ADError):
    """Raised when an optional offensive dependency (ldap3/impacket) is absent."""


# ── userAccountControl flags (subset relevant to AD attacks) ─────────────────
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

UAC_ACCOUNTDISABLE        = 0x00000002
UAC_SERVER_TRUST_ACCOUNT  = 0x00002000   # domain controller computer account
UAC_DONT_REQ_PREAUTH      = 0x00400000   # AS-REP roastable
UAC_TRUSTED_FOR_DELEGATION = 0x00080000  # unconstrained delegation
UAC_NOT_DELEGATED         = 0x00100000

# primaryGroupID values that imply Domain Controller membership
DC_PRIMARY_GROUP_IDS: frozenset[int] = frozenset({516, 521})  # DCs, Read-only DCs

# Built-in groups that grant effective domain-wide privilege.
PRIVILEGED_GROUPS: frozenset[str] = frozenset({
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "dnsadmins",
    "group policy creator owners",
    "cert publishers",
    "enterprise key admins",
    "key admins",
})

# msPKI-Certificate-Name-Flag bit: subject supplied by the enrollee (ESC1).
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

# Client-authentication EKUs that make a cert usable for impersonation.
CLIENT_AUTH_EKUS: frozenset[str] = frozenset({
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.5.2.3.4",         # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",             # Any Purpose
})

# Rights on a template that let a low-priv principal take it over (ESC4).
DANGEROUS_TEMPLATE_RIGHTS: frozenset[str] = frozenset({
    "GenericAll",
    "GenericWrite",
    "WriteOwner",
    "WriteDacl",
    "WriteProperty",
})

# Well-known low-privilege SIDs / principals (for ESC1/ESC4 enrolment checks).
LOW_PRIV_PRINCIPALS: frozenset[str] = frozenset({
    "s-1-1-0",            # Everyone
    "s-1-5-11",           # Authenticated Users
    "s-1-5-7",            # Anonymous
    "authenticated users",
    "domain users",
    "domain computers",
    "everyone",
    "users",
})


def severity_from_str(value: str) -> FindingSeverity:
    try:
        return FindingSeverity(str(value).lower())
    except ValueError:
        return FindingSeverity.info


def build_ad_finding(
    *,
    title: str,
    severity: FindingSeverity | str,
    description: str,
    mitre_techniques: list[str],
    reproduction: list[str],
    detection_opportunity: str,
    remediation: str,
    cwe: str | None = None,
    cve_ids: list[str] | None = None,
    attack_narrative: str | None = None,
    exploitable: bool = False,
    exploit_validated: bool = False,
    evidence_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Assemble a Finding-compatible dict.

    All findings carry — as required by the spec — a MITRE technique, an optional
    CWE, step-by-step reproduction, a detection opportunity, and a remediation
    recommendation. The fields without a dedicated Finding column live in
    ``evidence``.
    """
    sev = severity if isinstance(severity, FindingSeverity) else severity_from_str(severity)

    evidence: dict[str, Any] = {
        "category": "active_directory",
        "cwe": cwe,
        "reproduction_steps": reproduction,
        "detection_opportunity": detection_opportunity,
    }
    if attack_narrative:
        evidence["attack_narrative"] = attack_narrative
    if evidence_extra:
        evidence.update(evidence_extra)

    return {
        "title": title,
        "description": description,
        "severity": sev,
        "status": FindingStatus.open,
        "cve_ids": cve_ids or None,
        "mitre_techniques": mitre_techniques or None,
        "exploitable": exploitable,
        "exploit_validated": exploit_validated,
        "remediation": remediation,
        "evidence": evidence,
    }
