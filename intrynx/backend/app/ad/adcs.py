"""
ADCSChecker — Active Directory Certificate Services template misconfiguration
analysis (the "ESC" family from SpecterOps' Certified Pre-Owned).

Implements detection for:
  * ESC1 — template allows the enrollee to supply an arbitrary subject (SAN) AND
           grants a client-authentication EKU AND low-privilege enrollment.
  * ESC4 — a low-privilege principal has write access (GenericAll / WriteDacl /
           WriteOwner / WriteProperty) over the template object itself.
  * ESC8 — the CA exposes an HTTP/web-enrollment endpoint that accepts NTLM,
           enabling relay to AD CS for certificate issuance.

All checks are read-only. Templates are enumerated from the Configuration naming
context via the supplied LDAP connection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from app.ad.findings import (
    CLIENT_AUTH_EKUS,
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    DANGEROUS_TEMPLATE_RIGHTS,
    LOW_PRIV_PRINCIPALS,
    build_ad_finding,
)
from app.ad.ldap_enum import ACE, LDAPEnumerator
from app.models.enums import FindingSeverity

logger = structlog.get_logger()


@dataclass
class CertTemplate:
    name: str
    display_name: str | None = None
    enrollee_supplies_subject: bool = False
    client_auth: bool = False
    ekus: list[str] = field(default_factory=list)
    # Principals (SID or name) allowed to enrol on this template.
    enrollment_principals: list[str] = field(default_factory=list)
    # ACEs on the template object (for ESC4).
    aces: list[ACE] = field(default_factory=list)
    requires_manager_approval: bool = False
    authorized_signatures_required: int = 0
    dn: str | None = None


class ADCSChecker:
    MITRE = ["T1649"]  # Steal or Forge Authentication Certificates
    CWE = "CWE-295"    # Improper Certificate Validation / trust misconfig

    _TEMPLATE_CONTAINER = (
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"
    )

    # ── enumerate_templates ───────────────────────────────────────────────────────

    def enumerate_templates(self, ldap_conn: LDAPEnumerator) -> list[CertTemplate]:
        """Read pKICertificateTemplate objects from the Configuration NC."""
        conn = ldap_conn.connection
        if conn is None:
            return []

        base_dn = getattr(ldap_conn, "_base_dn", "") or ""
        search_base = f"{self._TEMPLATE_CONTAINER},{base_dn}"
        templates: list[CertTemplate] = []
        try:
            conn.search(
                search_base=search_base,
                search_filter="(objectClass=pKICertificateTemplate)",
                search_scope="SUBTREE",
                attributes=[
                    "cn", "displayName", "msPKI-Certificate-Name-Flag",
                    "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag",
                    "msPKI-RA-Signature", "nTSecurityDescriptor",
                ],
            )
        except Exception as exc:
            logger.warning("ad.adcs.enumerate_failed", error=str(exc))
            return []

        for e in conn.entries:
            name = str(ldap_conn._attr(e, "cn") or "")
            name_flag = int(ldap_conn._attr(e, "msPKI-Certificate-Name-Flag") or 0)
            ekus = [str(x) for x in (ldap_conn._attr(e, "pKIExtendedKeyUsage") or [])]
            ra_sig = int(ldap_conn._attr(e, "msPKI-RA-Signature") or 0)
            enroll_flag = int(ldap_conn._attr(e, "msPKI-Enrollment-Flag") or 0)
            dn = str(getattr(e, "entry_dn", "")) or None

            tmpl = CertTemplate(
                name=name,
                display_name=ldap_conn._attr(e, "displayName"),
                enrollee_supplies_subject=bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                ekus=ekus,
                client_auth=any(eku in CLIENT_AUTH_EKUS for eku in ekus) or not ekus,
                requires_manager_approval=bool(enroll_flag & 0x2),  # PEND_ALL_REQUESTS
                authorized_signatures_required=ra_sig,
                dn=dn,
            )
            if dn:
                try:
                    tmpl.aces = ldap_conn.get_aces(dn)
                    tmpl.enrollment_principals = self._enrollment_principals(tmpl.aces)
                except Exception as exc:
                    logger.debug("ad.adcs.aces_failed", template=name, error=str(exc))
            templates.append(tmpl)

        logger.info("ad.adcs.templates", count=len(templates))
        return templates

    @staticmethod
    def _enrollment_principals(aces: list[ACE]) -> list[str]:
        """Principals with an enrollment ExtendedRight or broad write on the template."""
        principals: list[str] = []
        for ace in aces:
            if ace.ace_type != "ALLOW":
                continue
            if "ExtendedRight" in ace.rights or set(ace.rights) & DANGEROUS_TEMPLATE_RIGHTS:
                principals.append(ace.trustee_sid)
        return principals

    @staticmethod
    def _has_low_priv(principals: list[str]) -> bool:
        return any(p.lower() in LOW_PRIV_PRINCIPALS for p in principals)

    # ── check_esc1 ────────────────────────────────────────────────────────────────

    def check_esc1(self, template: CertTemplate) -> bool:
        """
        ESC1: enrollee supplies subject + client-auth EKU + low-priv can enrol +
        no manager approval / RA signatures required.
        """
        if template.requires_manager_approval or template.authorized_signatures_required > 0:
            return False
        return (
            template.enrollee_supplies_subject
            and template.client_auth
            and self._has_low_priv(template.enrollment_principals)
        )

    # ── check_esc4 ────────────────────────────────────────────────────────────────

    def check_esc4(self, template: CertTemplate) -> bool:
        """ESC4: a low-privilege principal holds a dangerous write right on the template."""
        for ace in template.aces:
            if ace.ace_type != "ALLOW":
                continue
            if set(ace.rights) & DANGEROUS_TEMPLATE_RIGHTS and (
                ace.trustee_sid.lower() in LOW_PRIV_PRINCIPALS
            ):
                return True
        return False

    # ── check_esc8 ────────────────────────────────────────────────────────────────

    def check_esc8(self, ca_config: dict[str, Any]) -> bool:
        """
        ESC8: the CA exposes a web-enrollment (HTTP) endpoint that accepts NTLM
        and does not enforce HTTPS+EPA, enabling NTLM relay to AD CS.

        ``ca_config`` = {
            "web_enrollment": bool,
            "https_only": bool,
            "ntlm_enabled": bool,
            "epa_enforced": bool,   # Extended Protection for Authentication
        }
        """
        if not ca_config.get("web_enrollment"):
            return False
        ntlm = ca_config.get("ntlm_enabled", True)
        epa = ca_config.get("epa_enforced", False)
        https_only = ca_config.get("https_only", False)
        # Relay is possible when NTLM is accepted without EPA, or HTTP is allowed.
        return bool(ntlm and (not epa or not https_only))

    # ── generate_findings ─────────────────────────────────────────────────────────

    def generate_findings(
        self,
        templates: list[CertTemplate],
        ca_config: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        esc1 = [t for t in templates if self.check_esc1(t)]
        if esc1:
            names = ", ".join(t.name for t in esc1)
            findings.append(build_ad_finding(
                title=f"ADCS ESC1 — enrollee-supplied subject on client-auth template(s): {names}",
                severity=FindingSeverity.critical,
                description=(
                    "Certificate template(s) permit a low-privilege user to enrol "
                    "while supplying an arbitrary Subject Alternative Name and the "
                    "issued certificate is valid for client authentication. An "
                    "attacker can request a certificate as any user — including "
                    "Domain Admins — and authenticate as them (PKINIT)."
                ),
                mitre_techniques=self.MITRE,
                cwe=self.CWE,
                reproduction=[
                    "Find vulnerable templates: certipy find -u user@domain -p pass -dc-ip <DC>",
                    f"Request a cert as a privileged user: certipy req -template {esc1[0].name} "
                    "-upn administrator@domain -ca <CA> -target <CA-host>",
                    "Authenticate with the certificate: certipy auth -pfx administrator.pfx -dc-ip <DC>",
                ],
                detection_opportunity=(
                    "Audit AD CS certificate issuance (Event ID 4886/4887) for "
                    "requests where the SAN does not match the requester, and review "
                    "templates with msPKI-Certificate-Name-Flag ENROLLEE_SUPPLIES_SUBJECT."
                ),
                remediation=(
                    "Remove ENROLLEE_SUPPLIES_SUBJECT from client-auth templates, "
                    "require manager approval or authorized signatures, and restrict "
                    "enrollment permissions to specific, non-low-privilege groups."
                ),
                exploitable=True,
                evidence_extra={"templates": [t.name for t in esc1], "esc": "ESC1"},
            ))

        esc4 = [t for t in templates if self.check_esc4(t)]
        if esc4:
            names = ", ".join(t.name for t in esc4)
            findings.append(build_ad_finding(
                title=f"ADCS ESC4 — low-privilege write access to template(s): {names}",
                severity=FindingSeverity.high,
                description=(
                    "A low-privilege principal can modify certificate template(s). "
                    "An attacker can rewrite a vulnerable template into an ESC1 "
                    "configuration and then abuse it for domain privilege escalation."
                ),
                mitre_techniques=self.MITRE,
                cwe=self.CWE,
                reproduction=[
                    "Enumerate template ACLs: certipy find -vulnerable -u user@domain -p pass",
                    f"Overwrite the template to be ESC1-abusable: certipy template -template {esc4[0].name} ...",
                    "Exploit as ESC1 to obtain a privileged certificate.",
                ],
                detection_opportunity=(
                    "Alert on writes to objects under the Certificate Templates "
                    "container (Directory Service Changes, Event ID 5136)."
                ),
                remediation=(
                    "Restrict template DACLs so that only Domain/Enterprise Admins "
                    "hold write rights; remove WriteDacl/WriteOwner/GenericAll/"
                    "GenericWrite from low-privilege principals."
                ),
                exploitable=True,
                evidence_extra={"templates": [t.name for t in esc4], "esc": "ESC4"},
            ))

        if ca_config and self.check_esc8(ca_config):
            findings.append(build_ad_finding(
                title="ADCS ESC8 — web enrollment endpoint vulnerable to NTLM relay",
                severity=FindingSeverity.critical,
                description=(
                    "The Certificate Authority exposes an HTTP web-enrollment "
                    "endpoint that accepts NTLM authentication without Extended "
                    "Protection. An attacker can relay coerced machine authentication "
                    "(e.g. a Domain Controller via PetitPotam) to the CA and obtain a "
                    "certificate for that machine, leading to domain compromise."
                ),
                mitre_techniques=self.MITRE + ["T1557.001"],
                cwe=self.CWE,
                reproduction=[
                    "Start the relay to the CA web endpoint: ntlmrelayx.py -t "
                    "http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
                    "Coerce DC auth: PetitPotam.py <attacker-ip> <DC-ip>",
                    "Use the issued certificate to authenticate as the DC (PKINIT / S4U).",
                ],
                detection_opportunity=(
                    "Monitor AD CS web enrollment (IIS) logs for NTLM authentication "
                    "and certificate requests originating from machine accounts; "
                    "alert on coercion RPC calls."
                ),
                remediation=(
                    "Disable NTLM on the AD CS web enrollment endpoint, enforce "
                    "HTTPS with Extended Protection for Authentication (EPA), or "
                    "remove web enrollment entirely. Apply coercion patches."
                ),
                exploitable=True,
                evidence_extra={"ca_config": ca_config, "esc": "ESC8"},
            ))

        logger.info("ad.adcs.findings", count=len(findings))
        return findings
