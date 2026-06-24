"""
ServiceIdentifier — banner + port → structured service fingerprint.
Handles: HTTP/HTTPS, SSH, SMB, FTP, SMTP, RDP, SNMP, LDAP, Kerberos,
         MSSQL, MySQL, Redis, and a generic fallback.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceFingerprint:
    service: str = "unknown"
    version: str = ""
    product: str = ""
    cpe: str = ""
    confidence_score: float = 0.0
    extra: dict = field(default_factory=dict)


# ── Port → (service_name, cpe_base) hint map ─────────────────────────────────
_PORT_HINTS: dict[int, tuple[str, str]] = {
    21:    ("ftp",       "cpe:/a:"),
    22:    ("ssh",       "cpe:/a:openbsd:openssh"),
    23:    ("telnet",    "cpe:/a:"),
    25:    ("smtp",      "cpe:/a:"),
    53:    ("dns",       "cpe:/a:"),
    80:    ("http",      "cpe:/a:"),
    88:    ("kerberos",  "cpe:/a:mit:kerberos"),
    110:   ("pop3",      "cpe:/a:"),
    135:   ("msrpc",     "cpe:/a:microsoft:"),
    139:   ("netbios",   "cpe:/a:"),
    143:   ("imap",      "cpe:/a:"),
    389:   ("ldap",      "cpe:/a:"),
    443:   ("https",     "cpe:/a:"),
    445:   ("smb",       "cpe:/a:microsoft:windows"),
    636:   ("ldaps",     "cpe:/a:"),
    1433:  ("mssql",     "cpe:/a:microsoft:sql_server"),
    3306:  ("mysql",     "cpe:/a:mysql:mysql"),
    3389:  ("rdp",       "cpe:/a:microsoft:"),
    5432:  ("postgres",  "cpe:/a:postgresql:postgresql"),
    6379:  ("redis",     "cpe:/a:redis:redis"),
    8080:  ("http-proxy","cpe:/a:"),
    8443:  ("https-alt", "cpe:/a:"),
    161:   ("snmp",      "cpe:/a:"),
    27017: ("mongodb",   "cpe:/a:mongodb:mongodb"),
}

# ── Banner regex rules: (pattern, service, product_extract_group, version_group) ──
_BANNER_RULES: list[tuple[re.Pattern, str, int, int]] = [
    (re.compile(r"SSH-(\d+\.\d+)-(.+)", re.I),            "ssh",      2, 1),
    (re.compile(r"^220[\s-].*SMTP|Postfix|Sendmail|Exim", re.I), "smtp", 0, 0),
    (re.compile(r"^HTTP/[\d.]+\s+\d+|Server:\s*(.+)",     re.I), "http", 1, 0),
    (re.compile(r"^\+OK|^-ERR .* POP",                    re.I), "pop3", 0, 0),
    (re.compile(r"^\* OK.*IMAP",                           re.I), "imap", 0, 0),
    (re.compile(r"^220 .*FTP|^230 ",                       re.I), "ftp",  0, 0),
    (re.compile(r"NTLMSSP|SMB|\\x00\\x00\\x00\\x00",       re.I), "smb",  0, 0),
    (re.compile(r"Microsoft SQL Server|MSSQL",             re.I), "mssql",0, 0),
    (re.compile(r"mysql_native_password|\x00\x00\x00\nmysql", re.I), "mysql", 0, 0),
    (re.compile(r"\+PONG|-ERR .*(redis|WRONGTYPE)", re.I), "redis", 0, 0),
    (re.compile(r"^0 \x00.*\x00ldap|^\x30",               re.I), "ldap", 0, 0),
    (re.compile(r"Kerberos|KRB5",                          re.I), "kerberos", 0, 0),
    (re.compile(r"SNMP|public",                             re.I), "snmp", 0, 0),
]

_VERSION_RE = re.compile(
    r"(\d+\.\d+[\.\d]*(?:[-_][\w.]+)?)", re.I
)


class ServiceIdentifier:
    def identify(self, banner: str, port: int) -> ServiceFingerprint:
        banner = (banner or "").strip()
        fp = ServiceFingerprint()

        # 1. Port hint as baseline
        if port in _PORT_HINTS:
            fp.service, fp.cpe = _PORT_HINTS[port]
            fp.confidence_score = 0.3

        # 2. Banner pattern matching
        for pattern, svc, prod_grp, ver_grp in _BANNER_RULES:
            m = pattern.search(banner)
            if m:
                fp.service = svc
                fp.confidence_score = max(fp.confidence_score, 0.7)
                if prod_grp and prod_grp <= len(m.groups()):
                    fp.product = (m.group(prod_grp) or "").strip()
                if ver_grp and ver_grp <= len(m.groups()):
                    fp.version = (m.group(ver_grp) or "").strip()
                break

        # 3. Extract version string from banner if not already set
        if not fp.version and banner:
            vm = _VERSION_RE.search(banner)
            if vm:
                fp.version = vm.group(1)
                fp.confidence_score = round(min(fp.confidence_score + 0.1, 1.0), 10)

        # 4. Boost confidence if both port hint and banner agree
        if fp.service != "unknown" and fp.confidence_score >= 0.7:
            fp.confidence_score = round(min(fp.confidence_score + 0.2, 1.0), 10)

        return fp
