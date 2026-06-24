"""SMB / Active Directory enumeration via netexec (nxc) — lateral-movement recon.

Evidence-only: enumerates SMB signing, SMBv1, null sessions, and (with creds)
shares. It does not exploit. Credentials are optional job params.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner

# nxc line:  SMB  10.0.0.5  445  DC01  [*] Windows ... (name:DC01) (domain:corp.local) (signing:False) (SMBv1:True)
_LINE_RE = re.compile(r"^SMB\s+(?P<ip>\S+)\s+\d+\s+(?P<host>\S+)\s+\[")


def _field(line: str, key: str) -> str | None:
    m = re.search(rf"\({re.escape(key)}:([^)]*)\)", line, re.I)
    return m.group(1).strip() if m else None


def parse_nxc_smb(output: str) -> dict[str, Any]:
    """Parse nxc smb stdout into hosts + findings (field-by-field, position-agnostic)."""
    hosts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        ip = m.group("ip")
        if ip in seen:  # nxc prints multiple lines per host; dedupe the host record
            continue
        signing = (_field(line, "signing") or "").lower()
        smbv1 = (_field(line, "SMBv1") or "").lower()
        name = _field(line, "name")
        domain = _field(line, "domain")
        if signing or smbv1 or name:  # only treat header line as a host record
            seen.add(ip)
            hosts.append({
                "ip": ip, "hostname": name or m.group("host"), "domain": domain,
                "signing": signing == "true", "smbv1": smbv1 == "true",
            })
            if signing == "false":
                findings.append({"target": ip, "title": "SMB signing not required",
                                 "severity": "high", "detail": "Enables NTLM relay attacks."})
            if smbv1 == "true":
                findings.append({"target": ip, "title": "SMBv1 enabled", "severity": "high",
                                 "detail": "Legacy, vulnerable protocol (e.g. EternalBlue)."})
        if "[+]" in line and re.search(r"\\:", line):  # null/anon session (user:'' pass:'')
            findings.append({"target": ip, "title": "Anonymous/null SMB session allowed", "severity": "medium"})
    return {"hosts": hosts, "findings": findings}


@scanner("smb_enum", "nxc", "SMB/AD enumeration — signing, SMBv1, null sessions")
def smb_enum(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("smb_enum", "nxc", [], ok=False, error="no targets provided")
    started = now()
    cmd = ["nxc", "smb", *targets]
    creds = params.get("credentials") or {}
    if creds.get("username"):
        cmd += ["-u", creds["username"], "-p", creds.get("password", "")]
        if creds.get("domain"):
            cmd += ["-d", creds["domain"]]
        if params.get("enum_shares", True):
            cmd += ["--shares"]
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 900)))
    except subprocess.TimeoutExpired:
        return result("smb_enum", "nxc", targets, ok=False, error="nxc timed out", started=started)
    parsed = parse_nxc_smb(proc.stdout + "\n" + proc.stderr)  # nxc writes to stderr sometimes
    return result("smb_enum", "nxc", targets, hosts=parsed["hosts"], findings=parsed["findings"],
                  host_count=len(parsed["hosts"]), finding_count=len(parsed["findings"]), started=started)
