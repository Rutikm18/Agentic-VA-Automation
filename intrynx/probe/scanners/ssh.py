"""Credentialed Linux inventory collection via SSH.

WHY: credentialed collection finds far more, far-lower-false-positive data
than unauthenticated scanning, because it reads a host's actual installed
state instead of guessing from banners.

COLLECTION ONLY: logs in with credentials supplied in the job's own params
(credentials YOU supply and are authorized to use) and runs a FIXED allowlist
of READ-ONLY inventory commands below. Never changes anything, never
escalates privilege, never runs anything outside that allowlist. Credentials
are never echoed back in the result envelope.

DEPENDENCY: requires paramiko, an OPTIONAL Python package — not in
requirements.txt by default, matching the probe's minimal-mandatory-deps
philosophy (same pattern as nmap/sslscan/nuclei being self-provisioned only
when needed). Install on probes that need this capability: pip install paramiko
A probe without it simply doesn't advertise ssh_inventory — see
available_check below, same "missing engine -> not advertised" rule as every
other scan_type.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .base import BUILTIN_SSH, expand_hosts, normalize_targets, now, result, scanner, split_host_port

try:
    import paramiko
    _HAVE_PARAMIKO = True
except ImportError:
    _HAVE_PARAMIKO = False

# Strict allowlist of read-only inventory commands. Nothing else is ever run.
INVENTORY_COMMANDS: dict[str, str] = {
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -a",
    "hostname": "hostname",
    "uptime": "uptime",
    "dpkg_packages": "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | head -n 5000",
    "rpm_packages": "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -n 5000",
    "listening_tcp": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "listening_udp": "ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null",
    "processes": "ps -eo comm= 2>/dev/null | sort -u | head -n 2000",
}


def _collect_one(host: str, port: int, creds: dict, timeout: float) -> dict[str, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict[str, Any] = dict(
        hostname=host, port=port, username=creds.get("username"),
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        look_for_keys=False, allow_agent=False,
    )
    if creds.get("key"):
        connect_kwargs["key_filename"] = creds["key"]
    if creds.get("password"):
        connect_kwargs["password"] = creds["password"]

    client.connect(**connect_kwargs)
    out: dict[str, str] = {}
    try:
        for name, cmd in INVENTORY_COMMANDS.items():
            try:
                _stdin, stdout, _stderr = client.exec_command(cmd, timeout=timeout)
                out[name] = stdout.read().decode("utf-8", "replace")[:200_000]
            except Exception as exc:
                out[name] = f"__error__: {exc}"
    finally:
        client.close()
    return out


@scanner("ssh_inventory", BUILTIN_SSH,
         "Credentialed Linux inventory via SSH — read-only (OS, packages, listeners, processes)",
         available_check=lambda: _HAVE_PARAMIKO)
def ssh_inventory(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("ssh_inventory", BUILTIN_SSH, [], ok=False, error="no targets provided")
    creds = params.get("credentials") or {}
    if not creds.get("username") or not (creds.get("key") or creds.get("password")):
        return result("ssh_inventory", BUILTIN_SSH, targets, ok=False,
                      error="credentials.username + (credentials.key or "
                            "credentials.password) required")

    started = now()
    default_port = int(params.get("port", 22))
    timeout = float(params.get("timeout", 10.0))
    concurrency = int(params.get("concurrency", 8))
    # Credentialed collection is heavier per host than a port probe — a
    # smaller default cap than the unauthenticated scanners' 1024.
    max_hosts = int(params.get("max_hosts", 256))

    work: list[tuple[str, int]] = []
    for tok in targets:
        host, pin = split_host_port(tok)
        for h in expand_hosts([host], max_hosts=max_hosts):
            work.append((h, pin or default_port))

    def _one(host: str, port: int) -> dict[str, Any]:
        try:
            inv = _collect_one(host, port, creds, timeout)
        except Exception as exc:
            return {"ip": host, "port": port, "error": f"{type(exc).__name__}: {exc}"}
        pkg_lines = inv.get("dpkg_packages") or inv.get("rpm_packages") or ""
        pkg_count = len([l for l in pkg_lines.splitlines() if l.strip()])
        return {"ip": host, "port": port, "inventory": inv, "package_count": pkg_count}

    hosts_out: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_one, h, p) for h, p in work]
        for fut in as_completed(futs):
            hosts_out.append(fut.result())  # _one never raises

    ok_count = sum(1 for h in hosts_out if "error" not in h)
    return result("ssh_inventory", BUILTIN_SSH, targets, hosts=hosts_out,
                  host_count=ok_count, attempted=len(hosts_out), started=started)
