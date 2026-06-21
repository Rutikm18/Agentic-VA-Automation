"""
ssh_collector.py — credentialed (authenticated) inventory collection for Linux.

WHY: credentialed collection finds 5-10x more real, low-false-positive data than
unauthenticated scanning, because it reads the host's actual installed-software
state instead of guessing from banners.

WHAT IT DOES (collection only): logs into a host with credentials YOU supply
(and that you are authorized to use) and runs a fixed set of READ-ONLY inventory
commands:
  * OS / kernel / hostname
  * installed package list (dpkg / rpm)
  * listening services
  * running processes (names only)
It records the raw command output. It does NOT change anything, escalate
privilege, or run anything outside the allowlisted command set below.

Requires `paramiko` (pip install paramiko). Key-based auth strongly preferred.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from .scanner_base import (
    ScanResult, ScopeGuard, ResultWriter, expand_targets,
    setup_logging, base_argparser, LOG, RateLimiter, main_entrypoint,
)

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


def _collect_over_ssh(host: str, port: int, user: str,
                      key_path: str | None, password: str | None,
                      timeout: float) -> dict:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(hostname=host, port=port, username=user,
                          timeout=timeout, banner_timeout=timeout,
                          auth_timeout=timeout, look_for_keys=False,
                          allow_agent=False)
    if key_path:
        connect_kwargs["key_filename"] = key_path
    if password:
        connect_kwargs["password"] = password

    client.connect(**connect_kwargs)
    out: dict[str, str] = {}
    try:
        for name, cmd in INVENTORY_COMMANDS.items():
            try:
                _stdin, stdout, _stderr = client.exec_command(cmd, timeout=timeout)
                out[name] = stdout.read().decode("utf-8", "replace")[:200000]
            except Exception as exc:
                out[name] = f"__error__: {exc}"
    finally:
        client.close()
    return out


class SSHCollector:
    name = "ssh_inventory"

    def __init__(self, scope: ScopeGuard, *, user: str, key_path: str | None,
                 password: str | None, port: int = 22, timeout: float = 10.0,
                 rate: float = 20.0, concurrency: int = 10):
        self.scope = scope
        self.user = user
        self.key_path = key_path
        self.password = password
        self.port = port
        self.timeout = timeout
        self.limiter = RateLimiter(rate)
        self._sem = asyncio.Semaphore(concurrency)

    async def _collect(self, target: str) -> ScanResult:
        if not self.scope.in_scope(target):
            return ScanResult(self.name, target, status="error",
                              error="target not in authorized scope")
        async with self._sem:
            await self.limiter.wait()
            loop = asyncio.get_running_loop()
            try:
                data = await loop.run_in_executor(
                    None, _collect_over_ssh, target, self.port, self.user,
                    self.key_path, self.password, self.timeout)
            except Exception as exc:
                return ScanResult(self.name, target, status="error",
                                  error=f"{type(exc).__name__}: {exc}")
        pkg_lines = (data.get("dpkg_packages") or data.get("rpm_packages") or "")
        pkg_count = len([l for l in pkg_lines.splitlines() if l.strip()])
        return ScanResult(
            self.name, target, port=self.port, proto="tcp", status="observed",
            data={"inventory": data, "package_count": pkg_count},
            evidence=f"collected inventory, {pkg_count} packages",
        )

    async def run(self, targets: list[str], writer: ResultWriter) -> None:
        in_scope = list(self.scope.filter(targets))
        LOG.info("[%s] collecting from %d host(s)", self.name, len(in_scope))
        tasks = [asyncio.create_task(self._collect(t)) for t in in_scope]
        for fut in asyncio.as_completed(tasks):
            writer.write(await fut)


def main() -> None:
    parser = base_argparser("Credentialed SSH inventory collector (Linux)")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--key", help="path to private key (preferred)")
    parser.add_argument("--password", help="SSH password (use --key instead if possible)")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()
    setup_logging(args.verbose)

    if not _HAVE_PARAMIKO:
        LOG.error("paramiko not installed. Run: pip install paramiko")
        return
    if not args.key and not args.password:
        LOG.error("provide --key (preferred) or --password")
        return

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        collector = SSHCollector(scope, user=args.user, key_path=args.key,
                                 password=args.password, port=args.port,
                                 timeout=max(args.timeout, 10.0),
                                 rate=args.rate, concurrency=args.concurrency)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await collector.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
