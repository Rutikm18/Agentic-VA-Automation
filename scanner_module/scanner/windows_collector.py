"""
windows_collector.py — credentialed (authenticated) inventory for Windows hosts.

This is the Windows counterpart to ssh_collector.py and closes the single biggest
gap for enterprise value: most high-impact findings (missing patches/KBs, hotfix
level, installed-software versions, insecure local config) live on Windows and
are only visible with authenticated access.

ACCESS STRATEGY (degrades gracefully):
  1. WinRM (5985/5986)  — PRIMARY. Modern, HTTP(S), firewall-friendly, structured
     output. Runs read-only PowerShell to enumerate OS build, hotfixes, installed
     software, services, local admins, and key security settings.
  2. SMB + RemoteRegistry (445) — FALLBACK when WinRM is disabled (common on
     older / hardened hosts). Reads installed-software + patch info from the
     registry over SMB using impacket. Broadest reach across legacy estates.

WHAT IT DOES (collection only):
  * Authenticates with credentials YOU supply and are AUTHORIZED to use.
  * Runs a FIXED set of READ-ONLY inventory commands / registry reads.
  * Records raw output. It does NOT change config, write registry, create
    services, move laterally, or run anything outside the allowlisted set.

DEPENDENCIES (optional, per transport):
    pip install pywinrm      # for the WinRM path
    pip install impacket     # for the SMB/RemoteRegistry fallback path
Either alone is enough to use that transport.

CREDENTIAL HANDLING: prefer passing credentials via environment variables or a
secrets manager rather than the command line. Credentials are never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import os

from .scanner_base import (
    ScanResult, ScopeGuard, ResultWriter, expand_targets,
    setup_logging, base_argparser, LOG, RateLimiter, main_entrypoint,
)

# ---- optional transports -------------------------------------------------- #
try:
    import winrm  # pywinrm
    _HAVE_WINRM = True
except ImportError:
    _HAVE_WINRM = False

try:
    # impacket is large; only the registry remote-read path is needed.
    from impacket.dcerpc.v5 import transport, rrp
    from impacket.dcerpc.v5.rrp import DCERPCSessionError
    from impacket.smbconnection import SMBConnection
    _HAVE_IMPACKET = True
except ImportError:
    _HAVE_IMPACKET = False


# --------------------------------------------------------------------------- #
# WinRM path — read-only PowerShell inventory.
# --------------------------------------------------------------------------- #
# Each command is read-only. Output kept as raw text for the (separate) detection
# layer to parse; we do light structuring (counts) only.
WINRM_COMMANDS: dict[str, str] = {
    # OS build + patch level
    "os_info": (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture,"
        "LastBootUpTime | Format-List"
    ),
    # Installed hotfixes / KBs — the core of patch-state assessment
    "hotfixes": "Get-HotFix | Select-Object HotFixID,InstalledOn | Format-Table -AutoSize",
    # Installed software from both 32/64-bit uninstall keys
    "installed_software": (
        "Get-ItemProperty "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "-ErrorAction SilentlyContinue | "
        "Select-Object DisplayName,DisplayVersion,Publisher | "
        "Where-Object {$_.DisplayName} | Format-Table -AutoSize"
    ),
    # Services (name + start mode + state) — read only
    "services": (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,StartMode,State,PathName | Format-Table -AutoSize"
    ),
    # Local administrators group membership
    "local_admins": (
        "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
        "Select-Object Name,PrincipalSource | Format-Table -AutoSize"
    ),
    # A few high-signal security settings (read-only registry queries)
    "smb1_state": (
        "Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
        "-Name SMB1 -ErrorAction SilentlyContinue | Select-Object SMB1 | Format-List"
    ),
    "rdp_nla": (
        "Get-ItemProperty "
        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name UserAuthentication -ErrorAction SilentlyContinue | "
        "Select-Object UserAuthentication | Format-List"
    ),
    "defender_status": (
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureLastUpdated | Format-List"
    ),
}


def _winrm_collect(host: str, user: str, password: str, *, use_https: bool,
                   transport_auth: str, timeout: int) -> dict:
    scheme = "https" if use_https else "http"
    port = 5986 if use_https else 5985
    endpoint = f"{scheme}://{host}:{port}/wsman"
    session = winrm.Session(
        endpoint,
        auth=(user, password),
        transport=transport_auth,           # 'ntlm' (default) / 'kerberos' / 'basic'
        server_cert_validation="ignore",
        read_timeout_sec=timeout + 5,
        operation_timeout_sec=timeout,
    )

    # Connectivity/auth probe FIRST. If WinRM is unreachable or auth fails, raise
    # so the caller's transport loop falls through to the SMB fallback instead of
    # returning a result full of per-command errors.
    probe = session.run_ps("$true")
    if probe.status_code != 0:
        err = (probe.std_err or b"").decode("utf-8", "replace")
        raise ConnectionError(f"winrm probe failed: {err[:200]}")

    out: dict[str, str] = {}
    for name, ps in WINRM_COMMANDS.items():
        try:
            r = session.run_ps(ps)
            text = (r.std_out or b"").decode("utf-8", "replace")
            err = (r.std_err or b"").decode("utf-8", "replace")
            out[name] = text if text.strip() else (f"__stderr__: {err}" if err else "")
        except Exception as exc:  # one command failing must not abort the rest
            out[name] = f"__error__: {type(exc).__name__}: {exc}"
    return out


# --------------------------------------------------------------------------- #
# SMB + RemoteRegistry fallback — read installed software + OS build from
# registry over SMB (works where WinRM is off). Read-only registry queries.
# --------------------------------------------------------------------------- #
_UNINSTALL_PATHS = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]


def _smb_registry_collect(host: str, user: str, password: str,
                          domain: str, timeout: int) -> dict:
    """
    Connect to RemoteRegistry over SMB and enumerate installed-software keys plus
    the OS build. Requires the RemoteRegistry service reachable. Read-only.
    """
    result: dict[str, object] = {"transport": "smb_remoteregistry"}
    smb = SMBConnection(host, host, timeout=timeout)
    smb.login(user, password, domain)
    try:
        rpctransport = transport.SMBTransport(
            host, filename=r"\winreg", smb_connection=smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # OS build from registry
        os_info = {}
        try:
            hklm = rrp.hOpenLocalMachine(dce)["phKey"]
            key = rrp.hBaseRegOpenKey(
                dce, hklm,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
            for val in ("ProductName", "CurrentBuild", "ReleaseId",
                        "DisplayVersion"):
                try:
                    _t, data = rrp.hBaseRegQueryValue(dce, key, val)
                    os_info[val] = str(data).rstrip("\x00")
                except Exception:
                    pass
        except Exception as exc:
            os_info["__error__"] = str(exc)
        result["os_info"] = os_info

        # Installed software enumeration
        software: list[dict] = []
        for base in _UNINSTALL_PATHS:
            try:
                hklm = rrp.hOpenLocalMachine(dce)["phKey"]
                key = rrp.hBaseRegOpenKey(dce, hklm, base)["phkResult"]
                idx = 0
                while True:
                    try:
                        sub = rrp.hBaseRegEnumKey(dce, key, idx)["lpNameOut"]
                    except DCERPCSessionError:
                        break
                    idx += 1
                    subname = sub.rstrip("\x00")
                    try:
                        subkey = rrp.hBaseRegOpenKey(
                            dce, key, base + "\\" + subname)["phkResult"]
                        entry = {}
                        for v in ("DisplayName", "DisplayVersion", "Publisher"):
                            try:
                                _t, d = rrp.hBaseRegQueryValue(dce, subkey, v)
                                entry[v] = str(d).rstrip("\x00")
                            except Exception:
                                pass
                        if entry.get("DisplayName"):
                            software.append(entry)
                    except Exception:
                        continue
            except Exception as exc:
                software.append({"__error__": f"{base}: {exc}"})
        result["installed_software"] = software
        result["software_count"] = len([s for s in software if s.get("DisplayName")])
        dce.disconnect()
    finally:
        try:
            smb.logoff()
        except Exception:
            pass
    return result


# --------------------------------------------------------------------------- #
# Collector orchestration.
# --------------------------------------------------------------------------- #
class WindowsCollector:
    name = "windows_inventory"

    def __init__(self, scope: ScopeGuard, *, user: str, password: str,
                 domain: str = "", use_https: bool = False,
                 transport_auth: str = "ntlm", prefer: str = "auto",
                 timeout: float = 30.0, rate: float = 10.0,
                 concurrency: int = 8):
        self.scope = scope
        self.user = user
        self.password = password
        self.domain = domain
        self.use_https = use_https
        self.transport_auth = transport_auth
        self.prefer = prefer          # auto | winrm | smb
        self.timeout = int(timeout)
        self.limiter = RateLimiter(rate)
        self._sem = asyncio.Semaphore(concurrency)

    async def _collect_host(self, target: str) -> ScanResult:
        if not self.scope.in_scope(target):
            return ScanResult(self.name, target, status="error",
                              error="target not in authorized scope")
        async with self._sem:
            await self.limiter.wait()
            loop = asyncio.get_running_loop()

            order = self._transport_order()
            last_err = None
            for tname in order:
                try:
                    if tname == "winrm":
                        if not _HAVE_WINRM:
                            last_err = "pywinrm not installed"
                            continue
                        fn = functools.partial(
                            _winrm_collect, target, self._full_user(),
                            self.password, use_https=self.use_https,
                            transport_auth=self.transport_auth,
                            timeout=self.timeout)
                        data = await loop.run_in_executor(None, fn)
                        return self._winrm_result(target, data)
                    elif tname == "smb":
                        if not _HAVE_IMPACKET:
                            last_err = "impacket not installed"
                            continue
                        fn = functools.partial(
                            _smb_registry_collect, target, self.user,
                            self.password, self.domain, self.timeout)
                        data = await loop.run_in_executor(None, fn)
                        return self._smb_result(target, data)
                except Exception as exc:
                    last_err = f"{tname}: {type(exc).__name__}: {exc}"
                    LOG.debug("transport %s failed for %s: %s", tname, target, exc)
                    continue
            return ScanResult(self.name, target, status="error",
                              error=f"all transports failed ({last_err})")

    def _full_user(self) -> str:
        if self.domain and "\\" not in self.user and "@" not in self.user:
            return f"{self.domain}\\{self.user}"
        return self.user

    def _transport_order(self) -> list[str]:
        if self.prefer == "winrm":
            return ["winrm"]
        if self.prefer == "smb":
            return ["smb"]
        return ["winrm", "smb"]   # auto: try modern first, fall back

    def _winrm_result(self, target, data) -> ScanResult:
        sw = data.get("installed_software", "")
        hotfixes = data.get("hotfixes", "")
        sw_lines = len([l for l in sw.splitlines() if l.strip()]) if sw else 0
        kb_count = len([l for l in hotfixes.splitlines() if "KB" in l])
        return ScanResult(
            self.name, target, port=(5986 if self.use_https else 5985),
            proto="tcp", status="observed",
            data={"transport": "winrm", "inventory": data,
                  "software_lines": sw_lines, "hotfix_count": kb_count},
            evidence=f"winrm inventory: ~{sw_lines} sw rows, {kb_count} hotfixes")

    def _smb_result(self, target, data) -> ScanResult:
        return ScanResult(
            self.name, target, port=445, proto="tcp", status="observed",
            data={"inventory": data,
                  "software_count": data.get("software_count", 0)},
            evidence=(f"smb/registry inventory: "
                      f"{data.get('software_count', 0)} sw entries"))

    async def run(self, targets: list[str], writer: ResultWriter) -> None:
        in_scope = list(self.scope.filter(targets))
        LOG.info("[%s] collecting from %d Windows host(s)", self.name,
                 len(in_scope))
        tasks = [asyncio.create_task(self._collect_host(t)) for t in in_scope]
        for fut in asyncio.as_completed(tasks):
            writer.write(await fut)


def main() -> None:
    parser = base_argparser("Credentialed Windows inventory (WinRM + SMB fallback)")
    parser.add_argument("--user", required=True, help="username (or DOMAIN\\user)")
    parser.add_argument("--password", default=os.environ.get("WIN_SCAN_PASSWORD"),
                        help="password (prefer env WIN_SCAN_PASSWORD over CLI)")
    parser.add_argument("--domain", default="", help="AD domain (optional)")
    parser.add_argument("--https", action="store_true",
                        help="use WinRM over HTTPS (5986) — keeps creds encrypted")
    parser.add_argument("--auth", default="ntlm",
                        choices=["ntlm", "kerberos", "basic"],
                        help="WinRM auth method (default ntlm)")
    parser.add_argument("--prefer", default="auto",
                        choices=["auto", "winrm", "smb"],
                        help="transport preference (default auto: winrm then smb)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.password:
        LOG.error("no password provided (use --password or env WIN_SCAN_PASSWORD)")
        return
    if not _HAVE_WINRM and not _HAVE_IMPACKET:
        LOG.error("neither pywinrm nor impacket installed. "
                  "Run: pip install pywinrm impacket")
        return
    if args.prefer in ("auto", "winrm") and not _HAVE_WINRM:
        LOG.warning("pywinrm not installed; WinRM path unavailable")
    if args.prefer in ("auto", "smb") and not _HAVE_IMPACKET:
        LOG.warning("impacket not installed; SMB fallback unavailable")

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        collector = WindowsCollector(
            scope, user=args.user, password=args.password, domain=args.domain,
            use_https=args.https, transport_auth=args.auth, prefer=args.prefer,
            timeout=max(args.timeout, 30.0), rate=args.rate,
            concurrency=args.concurrency)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await collector.run(targets, writer)
        finally:
            writer.close()
            LOG.info("[windows_inventory] done — %d host(s)", writer.count)

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
