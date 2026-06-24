"""Credentialed Windows inventory — WinRM primary, SMB+RemoteRegistry fallback.

WHY: most high-impact findings (missing patches/KBs, hotfix level, installed-
software versions, insecure local config) live on Windows and are only
visible with authenticated access — unauthenticated scanning can't see them.

ACCESS STRATEGY (degrades gracefully):
  1. WinRM (5985/5986) — PRIMARY. Modern, HTTP(S), firewall-friendly,
     structured output. Runs read-only PowerShell to enumerate OS build,
     hotfixes, installed software, services, local admins, and a few
     high-signal security settings.
  2. SMB + RemoteRegistry (445) — FALLBACK when WinRM is disabled (common on
     older/hardened hosts). Reads installed-software + OS build from the
     registry over SMB.

COLLECTION ONLY: authenticates with credentials YOU supply in the job's own
params (and are authorized to use), runs a FIXED set of READ-ONLY commands /
registry reads. Never changes config, writes registry, creates services, or
moves laterally. Credentials are never echoed back in the result envelope.

SCOPE NOTE: this is a faithful port of an already fixture-validated
collector (the WinRM/SMB code paths below are unchanged from the original).
It is deliberately NOT extended with finding-extraction from the raw
PowerShell text (e.g. flagging SMB1/RDP-NLA/Defender state) in this pass —
Format-List/Format-Table output is fragile to parse reliably, and bolting on
an untested regex parser here would repeat exactly the class of mistake this
session's mcp_ai.py false-positive fix was about (trusting a generic signal
without real evidence). That extraction is a deliberate follow-up, not a gap
discovered late.

DEPENDENCIES (optional, per transport):
    pip install pywinrm      # for the WinRM path
    pip install impacket     # for the SMB/RemoteRegistry fallback path
Either alone is enough to advertise this capability; the probe's "missing
engine -> not advertised" rule applies the same way it does for nmap/sslscan.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .base import BUILTIN_WINRM, expand_hosts, normalize_targets, now, result, scanner, split_host_port

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

# Each command is read-only. Output kept as raw text for the (separate)
# detection layer to parse; only light structuring (counts) happens here.
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
                   transport_auth: str, timeout: float) -> dict[str, str]:
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

    # Connectivity/auth probe FIRST. If WinRM is unreachable or auth fails,
    # raise so the caller's transport loop falls through to the SMB fallback
    # instead of returning a result full of per-command errors.
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


_UNINSTALL_PATHS = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]


def _smb_registry_collect(host: str, user: str, password: str,
                          domain: str, timeout: float) -> dict[str, Any]:
    """Connect to RemoteRegistry over SMB and enumerate installed-software keys
    plus the OS build. Requires the RemoteRegistry service reachable. Read-only.
    """
    out: dict[str, Any] = {}
    smb = SMBConnection(host, host, timeout=timeout)
    smb.login(user, password, domain)
    try:
        rpctransport = transport.SMBTransport(
            host, filename=r"\winreg", smb_connection=smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # OS build from registry
        os_info: dict[str, Any] = {}
        try:
            hklm = rrp.hOpenLocalMachine(dce)["phKey"]
            key = rrp.hBaseRegOpenKey(
                dce, hklm,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
            for val in ("ProductName", "CurrentBuild", "ReleaseId", "DisplayVersion"):
                try:
                    _t, data = rrp.hBaseRegQueryValue(dce, key, val)
                    os_info[val] = str(data).rstrip("\x00")
                except Exception:
                    pass
        except Exception as exc:
            os_info["__error__"] = str(exc)
        out["os_info"] = os_info

        # Installed software enumeration
        software: list[dict[str, Any]] = []
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
                        entry: dict[str, Any] = {}
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
        out["installed_software"] = software
        out["software_count"] = len([s for s in software if s.get("DisplayName")])
        dce.disconnect()
    finally:
        try:
            smb.logoff()
        except Exception:
            pass
    return out


def _full_user(creds: dict) -> str:
    user = creds.get("username", "")
    domain = creds.get("domain", "")
    if domain and "\\" not in user and "@" not in user:
        return f"{domain}\\{user}"
    return user


def _collect_host(host: str, creds: dict, prefer: str, use_https: bool,
                  transport_auth: str, timeout: float) -> dict[str, Any]:
    """Try transports in order (auto: winrm then smb), return on first success.

    Raises on total failure so the caller can record a per-host error without
    aborting the rest of the scan.
    """
    order = ["winrm", "smb"] if prefer == "auto" else [prefer]
    last_err = None
    for tname in order:
        try:
            if tname == "winrm":
                if not _HAVE_WINRM:
                    last_err = "pywinrm not installed"
                    continue
                data = _winrm_collect(host, _full_user(creds), creds.get("password", ""),
                                      use_https=use_https, transport_auth=transport_auth,
                                      timeout=timeout)
                return {"transport": "winrm", "inventory": data}
            elif tname == "smb":
                if not _HAVE_IMPACKET:
                    last_err = "impacket not installed"
                    continue
                data = _smb_registry_collect(host, creds.get("username", ""),
                                             creds.get("password", ""),
                                             creds.get("domain", ""), timeout)
                return {"transport": "smb_remoteregistry", "inventory": data}
        except Exception as exc:
            last_err = f"{tname}: {type(exc).__name__}: {exc}"
            continue
    raise RuntimeError(f"all transports failed ({last_err})")


@scanner("windows_inventory", BUILTIN_WINRM,
         "Credentialed Windows inventory — WinRM primary, SMB/registry fallback",
         available_check=lambda: _HAVE_WINRM or _HAVE_IMPACKET)
def windows_inventory(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("windows_inventory", BUILTIN_WINRM, [], ok=False, error="no targets provided")
    creds = params.get("credentials") or {}
    if not creds.get("username") or not creds.get("password"):
        return result("windows_inventory", BUILTIN_WINRM, targets, ok=False,
                      error="credentials.username + credentials.password required")

    started = now()
    prefer = params.get("prefer", "auto")          # auto | winrm | smb
    use_https = bool(params.get("https", False))
    transport_auth = params.get("auth", "ntlm")    # ntlm | kerberos | basic
    timeout = float(params.get("timeout", 30.0))
    concurrency = int(params.get("concurrency", 6))  # heavier per host than ssh_inventory
    max_hosts = int(params.get("max_hosts", 256))

    work: list[str] = []
    for tok in targets:
        host, _pin = split_host_port(tok)
        work.extend(expand_hosts([host], max_hosts=max_hosts))

    def _one(host: str) -> dict[str, Any]:
        try:
            r = _collect_host(host, creds, prefer, use_https, transport_auth, timeout)
            return {"ip": host, "transport": r["transport"], "inventory": r["inventory"]}
        except Exception as exc:
            return {"ip": host, "error": str(exc)}

    hosts_out: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_one, h) for h in work]
        for fut in as_completed(futs):
            hosts_out.append(fut.result())  # _one never raises

    ok_count = sum(1 for h in hosts_out if "error" not in h)
    return result("windows_inventory", BUILTIN_WINRM, targets, hosts=hosts_out,
                  host_count=ok_count, attempted=len(hosts_out), started=started)
