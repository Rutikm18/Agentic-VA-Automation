"""
Scanner framework for the Intrynx probe.

Each capability (discovery, vuln_scan, tls_scan, …) is a small function that takes
the job's ``params`` dict, runs the matching **scan engine**, and returns a
**normalized result dict**. Scanners self-register via the ``@scanner`` decorator;
the agent dispatches by ``scan_type`` and only offers engines that are available.

White-labeling: the underlying open-source utilities are an internal implementation
detail. Every value that leaves the probe (results, the capability catalog, logs,
and error text) is branded with a neutral **engine** label and scrubbed of raw
binary names — see ``engine_label`` / ``sanitize`` below.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable

# Sentinel binary names for scanners implemented in pure Python (no external
# CLI). These are always "available" — they only need the probe's own deps.
# Distinct sentinels (not one shared BUILTIN) so each gets its own engine
# label below — collapsing them would mislabel e.g. a passive listener or a
# DB fingerprinter as "ix-aiscan" just because it's also pure-Python.
BUILTIN = "builtin"
BUILTIN_PASSIVE = "builtin-passive"
BUILTIN_DB = "builtin-db"
BUILTIN_SSH = "builtin-ssh"
BUILTIN_WINRM = "builtin-winrm"

# Internal binary → public engine label. The probe never surfaces the real tool
# name; operators and results see only the Intrynx engine codename.
ENGINE_LABELS: dict[str, str] = {
    "nmap":     "ix-netscan",
    "masscan":  "ix-fastsweep",
    "nuclei":   "ix-vulnscan",
    "httpx":    "ix-webscan",
    "sslscan":  "ix-tlsscan",
    "nxc":      "ix-smbscan",
    BUILTIN:    "ix-aiscan",
    BUILTIN_PASSIVE: "ix-passivescan",
    BUILTIN_DB: "ix-dbscan",
    BUILTIN_SSH: "ix-sshaudit",
    BUILTIN_WINRM: "ix-winaudit",
}

# Redaction rules applied to any tool-generated text (e.g. stderr) before it is
# returned to the platform — raw binary names, tool-specific banner words, and
# embedded homepage URLs that would otherwise fingerprint the engine.
_REDACTIONS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(nmap|masscan|nuclei|httpx|sslscan|netexec|nxc|crackmapexec|projectdiscovery)\b", re.I),
     "scan-engine"),
    (re.compile(r"\bquitting\b", re.I), "aborted"),   # nmap's signature abort word
    (re.compile(r"https?://\S+"), ""),                 # tool banners embed their homepage URL
]


def engine_label(binary: str | None) -> str:
    """Public engine codename for an internal binary (never reveals the tool)."""
    return ENGINE_LABELS.get(binary or "", "ix-scan")


def sanitize(text: str | None) -> str:
    """Redact tool names / banners / URLs from text leaving the probe."""
    if not text:
        return text or ""
    for pat, repl in _REDACTIONS:
        text = pat.sub(repl, text)
    return text.strip()


# name -> Scanner
REGISTRY: dict[str, "Scanner"] = {}


class Scanner:
    def __init__(self, name: str, binary: str, runner: Callable[[dict], dict], description: str = "",
                 available_check: Callable[[], bool] | None = None):
        self.name = name
        self.binary = binary                  # internal: real executable — never surfaced
        self.engine = engine_label(binary)    # public: branded engine label
        self.runner = runner
        self.description = description
        # Optional override for scanners whose availability depends on an
        # optional Python import (e.g. paramiko/pywinrm) rather than an
        # external CLI binary — there's nothing for shutil.which() to find.
        self._available_check = available_check

    def available(self) -> bool:
        if self._available_check is not None:
            return self._available_check()
        # Built-in (pure-Python) scanners have no external binary to locate.
        if self.binary in (None, BUILTIN, BUILTIN_PASSIVE, BUILTIN_DB):
            return True
        return shutil.which(self.binary) is not None

    def run(self, params: dict) -> dict:
        return self.runner(params)


def scanner(name: str, binary: str, description: str = "",
            available_check: Callable[[], bool] | None = None) -> Callable:
    """Register a scan capability (``binary`` is the internal executable to run).

    ``available_check``, when given, replaces the default shutil.which()-based
    availability test — for scanners gated on an optional Python import
    instead of a binary on PATH.
    """
    def deco(fn: Callable[[dict], dict]) -> Callable[[dict], dict]:
        REGISTRY[name] = Scanner(name, binary, fn, description, available_check)
        return fn
    return deco


# ── helpers ──────────────────────────────────────────────────────────────────

def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def normalize_targets(params: dict) -> list[str]:
    """Accept targets as a list, or a comma/space/newline-separated string."""
    t = params.get("targets") or params.get("scope_cidrs") or params.get("target")
    if isinstance(t, str):
        t = [x.strip() for x in t.replace(",", " ").split() if x.strip()]
    return [str(x).strip() for x in (t or []) if str(x).strip()]


def split_host_port(target: str) -> tuple[str, int | None]:
    """Split ``host:port`` → (host, port). Handles IPv6 in ``[::1]:8080`` form.

    Returns (host, None) when no port is present.
    """
    target = target.strip()
    if target.startswith("["):  # [ipv6]:port  or  [ipv6]
        host, _, rest = target[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, int(port) if port.isdigit() else None
    # host:port only when there is exactly one colon (else it's a bare IPv6)
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        return host, int(port) if port.isdigit() else None
    return target, None


def expand_hosts(targets: list[str], max_hosts: int = 4096) -> list[str]:
    """Expand CIDRs / single IPs into individual host strings for per-host probing.

    Hostnames and ``host:port`` tokens pass through untouched. CIDRs expand to
    their usable hosts (network/broadcast excluded for IPv4 blocks). The total is
    capped at ``max_hosts`` so a stray ``/8`` can never blow up the probe.
    """
    out: list[str] = []
    for raw in targets:
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            out.append(raw)  # hostname or host:port — keep as-is
            if len(out) >= max_hosts:
                return out[:max_hosts]
            continue
        hosts = net.hosts() if net.num_addresses > 2 else [net.network_address]
        for ip in hosts:
            out.append(str(ip))
            if len(out) >= max_hosts:
                return out[:max_hosts]
    return out


def run_cmd(cmd: list[str], timeout: int = 1800, input_text: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
    try:
        import probe_logger  # probe-local module; may not exist in test environments
        probe_logger.log_cmd(cmd, proc)
    except ImportError:
        pass
    return proc


def deduplicate_targets(targets: list[str]) -> list[str]:
    """Preserve order while removing exact duplicates."""
    seen: set[str] = set()
    out: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def scope_check(targets: list[str], allowed_cidrs: list[str]) -> tuple[list[str], list[str]]:
    """Return (allowed, blocked) by checking each target against ``allowed_cidrs``.

    IP targets are range-checked. Hostnames pass through (the manager already
    validated scope at the job-queue level; the probe can't resolve them to IPs
    without a network round-trip that might itself be out-of-scope).
    An empty ``allowed_cidrs`` is treated as "unrestricted" (all pass through).
    """
    if not allowed_cidrs:
        return targets, []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in allowed_cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    if not networks:
        return targets, []
    allowed: list[str] = []
    blocked: list[str] = []
    for t in targets:
        host, _ = split_host_port(t)
        try:
            addr = ipaddress.ip_address(host)
            if any(addr in net for net in networks):
                allowed.append(t)
            else:
                blocked.append(t)
        except ValueError:
            allowed.append(t)   # hostname — let it through
    return allowed, blocked


def result(scan_type: str, tool: str, targets: list[str], *, ok: bool = True,
           error: str | None = None, started: datetime | None = None, **extra: Any) -> dict:
    """Build the normalized result envelope every scanner returns.

    ``tool`` is passed as the internal binary name; it is branded to the public
    engine label and any ``error`` text is scrubbed of raw tool names before the
    envelope leaves the probe.
    """
    fin = now()
    out: dict[str, Any] = {
        "scan_type": scan_type,
        "engine": engine_label(tool),
        "tool": engine_label(tool),  # back-compat key; value is the branded label
        "targets": targets,
        "ok": ok and error is None,
        "error": sanitize(error) if error else error,
        "finished_at": iso(fin),
    }
    if started is not None:
        out["started_at"] = iso(started)
        out["duration_sec"] = round((fin - started).total_seconds(), 1)
    out.update(extra)
    return out
