#!/usr/bin/env python3
"""
ADVERSA probe — a lightweight remote scanning agent.

Deploys on a target network, registers with the platform, then polls for and
executes network-side scan jobs (discovery, fingerprinting, vuln, TLS, web, SMB,
MCP/AI) and submits results. Scan engines are an internal detail — results and
logs reference only branded engine labels.

Protocol (matches the platform's /agents API):
  login (operator)  → POST /auth/login            (only to obtain a registration token)
  register          → POST /agents/register       → {agent_id, token}
  heartbeat (30s)   → POST /agents/heartbeat
  poll jobs         → GET  /agents/{id}/jobs?limit=N
  submit result     → POST /agents/{id}/jobs/{job_id}/result

All agent calls send the agent's own bearer token. The agent_id + token are
cached in STATE_FILE so restarts reuse the same identity.

Config via environment (see probe.env.example):
  PLATFORM_URL              e.g. https://adversa.example.com   (required)
  PROBE_NAME                display name                       (default: hostname)
  PROBE_LOCATION            free text
  PROBE_CAPABILITIES        comma list                         (default: discovery)
  PROBE_NETWORK_SEGMENTS    comma list of CIDRs the probe can reach
  # Auth — provide ONE of:
  OPERATOR_EMAIL + OPERATOR_PASSWORD     (probe logs in and self-registers)
  AGENT_ID + AGENT_TOKEN                 (pre-provisioned identity)
  HEARTBEAT_INTERVAL        seconds      (default: 30)
  POLL_INTERVAL             seconds      (default: 10)
  JOB_LIMIT                 jobs per poll (default: 1)
  PROBE_DEFAULT_TARGETS     fallback scan targets if a job carries none
  SCAN_DEFAULT_ARGS         default discovery engine flags (default: -sV -T4 -Pn)
  VERIFY_TLS                "false" to skip TLS verification (default: true)
  STATE_FILE                identity cache (default: /var/lib/adversa-probe/state.json)
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import httpx

import scanners
import security
import toolchain

VERSION = "1.2.0"

# Plain-English names for each scan type, used in operator-facing messages.
FRIENDLY_SCAN = {
    "host_discovery": "host discovery",
    "discovery": "host & service discovery",
    "port_scan": "port scan",
    "mass_scan": "fast port sweep",
    "service_fingerprint": "service fingerprinting",
    "udp_scan": "UDP service scan",
    "vuln_scan": "vulnerability scan",
    "tls_scan": "TLS/SSL check",
    "web_scan": "web service check",
    "smb_enum": "Windows/SMB check",
    "mcp_discovery": "MCP server discovery",
    "ai_service_discovery": "AI/LLM server discovery",
    "passive_discovery": "passive OT-safe listening",
    "db_fingerprint": "database fingerprint",
    "ssh_inventory": "credentialed Linux inventory (SSH)",
    "windows_inventory": "credentialed Windows inventory (WinRM/SMB)",
}

# ── config ────────────────────────────────────────────────────────────────────

def _load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from probe.env without shell evaluation.

    Values may contain spaces / dashes (e.g. ``-sV -T4 -Pn``). Existing
    environment variables win, so Docker ``--env-file`` and systemd
    ``EnvironmentFile`` still take precedence.
    """
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_env_file(Path(__file__).resolve().parent / "probe.env")

PLATFORM_URL = os.environ.get("PLATFORM_URL", "").rstrip("/")
PROBE_NAME = os.environ.get("PROBE_NAME") or socket.gethostname()
PROBE_LOCATION = os.environ.get("PROBE_LOCATION", "")
# Explicit override via PROBE_CAPABILITIES, else auto-detect from installed tools.
_ENV_CAPS = os.environ.get("PROBE_CAPABILITIES")
CAPABILITIES = [c.strip() for c in _ENV_CAPS.split(",") if c.strip()] if _ENV_CAPS else None


def effective_capabilities() -> list[str]:
    return CAPABILITIES or scanners.available_capabilities()
NETWORK_SEGMENTS = [s.strip() for s in os.environ.get("PROBE_NETWORK_SEGMENTS", "").split(",") if s.strip()]
OPERATOR_EMAIL = os.environ.get("OPERATOR_EMAIL", "")
OPERATOR_PASSWORD = os.environ.get("OPERATOR_PASSWORD", "")
AGENT_ID = os.environ.get("AGENT_ID", "")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))
JOB_LIMIT = int(os.environ.get("JOB_LIMIT", "1"))
DEFAULT_TARGETS = os.environ.get("PROBE_DEFAULT_TARGETS", "")
# Default discovery-engine flags (back-compat: honour the legacy NMAP_DEFAULT_ARGS).
SCAN_DEFAULT_ARGS = os.environ.get("SCAN_DEFAULT_ARGS") or os.environ.get("NMAP_DEFAULT_ARGS", "-sV -T4 -Pn")
VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() not in ("false", "0", "no")
STATE_FILE = Path(os.environ.get("STATE_FILE", "/var/lib/adversa-probe/state.json"))
# Anti-copy: a valid host-locked license is required to run unless explicitly disabled.
LICENSE_ENFORCED = os.environ.get("LICENSE_ENFORCED", "true").lower() not in ("false", "0", "no")
# Self-provisioning: auto-install missing scan engines on start (idempotent).
AUTO_INSTALL_TOOLS = os.environ.get("AUTO_INSTALL_TOOLS", "true").lower() not in ("false", "0", "no")


def log(level: str, msg: str, **kw: Any) -> None:
    extra = " ".join(f"{k}={v}" for k, v in kw.items())
    print(f"[{time.strftime('%H:%M:%S')}] {level:<5} {msg} {extra}".rstrip(), flush=True)


def say(msg: str = "", indent: int = 0) -> None:
    """Print a plain-English, operator-facing line."""
    print(("  " * indent) + msg, flush=True)


def banner() -> None:
    say("Intrynx Probe")
    say("--------------------------------")


# ── identity (login → register, cached, host-bound encryption) ─────────────────

def _host_fp() -> str:
    return security.hostid.host_fingerprint()


def _load_state() -> dict[str, str]:
    """Load the cached identity, decrypting it with this machine's key.

    A state file copied from another machine won't decrypt here → returns {} and
    the probe simply re-registers (the stolen identity is useless).
    """
    try:
        blob = STATE_FILE.read_text()
    except OSError:
        return {}
    return security.decrypt_state(blob, _host_fp())


def _save_state(state: dict[str, str]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(security.encrypt_state(state, _host_fp()))
    except OSError as exc:
        log("WARN", "could not persist state", error=str(exc))


def obtain_identity(client: httpx.Client) -> tuple[str, str]:
    """Return (agent_id, agent_token), reusing cache / env, else registering."""
    if AGENT_ID and AGENT_TOKEN:
        return AGENT_ID, AGENT_TOKEN

    cached = _load_state()
    if cached.get("agent_id") and cached.get("token"):
        return cached["agent_id"], cached["token"]

    if not (OPERATOR_EMAIL and OPERATOR_PASSWORD):
        say("Setup needed: no sign-in details for the manager.")
        say("Add OPERATOR_EMAIL and OPERATOR_PASSWORD to probe.env (or run './probe setup').")
        raise SystemExit(1)

    # 1. operator login → registration token
    r = client.post("/auth/login", json={"email": OPERATOR_EMAIL, "password": OPERATOR_PASSWORD})
    r.raise_for_status()
    op_token = r.json()["access_token"]

    # 2. register this probe
    r = client.post(
        "/agents/register",
        headers={"Authorization": f"Bearer {op_token}"},
        json={
            "name": PROBE_NAME,
            "location": PROBE_LOCATION or None,
            "capabilities": effective_capabilities(),
            "network_segments": NETWORK_SEGMENTS,
        },
    )
    r.raise_for_status()
    data = r.json()
    _save_state({"agent_id": data["agent_id"], "token": data["token"]})
    return data["agent_id"], data["token"]


# ── job execution ──────────────────────────────────────────────────────────────

def execute_job(job: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
    """
    Resolve the scan_type (from params, else mapped from job_type), inject fallback
    targets/args, run the matching scanner, and return (ok, result, error).
    """
    params = dict(job.get("params") or {})
    scan_type = scanners.resolve_scan_type(job.get("job_type"), params)

    # Fallback targets if the job carries none.
    if not (params.get("targets") or params.get("target") or params.get("scope_cidrs")):
        fallback = DEFAULT_TARGETS or ",".join(NETWORK_SEGMENTS)
        if fallback:
            params["targets"] = fallback
    # Don't inject SCAN_DEFAULT_ARGS when no override is set — let the scanner
    # module use its own tuned defaults (--version-intensity 7 --script=banner).

    log("INFO", "running scan", scan_type=scan_type, targets=params.get("targets"))
    res = scanners.dispatch(scan_type, params)
    return bool(res.get("ok")), res, res.get("error")


# ── license gate (anti-copy) ────────────────────────────────────────────────────

def license_gate():
    """Verify the host-locked license. Exits with a plain message on failure."""
    say("Checking deployment license...")
    if not LICENSE_ENFORCED:
        say("License check is turned off (LICENSE_ENFORCED=false).", 1)
        return None
    try:
        lic = security.check_license()
    except security.LicenseError as exc:
        say(exc.friendly, 1)
        say(f"This machine's Host ID: {security.hostid.short_id()}", 1)
        raise SystemExit(2)
    locked = "this machine" if lic.locked_to_host else "any machine"
    say(f"License OK  (customer: {lic.customer}; locked to: {locked})", 1)
    say(f"Valid until: {lic.expires_at[:10]}", 1)
    return lic


def auto_provision() -> None:
    """Make sure missing scan engines are installed (no-op when all present)."""
    toolchain.prepend_path()
    if not AUTO_INSTALL_TOOLS:
        return
    missing = toolchain.missing_engines()
    if not missing:
        return
    say(f"Setting up scan engines ({', '.join(missing)}) — one-time ...")
    report = toolchain.ensure(log=lambda m: say(m))
    ok = [t for t, s in report if s == "installed"]
    bad = [t for t, s in report if s == "failed"]
    if ok:
        say(f"Installed: {', '.join(ok)}", 1)
    if bad:
        say(f"Couldn't auto-install: {', '.join(bad)} — those scans stay disabled.", 1)


def summarize(res: dict[str, Any]) -> str:
    """One plain-English line describing a scan result."""
    if not res.get("ok"):
        return "finished with a problem: " + (res.get("error") or "unknown error")
    bits = []
    for key, label in (("host_count", "hosts"), ("server_count", "servers"),
                       ("service_count", "services"), ("open_ports", "open ports"),
                       ("finding_count", "findings")):
        if res.get(key):
            bits.append(f"{res[key]} {label}")
    return "done — " + (", ".join(bits) if bits else "nothing found")


# ── connect / register (resilient, plain-English) ───────────────────────────────

def connect_with_retry(client: httpx.Client) -> tuple[str, str]:
    """Register with the manager, retrying on network errors with friendly messages.

    Configuration problems (missing creds) exit cleanly; bad credentials exit with
    a clear message; transient connection issues just keep retrying.
    """
    while True:
        try:
            return obtain_identity(client)
        except SystemExit:
            raise  # already printed a friendly, actionable message
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code in (401, 403):
                say("The manager rejected the sign-in — check OPERATOR_EMAIL and OPERATOR_PASSWORD.")
                raise SystemExit(1)
            say(f"The manager replied with an error (HTTP {code}). Trying again in {POLL_INTERVAL}s ...")
        except httpx.HTTPError:
            say(f"Can't reach the manager at {PLATFORM_URL} yet.")
            say("Check the address is right and the manager is running. Trying again ...", 1)
        time.sleep(POLL_INTERVAL)


# ── main loop ──────────────────────────────────────────────────────────────────

def main() -> None:
    banner()
    license_gate()
    auto_provision()

    if not PLATFORM_URL:
        say("Setup needed: the manager address (PLATFORM_URL) is not set.")
        say("Run './probe setup' or edit probe.env, then start again.")
        raise SystemExit(1)

    timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=30.0)
    client = httpx.Client(base_url=PLATFORM_URL, timeout=timeout, verify=VERIFY_TLS)
    say(f"Connecting to the Intrynx manager at {PLATFORM_URL} ...")
    agent_id, token = connect_with_retry(client)
    auth = {"Authorization": f"Bearer {token}"}

    caps = effective_capabilities()
    friendly = ", ".join(FRIENDLY_SCAN.get(c, c) for c in caps) or "none"
    say(f"Registered as '{PROBE_NAME}'. Ready.")
    say(f"Scans this probe can run: {friendly}", 1)
    say("Waiting for scan jobs...")
    last_heartbeat = 0.0

    while True:
        now = time.monotonic()
        try:
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                client.post("/agents/heartbeat", headers=auth,
                            json={"agent_id": agent_id, "status": "online"})
                last_heartbeat = now

            r = client.get(f"/agents/{agent_id}/jobs", headers=auth, params={"limit": JOB_LIMIT})
            if r.status_code == 401:
                say("The manager no longer accepts this probe's identity — registering again...")
                _save_state({})
                agent_id, token = obtain_identity(client)
                auth = {"Authorization": f"Bearer {token}"}
                continue
            r.raise_for_status()
            jobs = r.json()

            for job in jobs:
                job_id = job["job_id"]
                params = dict(job.get("params") or {})
                scan_type = scanners.resolve_scan_type(job.get("job_type"), params)
                targets = params.get("targets") or params.get("target") or "the configured network"
                say(f"Running {FRIENDLY_SCAN.get(scan_type, scan_type)} on {targets} ...")
                client.post("/agents/heartbeat", headers=auth,
                            json={"agent_id": agent_id, "status": "busy", "current_job_id": job_id})
                success, result, error = execute_job(job)
                client.post(
                    f"/agents/{agent_id}/jobs/{job_id}/result",
                    headers=auth,
                    json={"success": success, "result": result, "error": error},
                )
                say(summarize(result), 1)
                client.post("/agents/heartbeat", headers=auth,
                            json={"agent_id": agent_id, "status": "online"})
        except httpx.HTTPError:
            say("Can't reach the manager right now — will keep retrying.")

        time.sleep(POLL_INTERVAL)


# ── operator commands ────────────────────────────────────────────────────────────

def cmd_install() -> int:
    """Install every missing scan engine (idempotent), then show what's ready."""
    banner()
    say("Provisioning scan engines ...")
    report = toolchain.ensure(log=lambda m: say(m))
    say("")
    for tool, status in report:
        mark = {"present": "ready", "installed": "installed", "failed": "FAILED"}[status]
        say(f"[{mark:>9}] {tool}", 1)
    say("")
    say("Run './probe check' to see scan capabilities.")
    return 0 if not any(s == "failed" for _, s in report) else 1


def cmd_cleanup_tools() -> int:
    banner()
    toolchain.cleanup()
    say("Removed probe-local scan engines and temp downloads.")
    return 0


def cmd_check() -> int:
    """Plain-English health check: license, host, engines, manager reachability."""
    banner()
    toolchain.prepend_path()  # so locally-installed engines are counted as ready
    say(f"Host ID (this machine): {security.hostid.host_fingerprint()}")
    say("")
    try:
        lic = security.check_license()
        say(f"License: OK — {lic.customer}, valid until {lic.expires_at[:10]}")
    except security.LicenseError as exc:
        say("License: " + exc.friendly)
    say("")
    say("Scans available on this machine:")
    for c in scanners.capability_catalog():
        mark = "ready    " if c["available"] else "missing  "
        say(f"[{mark}] {FRIENDLY_SCAN.get(c['scan_type'], c['scan_type'])}", 1)
    if PLATFORM_URL:
        say("")
        say(f"Manager: {PLATFORM_URL}")
        try:
            r = httpx.Client(timeout=10.0, verify=VERIFY_TLS).get(f"{PLATFORM_URL}/health")
            say(f"reachable (status {r.status_code}).", 1)
        except httpx.HTTPError:
            say("could not reach the manager right now.", 1)
    else:
        say("")
        say("Manager address not set yet — run './probe setup'.")
    return 0


def cmd_setup() -> int:
    """Guided, plain-English first-time setup that writes probe.env."""
    banner()
    say("Let's set up this probe. Press Enter to keep the [default].")
    say("")
    env_path = Path("probe.env")

    def ask(label: str, default: str = "") -> str:
        d = f" [{default}]" if default else ""
        val = input(f"{label}{d}: ").strip()
        return val or default

    platform = ask("Manager address (https://...)", PLATFORM_URL)
    name = ask("A name for this probe", PROBE_NAME)
    segments = ask("Networks this probe can scan (comma-separated CIDRs)", ",".join(NETWORK_SEGMENTS))
    email = ask("Operator email (to register with the manager)", OPERATOR_EMAIL)
    password = ask("Operator password", "")
    license_token = ask("Deployment license (from your administrator)", "")

    lines = [
        f"PLATFORM_URL={platform}",
        f"PROBE_NAME={name}",
        f"PROBE_NETWORK_SEGMENTS={segments}",
        f"OPERATOR_EMAIL={email}",
        f"OPERATOR_PASSWORD={password}",
        f"PROBE_LICENSE={license_token}",
        "VERIFY_TLS=true",
    ]
    env_path.write_text("\n".join(lines) + "\n")
    say("")
    say(f"Saved to {env_path.resolve()}.")
    say("Start the probe with:  ./probe run")
    return 0


def _dispatch_cli(argv: list[str]) -> int:
    cmd = argv[0] if argv and not argv[0].startswith("-") else "run"
    if cmd in ("run", ""):
        main()
        return 0
    if cmd in ("check", "doctor"):
        return cmd_check()
    if cmd == "setup":
        return cmd_setup()
    if cmd in ("install", "install-tools"):
        return cmd_install()
    if cmd in ("cleanup-tools", "uninstall-tools"):
        return cmd_cleanup_tools()
    if cmd == "hostid":
        say(security.hostid.host_fingerprint())
        return 0
    if cmd in ("version", "--version", "-v"):
        say(f"Intrynx Probe {VERSION}")
        return 0
    say(f"Unknown command '{cmd}'.")
    say("Usage:  ./probe [run|check|install|cleanup-tools|setup|hostid|version]")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(_dispatch_cli(sys.argv[1:]))
    except KeyboardInterrupt:
        say("")
        say("Probe stopped.")
        sys.exit(0)
