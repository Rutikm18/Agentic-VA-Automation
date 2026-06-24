#!/usr/bin/env python3
"""Dispatch scan jobs to a running Intrynx probe and stream results.

Usage:
  ./dispatch_scan.py 127.0.0.1                    # discovery on localhost
  ./dispatch_scan.py 10.0.0.0/24 discovery        # discovery on a range
  ./dispatch_scan.py 192.168.1.0/24 cloud_scan    # vuln scan
  ./dispatch_scan.py 192.168.1.10 lateral         # SMB/AD enumeration
  ./dispatch_scan.py --status                     # show probe + pending jobs
  ./dispatch_scan.py --results                    # show latest job results

Reads PLATFORM_URL / OPERATOR_EMAIL / OPERATOR_PASSWORD from probe.env.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ── load probe.env ────────────────────────────────────────────────────────────

def _load_env(path: Path) -> None:
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass

_load_env(Path(__file__).resolve().parent / "probe.env")

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:18080").rstrip("/")
EMAIL        = os.environ.get("OPERATOR_EMAIL", "admin@adversa.io")
PASSWORD     = os.environ.get("OPERATOR_PASSWORD", "ChangeMe123!")

# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http(method: str, path: str, token: str | None = None, **kw) -> dict | list:
    import httpx
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = PLATFORM_URL + path
    r = httpx.request(method, url, headers=headers, timeout=30, **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


# ── auth ──────────────────────────────────────────────────────────────────────

def login() -> str:
    data = _http("POST", "/auth/login", json={"email": EMAIL, "password": PASSWORD})
    return data["access_token"]


# ── engagement helpers ────────────────────────────────────────────────────────

def get_or_create_engagement(token: str, target: str) -> str:
    """Return an engagement_id, creating one on the fly if needed."""
    items = _http("GET", "/engagements", token).get("items", [])
    # Prefer an active engagement; draft is fine too.
    for status in ("active", "draft"):
        for e in items:
            if e["status"] == status:
                return str(e["id"])
    # Nothing usable — create a quick one.
    # Derive a CIDR from the target (works for IPs, CIDRs, and hostnames).
    import ipaddress
    try:
        net = str(ipaddress.ip_network(target, strict=False))
    except ValueError:
        net = "0.0.0.0/0"   # hostname target — open scope
    eng = _http("POST", "/engagements", token, json={
        "name": f"probe-dispatch-{time.strftime('%Y%m%d-%H%M')}",
        "scope_cidrs": [net],
    })
    return str(eng["id"])


# ── dispatch ──────────────────────────────────────────────────────────────────

def dispatch(target: str, job_type: str, token: str) -> str:
    eng_id = get_or_create_engagement(token, target)
    job = _http("POST", "/agents/jobs", token, json={
        "engagement_id": eng_id,
        "job_type": job_type,
        "params": {
            "targets": [target],
            "scan_type": {
                "discovery": "discovery",
                "lateral":   "smb_enum",
                "cloud_scan": "vuln_scan",
            }.get(job_type, "discovery"),
        },
    })
    return str(job["job_id"])


# ── wait for result ───────────────────────────────────────────────────────────

def wait_for_result(job_id: str, token: str, timeout: int = 600) -> dict | None:
    """Poll the engagement's job list until the job completes."""
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        # Check all engagements' jobs for this job_id
        items = _http("GET", "/engagements", token).get("items", [])
        for eng in items:
            try:
                jobs = _http("GET", f"/engagements/{eng['id']}/jobs", token)
                if isinstance(jobs, dict):
                    jobs = jobs.get("items", [])
                for j in (jobs or []):
                    if str(j.get("id")) == job_id:
                        if j.get("status") in ("completed", "failed"):
                            return j
            except Exception:
                pass
        dots = (dots + 1) % 4
        print(f"\r  waiting for probe{'.' * (dots + 1)}   ", end="", flush=True)
        time.sleep(3)
    return None


# ── display ───────────────────────────────────────────────────────────────────

_C = sys.stdout.isatty()
def _col(c, s): return f"\033[{c}m{s}\033[0m" if _C else s
def bold(s): return _col("1", s)
def dim(s):  return _col("2", s)
def green(s): return _col("32", s)
def red(s):   return _col("31", s)
def cyan(s):  return _col("36", s)
def yellow(s): return _col("33", s)
def magenta(s): return _col("35", s)


def show_result(job: dict) -> None:
    print()
    r = job.get("result") or {}
    ok = job.get("status") == "completed"
    scan_type = r.get("scan_type", job.get("job_type", "?"))
    print(cyan("━" * 68))
    print(f"  {bold('Scan result')} · {bold(scan_type)}  {'✓' if ok else '✗'}")
    print(cyan("━" * 68))

    if r.get("error"):
        print(red(f"\n  Error: {r['error']}"))

    for h in r.get("hosts", []):
        ip = h.get("ip", "?")
        hn = f"  {dim(h['hostname'])}" if h.get("hostname") else ""
        print(f"\n{green('●')} {bold(ip)}{hn}")
        for p in h.get("ports", []):
            port = f"{p.get('port')}/{p.get('protocol', '')}"
            svc = p.get("service") or ""
            prod = p.get("product") or ""
            print(f"    {cyan(f'{port:<12}')} {green('open  ')} {yellow(f'{svc:<14}')} {prod}")

    for s in r.get("web_services", []):
        code = s.get("status")
        col = green if (isinstance(code, int) and code < 400) else yellow
        title = f"  {s['title']}" if s.get("title") else ""
        tech = f"  {dim('[' + ', '.join(s['tech']) + ']')}" if s.get("tech") else ""
        print(f"  {col(str(code or '?')):<6} {bold(s.get('url', ''))}{title}{tech}")

    sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_col = {"critical": red, "high": magenta, "medium": yellow, "low": dim, "info": dim}
    for f in sorted(r.get("findings", []), key=lambda x: sev_ord.get(x.get("severity","info").lower(), 9)):
        sev = (f.get("severity") or "info").lower()
        tag = sev_col.get(sev, dim)(f"[{sev.upper():<8}]")
        name = f.get("title") or f.get("name") or f.get("template_id") or "finding"
        where = f.get("matched_at") or f.get("target") or ""
        print(f"  {tag} {name}")
        if where:
            print(dim(f"             {where}"))

    # Summary
    bits = []
    for k, lbl in (("host_count","hosts"),("service_count","services"),
                    ("open_ports","open ports"),("finding_count","findings"),
                    ("endpoints_probed","endpoints probed")):
        if r.get(k):
            bits.append(f"{bold(str(r[k]))} {lbl}")
    print(f"\n  {green('✓') if ok else red('✗')} " + (" · ".join(bits) if bits else "nothing found") + "\n")


def cmd_status(token: str) -> None:
    agents = _http("GET", "/agents", token)
    print(f"\n  {bold('Probes')}\n")
    for a in (agents if isinstance(agents, list) else []):
        mark = green("●") if a.get("online") else dim("○")
        caps = len(a.get("capabilities", []))
        hb = (a.get("last_heartbeat") or "")[:19]
        print(f"  {mark} {bold(a['name']):<25} {a['status']:<8} {caps} caps  hb={hb}")
    print()
    # Jobs across engagements
    items = _http("GET", "/engagements", token).get("items", [])
    for eng in items[:3]:
        try:
            jobs = _http("GET", f"/engagements/{eng['id']}/jobs", token)
            if isinstance(jobs, dict): jobs = jobs.get("items", [])
            for j in (jobs or [])[:5]:
                st = j.get("status","?")
                col = green if st == "completed" else yellow if st == "running" else dim
                print(f"  {col(f'[{st:<9}]')} {j.get('job_type','?'):<12} {str(j.get('id',''))[:8]}…  eng:{str(eng['id'])[:8]}…")
        except Exception:
            pass
    print()


def cmd_results(token: str) -> None:
    items = _http("GET", "/engagements", token).get("items", [])
    print(f"\n  {bold('Latest results')}\n")
    for eng in items[:3]:
        try:
            jobs = _http("GET", f"/engagements/{eng['id']}/jobs", token)
            if isinstance(jobs, dict): jobs = jobs.get("items", [])
            for j in sorted((jobs or []),
                             key=lambda x: x.get("completed_at") or "", reverse=True)[:3]:
                if j.get("status") == "completed":
                    show_result(j)
                    return
        except Exception:
            pass
    print("  No completed jobs found yet.\n")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    try:
        token = login()
    except Exception as exc:
        print(f"Login failed: {exc}")
        return 1

    if argv[0] == "--status":
        cmd_status(token)
        return 0
    if argv[0] == "--results":
        cmd_results(token)
        return 0

    target   = argv[0]
    job_type = argv[1] if len(argv) > 1 else "discovery"

    VALID = ("discovery", "lateral", "cloud_scan")
    if job_type not in VALID:
        print(f"  job_type must be one of {VALID}")
        return 1

    print(f"\n  {bold('Dispatching')} {job_type} → {bold(target)}")
    try:
        job_id = dispatch(target, job_type, token)
    except Exception as exc:
        print(f"  {red('Dispatch failed:')} {exc}")
        return 1

    print(f"  job_id: {dim(job_id)}")
    print(f"  Waiting for the probe to pick up and run the job ...\n")

    job = wait_for_result(job_id, token, timeout=600)
    if job is None:
        print(f"\n  {red('Timed out')} — job {job_id} still running. Check ./dispatch_scan.py --results later.")
        return 1

    show_result(job)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n  stopped")
        sys.exit(130)
