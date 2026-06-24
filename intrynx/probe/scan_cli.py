#!/usr/bin/env python3
"""Intrynx probe — standalone scan runner with a readable terminal report.

No manager, no registration, no license — just run a scan and see the results.

  ./scan_cli.py 127.0.0.1                      # discovery (default) on one host
  ./scan_cli.py scanme.nmap.org discovery      # explicit scan type
  ./scan_cli.py 10.0.0.0/24 host_discovery     # fast liveness sweep
  ./scan_cli.py 127.0.0.1 recon                # chain: discovery + AI + MCP
  ./scan_cli.py 127.0.0.1 ai_service_discovery # find AI/LLM servers
  ./scan_cli.py 127.0.0.1 discovery ports=22,80,443   # extra params: key=value
  ./scan_cli.py --list                         # show capabilities
  ./scan_cli.py --logs                         # show recent scan log summaries
  ./scan_cli.py 127.0.0.1 --json               # raw JSON instead of report
  ./scan_cli.py 127.0.0.1 --debug              # verbose debug output to stderr

Extra `key=value` args pass through to the scanner. Values stay strings unless
they're a number/bool; only list-style keys (tags, paths, signatures) are split
on commas — so `ports=22,80,443` is kept intact for the scan engine.

Troubleshooting:
  --debug         prints every subprocess command, rc, stdout/stderr to stderr
  PROBE_DEBUG=1   same as --debug but via environment variable
  --logs          shows a summary of the last 10 scan log files in ./logs/
  check ./logs/   for detailed JSONL logs of every scan that was run
"""
from __future__ import annotations

import json
import os
import sys
import time

# ── debug flag must be set before scanner modules are imported ───────────────────
if "--debug" in sys.argv:
    os.environ["PROBE_DEBUG"] = "1"
    sys.argv = [a for a in sys.argv if a != "--debug"]

import scanners
import toolchain

toolchain.prepend_path()  # find probe-local installed engines (./probe install)

# ── colors (auto-off when not a TTY or NO_COLOR set) ────────────────────────────
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)
def red(s):    return _c("31", s)
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def blue(s):   return _c("34", s)
def magenta(s):return _c("35", s)
def cyan(s):   return _c("36", s)


SEV_COLOR = {"critical": red, "high": magenta, "medium": yellow, "low": blue,
             "info": dim, "unknown": dim}
FRIENDLY = {
    "host_discovery": "host liveness sweep", "discovery": "host & service discovery",
    "port_scan": "port scan", "mass_scan": "fast port sweep",
    "service_fingerprint": "service fingerprinting", "udp_scan": "UDP service scan",
    "vuln_scan": "vulnerability scan", "tls_scan": "TLS/SSL check",
    "web_scan": "web service check", "smb_enum": "SMB/Windows check",
    "mcp_discovery": "MCP server discovery", "ai_service_discovery": "AI/LLM server discovery",
}
LIST_KEYS = {"tags", "paths", "signatures"}


# ── arg parsing ─────────────────────────────────────────────────────────────────

def coerce(v: str):
    if v.lstrip("-").isdigit():
        return int(v)
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v


def parse_params(argv: list[str], key: str) -> dict:
    """Split key=value extras into params (lists only for LIST_KEYS)."""
    params = {}
    for a in argv:
        if "=" not in a:
            continue
        k, _, v = a.partition("=")
        k = k.strip()
        params[k] = [x.strip() for x in v.split(",") if x.strip()] if k in LIST_KEYS else coerce(v)
    return params


# ── pretty renderer ─────────────────────────────────────────────────────────────

def rule(width=68):
    return dim("─" * width)


def header(res: dict, target: str, elapsed: float):
    st = res.get("scan_type", "?")
    eng = res.get("engine", res.get("tool", "?"))
    print()
    print(cyan("━" * 68))
    print(f"  {bold('Intrynx Probe')} · {bold(FRIENDLY.get(st, st))}")
    print(f"  target: {bold(target)} · engine: {eng} · {elapsed:.1f}s")
    print(cyan("━" * 68))


def render_hosts(hosts: list):
    for h in hosts:
        ip = h.get("ip") or "?"
        name = f"  {dim(h['hostname'])}" if h.get("hostname") else ""
        meta = []
        if h.get("os"):     meta.append(h["os"])
        if h.get("vendor"): meta.append(h["vendor"])
        if h.get("mac"):    meta.append(h["mac"])
        metas = dim("  " + " · ".join(meta)) if meta else ""
        print(f"\n{green('●')} {bold(ip)}{name}{metas}")
        ports = h.get("ports") or []
        for p in ports:
            port = f"{p.get('port')}/{p.get('protocol','')}"
            state = p.get("state") or "open"
            svc = p.get("service") or ""
            prod = " ".join(x for x in (p.get("product"), p.get("version")) if x)
            extra = dim(p.get("extrainfo")) if p.get("extrainfo") else ""
            cpe = dim("  " + ", ".join(p.get("cpe"))) if p.get("cpe") else ""
            # Show http-title or banner hint when no product detected.
            # Collapse \xNN binary escapes to dots so the terminal stays clean.
            import re as _re
            hint = ""
            if not prod and p.get("http_title"):
                hint = dim(f"  ← {p['http_title'][:60]}")
            elif not prod and p.get("banner"):
                clean = _re.sub(r"\\x[0-9a-fA-F]{2}|\\[0-9]{3}", ".", p["banner"])
                clean = _re.sub(r"\.{3,}", "…", clean).strip()
                if clean:
                    hint = dim(f"  ← {clean[:70]}")
            print(f"    {cyan(f'{port:<11}')} {green(f'{state:<6}')} {yellow(f'{svc:<14}')} {prod}{(' ' + extra) if extra else ''}{cpe}{hint}")
        if not ports and not h.get("os"):
            print(dim("    (alive, no open ports detected)"))


def render_findings(findings: list, title="Findings"):
    if not findings:
        return
    print(f"\n{bold(title)}")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order.get((x.get("severity") or "info").lower(), 9)):
        sev = (f.get("severity") or "info").lower()
        tag = SEV_COLOR.get(sev, dim)(f"[{sev.upper():<8}]")
        name = f.get("title") or f.get("name") or f.get("template_id") or "finding"
        where = f.get("matched_at") or f.get("target") or f.get("url") or ""
        cves = " " + magenta(",".join(f["cves"])) if f.get("cves") else ""
        print(f"  {tag} {name}{cves}")
        if where:
            print(dim(f"            {where}"))
        if f.get("detail"):
            print(dim(f"            {f['detail']}"))


def render_services(services: list, title="Services"):
    print(f"\n{bold(title)}")
    for s in services:
        url = s.get("url") or ""
        prod = s.get("product") or s.get("name") or ""
        models = f"  models: {', '.join(s['models'][:4])}" if s.get("models") else ""
        ver = f" {s['version']}" if s.get("version") else ""
        print(f"  {green('●')} {bold(prod)}{ver}  {dim(url)}{dim(models)}")


def render_web(services: list):
    print(f"\n{bold('Web services')}")
    for s in services:
        code = s.get("status")
        col = green if (isinstance(code, int) and code < 400) else yellow if (isinstance(code, int) and code < 500) else red
        title = f"  {s['title']}" if s.get("title") else ""
        ws = f"  {dim(s['webserver'])}" if s.get("webserver") else ""
        tech = f"  {dim('[' + ', '.join(s['tech']) + ']')}" if s.get("tech") else ""
        print(f"  {col(str(code or '?')):<6} {bold(s.get('url') or '')}{title}{ws}{tech}")


def render_mcp(servers: list):
    print(f"\n{bold('MCP servers')}")
    for s in servers:
        danger = red("  ⚠ code/data tools") if s.get("dangerous_tools") else ""
        print(f"  {green('●')} {bold(s.get('server_name') or s.get('url'))}  {dim(s.get('transport',''))}{danger}")
        if s.get("tools"):
            print(dim(f"      tools: {', '.join(s['tools'][:10])}"))


def render(res: dict, target: str, elapsed: float):
    header(res, target, elapsed)
    if not res.get("ok"):
        print(red(f"\n  ✗ {res.get('error', 'scan failed')}"))
        if res.get("engine"):
            print(dim(f"  engine : {res['engine']}"))
        print(dim("  tip    : run with --debug for full subprocess output"))
        print(dim("  tip    : run --logs to review recent scan history"))
        print()
        return

    if res.get("hosts"):
        render_hosts(res["hosts"])
    if res.get("web_services"):
        render_web(res["web_services"])
    if res.get("ai_services"):
        render_services(res["ai_services"], "AI / LLM services")
    if res.get("mcp_servers"):
        render_mcp(res["mcp_servers"])
    if res.get("by_category"):
        cats = " · ".join(f"{k}:{v}" for k, v in res["by_category"].items())
        print(dim(f"\n  categories: {cats}"))
    if res.get("findings"):
        render_findings(res["findings"])

    # summary line
    bits = []
    for k, label in (("host_count", "hosts"), ("server_count", "servers"),
                     ("service_count", "services"), ("open_ports", "open ports"),
                     ("finding_count", "findings")):
        if res.get(k):
            bits.append(f"{bold(str(res[k]))} {label}")
    print(f"\n  {green('✓')} " + (" · ".join(bits) if bits else "nothing found") + "\n")


# ── recon: chain several scans into one report ──────────────────────────────────

RECON_CHAIN = ["discovery", "ai_service_discovery", "mcp_discovery"]


def _show_log_hint() -> None:
    try:
        import probe_logger
        logs = probe_logger.recent_logs(1)
        if logs:
            print(dim(f"  log: {logs[0]}"))
    except Exception:
        pass


def run_one(scan_type: str, params: dict) -> tuple[dict, float]:
    t0 = time.time()
    res = scanners.dispatch(scan_type, params)
    return res, time.time() - t0


def cmd_list():
    print(f"\n  {bold('Available scans')} (✓ ready on this machine):\n")
    for c in scanners.capability_catalog():
        mark = green("✓") if c["available"] else red("✗")
        print(f"   {mark} {bold(c['scan_type']):<32} {dim('[' + c['engine'] + ']')}")
    print()


def cmd_logs():
    import probe_logger
    logs = probe_logger.recent_logs(10)
    if not logs:
        print(f"\n  {dim('No scan logs found in')} {probe_logger.LOG_DIR}\n")
        return
    print(f"\n  {bold('Recent scan logs')} ({probe_logger.LOG_DIR}):\n")
    for p in logs:
        rec = probe_logger.tail_log(p)
        if not rec:
            continue
        ok_mark = green("✓") if rec.get("summary", {}).get("ok") else red("✗")
        st = rec.get("scan_type", "?")
        tgts = rec.get("targets", [])
        tgt_str = ", ".join(tgts[:2]) + ("…" if len(tgts) > 2 else "")
        s = rec.get("summary", {})
        bits = []
        for k, lbl in (("host_count", "hosts"), ("finding_count", "findings"),
                        ("service_count", "services"), ("endpoints_probed", "probed")):
            if s.get(k):
                bits.append(f"{s[k]} {lbl}")
        summary = "  " + " · ".join(bits) if bits else ""
        err = f"  {red(s['error'][:80])}" if s.get("error") else ""
        print(f"  {ok_mark} {bold(st):<30} {dim(tgt_str)}{summary}{err}")
        print(f"       {dim(str(p))}")
    print()


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--list":
        cmd_list()
        return 0
    if argv[0] == "--logs":
        cmd_logs()
        return 0

    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]

    target = argv[0]
    rest = argv[1:]
    scan_type = next((a for a in rest if "=" not in a), "discovery")
    params = parse_params(rest, scan_type)
    params["targets"] = [target]

    if scan_type == "recon":
        print()
        print(cyan("━" * 68))
        print(f"  {bold('Intrynx Probe · RECON')} · target: {bold(target)}")
        print(cyan("━" * 68))
        worst_ok = True
        for st in RECON_CHAIN:
            res, el = run_one(st, dict(params))
            render(res, target, el)
            worst_ok = worst_ok and res.get("ok", False)
        _show_log_hint()
        return 0 if worst_ok else 1

    res, el = run_one(scan_type, params)
    if as_json:
        print(json.dumps(res, indent=2, default=str))
    else:
        render(res, target, el)
        _show_log_hint()
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n  stopped")
        sys.exit(130)
