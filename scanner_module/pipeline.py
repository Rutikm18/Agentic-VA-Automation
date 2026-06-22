#!/usr/bin/env python3
"""
pipeline.py — staged, profile-aware scan orchestrator.

WHY THIS EXISTS (vs. run_scan.py):
  run_scan.py runs each selected scanner against EVERY target independently and
  dumps every raw observation. That is the right tool for measuring a single
  scanner's false-positive rate. It is the wrong tool for an actual assessment,
  where you want a FUNNEL:

      discover live hosts  ->  scan ports on live hosts ONLY
                           ->  grab services on OPEN ports ONLY
                           ->  deep-inspect (tls/web/smb/db) the RELEVANT ports ONLY

  Each stage narrows the scope of the next, so you send the minimum number of
  packets and you get back a clean per-host rollup instead of 254 lines of
  "host is down". This module builds that funnel on top of the existing base
  scanners — it does not reimplement any scanning.

ENVIRONMENT PROFILES (the important part):
  Networks are not interchangeable. The same scan that is routine on a corporate
  LAN can knock an embedded device offline or disrupt a physical process. So the
  pipeline runs under a PROFILE that fixes the policy:

    --profile it   ACTIVE, full funnel, normal speed. Corporate / server LANs.
    --profile iot  ACTIVE but GENTLE: low rate, low concurrency, long timeouts,
                   curated embedded-device port set, no SMB/DB hammering.
                   Cameras, printers, embedded Linux, consumer IoT.
    --profile ot   PASSIVE ONLY. Operational Technology / ICS / SCADA. NO packet
                   is ever sent to a target. Runs the listen-only collector and
                   HARD-REFUSES every active scanner. An unsolicited probe to a
                   PLC/RTU can disrupt a live process — so on OT we only listen.

  The OT gate is not a default you can override with a flag — active scanning is
  structurally unreachable in the ot profile. That is deliberate.

USAGE:
  python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile it
  python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile iot
  python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile ot --listen-seconds 120
  python3 pipeline.py -t 10.0.0.0/24   -s scope.txt --profile it -o results.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from scanner.scanner_base import (
    ScopeGuard, ResultWriter, RateLimiter, ScanResult, expand_targets,
    setup_logging, main_entrypoint, LOG,
)
from scanner.host_discovery import HostDiscoveryScanner
from scanner.port_scanner import PortScanner
from scanner.service_banner import ServiceBannerScanner
from scanner.tls_scanner import TLSScanner
from scanner.web_scanner import WebScanner
from scanner.smb_scanner import SMBScanner
from scanner.db_scanner import DBScanner, DEFAULT_DB_PORTS
from scanner.passive_collector import PassiveCollector


# --------------------------------------------------------------------------- #
# Port sets per profile. Deliberately small and purposeful.
# --------------------------------------------------------------------------- #
IT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    8000, 8080, 8443, 9200, 11211, 27017,
]
# IoT / embedded: the ports embedded gear actually exposes. No Windows-domain
# or DB ports — pointless on a camera and just extra packets at a fragile stack.
IOT_PORTS = [
    22, 23, 80, 443, 554, 1883, 8883, 5683, 8080, 8443, 8888, 9000, 9100,
    49152, 62078, 5000, 8081, 37777,
]

# Which open TCP ports route to which deep scanner.
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 5986}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9000, 9200, 8081, 5000}
SMB_PORTS = {139, 445}
DB_PORTS = set(DEFAULT_DB_PORTS.keys())

PROFILES: dict[str, dict] = {
    "it": {
        "mode": "active",
        "ports": IT_PORTS,
        "rate": 200.0, "concurrency": 100, "timeout": 3.0,
        # Discovery uses a SHORTER timeout than the service/deep stages. Because
        # each probe holds a concurrency slot for the full timeout, the dead
        # hosts on a sparse /24 dominate runtime, and that cost scales directly
        # with this value. 1.5s is the balance point we measured on a real LAN:
        # ~2x faster than the 3s service timeout while still catching wifi
        # power-save devices that need >1s to answer a RST (1.0s missed several
        # of them). Raise with --disc-timeout for slow/remote/satellite targets.
        "disc_timeout": 1.5,
        "deep": ["tls", "web", "smb", "db"],
        "blurb": "ACTIVE full funnel — corporate / server LAN",
    },
    "iot": {
        "mode": "active",
        "ports": IOT_PORTS,
        # Gentle: a tenth of IT's rate, a fifth of the concurrency, longer waits.
        "rate": 20.0, "concurrency": 20, "timeout": 5.0,
        "disc_timeout": 2.0,   # embedded gear can be slow to answer SYNs
        "deep": ["tls", "web"],   # no SMB/DB probing of embedded devices
        "blurb": "ACTIVE but GENTLE — embedded / IoT devices",
    },
    "ot": {
        "mode": "passive",
        "blurb": "PASSIVE ONLY — OT / ICS / SCADA (no packets sent to targets)",
    },
}


# --------------------------------------------------------------------------- #
# A collecting writer: accumulates results in memory so we can both (a) build a
# clean per-host summary and (b) optionally stream raw JSONL to a file.
# --------------------------------------------------------------------------- #
class _Collector:
    def __init__(self, raw_writer: ResultWriter | None):
        self.results: list[ScanResult] = []
        self._raw = raw_writer

    def write(self, r: ScanResult) -> None:
        self.results.append(r)
        if self._raw:
            self._raw.write(r)


def _shared(scanner, limiter: RateLimiter, sem: asyncio.Semaphore):
    """
    Make a per-host scanner instance share ONE rate limiter + semaphore with all
    the others in its stage. Per-host instances let us target exactly the ports
    a given host has open (minimum packets), while the shared limiter/sem keep
    global pacing honest instead of every instance bursting on its own budget.
    """
    scanner.limiter = limiter
    scanner.sem = sem
    return scanner


async def _run_active(args, profile: dict, scope: ScopeGuard,
                      targets: list[str], collector: _Collector) -> dict:
    rate, conc, timeout = profile["rate"], profile["concurrency"], profile["timeout"]
    limiter = RateLimiter(rate)
    sem = asyncio.Semaphore(conc)

    # ---- Stage 1: discovery -------------------------------------------------
    disc_timeout = args.disc_timeout or profile.get("disc_timeout", timeout)
    LOG.info("stage 1/4: host discovery over %d target(s) (timeout %.1fs)",
             len(targets), disc_timeout)
    disc = _shared(HostDiscoveryScanner(scope, rate=rate, concurrency=conc,
                                        timeout=disc_timeout), limiter, sem)
    disc_sink = _Collector(None)
    await disc.run(targets, disc_sink)
    for r in disc_sink.results:
        collector.write(r)
    live = sorted({r.target for r in disc_sink.results
                   if r.data.get("alive")}, key=_ip_key)
    LOG.info("stage 1 complete: %d live host(s)", len(live))
    if not live:
        return {}

    # ---- Stage 2: port scan (live hosts only) -------------------------------
    LOG.info("stage 2/4: port scan over %d live host(s)", len(live))
    ports = profile["ports"]
    pscan = _shared(PortScanner(scope, ports=ports, rate=rate, concurrency=conc,
                                timeout=timeout), limiter, sem)
    port_sink = _Collector(None)
    await pscan.run(live, port_sink)
    open_map: dict[str, list[int]] = {}
    for r in port_sink.results:
        if r.status == "open" and r.port:
            open_map.setdefault(r.target, []).append(r.port)
            collector.write(r)
    for h in open_map:
        open_map[h].sort()
    total_open = sum(len(v) for v in open_map.values())
    LOG.info("stage 2 complete: %d open port(s) across %d host(s)",
             total_open, len(open_map))
    if not open_map:
        return _rollup(live, open_map, [], [])

    # ---- Stage 3: service/banner (open ports only, per host) ----------------
    LOG.info("stage 3/4: service detection on %d open port(s)", total_open)
    svc_sink = _Collector(None)
    svc_tasks = []
    for host, hports in open_map.items():
        sb = _shared(ServiceBannerScanner(scope, ports=hports, rate=rate,
                                          concurrency=conc, timeout=timeout),
                     limiter, sem)
        svc_tasks.append(sb.run([host], svc_sink))
    await asyncio.gather(*svc_tasks)
    for r in svc_sink.results:
        collector.write(r)

    # ---- Stage 4: deep protocol inspection (routed ports only) --------------
    deep = profile["deep"]
    LOG.info("stage 4/4: deep inspection (%s)", ", ".join(deep) or "none")
    deep_sink = _Collector(None)
    deep_tasks = []
    for host, hports in open_map.items():
        hset = set(hports)
        if "tls" in deep and (sel := sorted(hset & TLS_PORTS)):
            deep_tasks.append(_shared(TLSScanner(scope, ports=sel, rate=rate,
                concurrency=conc, timeout=timeout), limiter, sem).run([host], deep_sink))
        if "web" in deep and (sel := sorted(hset & WEB_PORTS)):
            deep_tasks.append(_shared(WebScanner(scope, ports=sel, rate=rate,
                concurrency=conc, timeout=timeout), limiter, sem).run([host], deep_sink))
        if "smb" in deep and (hset & SMB_PORTS):
            deep_tasks.append(_shared(SMBScanner(scope, rate=rate,
                concurrency=conc, timeout=timeout), limiter, sem).run([host], deep_sink))
        if "db" in deep and (sel := sorted(hset & DB_PORTS)):
            pmap = {p: DEFAULT_DB_PORTS[p] for p in sel}
            deep_tasks.append(_shared(DBScanner(scope, port_map=pmap, rate=rate,
                concurrency=conc, timeout=timeout), limiter, sem).run([host], deep_sink))
    if deep_tasks:
        await asyncio.gather(*deep_tasks)
    for r in deep_sink.results:
        collector.write(r)

    return _rollup(live, open_map, svc_sink.results, deep_sink.results)


async def _run_passive(args, scope: ScopeGuard, collector: _Collector) -> dict:
    LOG.info("OT profile: PASSIVE ONLY. No packets will be sent to any target.")
    pc = PassiveCollector(scope, listen_seconds=args.listen_seconds)
    await pc.run(collector)
    hosts = sorted({r.target for r in collector.results}, key=_ip_key)
    rollup = {h: {"alive": True, "source": "passive", "ports": {}, "hints": []}
              for h in hosts}
    for r in collector.results:
        rollup[r.target]["hints"] = r.data.get("device_hints", [])
        rollup[r.target]["announced_via"] = r.data.get("announced_via", [])
    return rollup


# --------------------------------------------------------------------------- #
# Rollup + clean rendering.
# --------------------------------------------------------------------------- #
def _ip_key(ip: str):
    try:
        import ipaddress
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def _clean(s: str | None, maxlen: int = 48) -> str:
    """
    Make a raw banner safe and readable for the summary line.

    Many services answer with binary (a MySQL handshake, a TLS record, an RDP
    PDU). service_banner records those bytes verbatim — correct for the audit
    trail, but ugly in a one-line summary. This collapses non-printable runs to
    a single space and trims, so "E\\x00\\x00\\xffjHost '…' is not allowed"
    becomes the genuinely useful "E jHost '…' is not allowed", while a purely
    binary blob collapses to empty (the caller then renders just "open").
    """
    if not s:
        return ""
    out, prev_space = [], False
    for ch in s:
        if 32 <= ord(ch) < 127:
            out.append(ch)
            prev_space = False
        elif not prev_space:
            out.append(" ")
            prev_space = True
    return "".join(out).strip()[:maxlen]


def _rollup(live, open_map, svc_results, deep_results) -> dict:
    rollup: dict[str, dict] = {
        h: {"alive": True, "source": "active", "ports": {}} for h in live}
    for host, hports in open_map.items():
        for p in hports:
            rollup[host]["ports"][p] = {"status": "open", "service": None,
                                        "detail": None}
    for r in svc_results:
        if r.target in rollup and r.port in rollup[r.target]["ports"]:
            cleaned = _clean((r.data or {}).get("first_line"))
            # cleaned == "" means the port answered with pure binary (or didn't
            # answer the banner probe) — leave service None so it renders as a
            # plain "open" rather than a line of mojibake.
            rollup[r.target]["ports"][r.port]["service"] = cleaned or None
    # Deep identification is authoritative — it overrides the raw banner string
    # (a binary handshake's first byte is noise; "mysql/mariadb 9.6.0" is signal).
    # Apply TLS last so that on a port that is BOTH a web and a TLS port (e.g.
    # 8443) the more security-relevant "https/tls + versions" label wins
    # deterministically, instead of depending on gather() completion order.
    _deep_order = {"web_scan": 0, "smb_scan": 1, "db_scan": 2, "tls_scan": 3}
    for r in sorted(deep_results, key=lambda x: _deep_order.get(x.scanner, 0)):
        if r.target not in rollup or r.port not in rollup[r.target]["ports"]:
            continue
        slot = rollup[r.target]["ports"][r.port]
        d = r.data or {}
        if r.scanner == "tls_scan" and d.get("accepted_versions"):
            slot["service"] = "https/tls"
            slot["detail"] = ", ".join(d["accepted_versions"])
        elif r.scanner == "web_scan":
            slot["service"] = "http"
            slot["detail"] = f"HTTP {d.get('status')} {d.get('server') or ''}".strip()
        elif r.scanner == "db_scan" and d.get("engine"):
            slot["service"] = d["engine"]
            slot["detail"] = d.get("server_version") or ""
        elif r.scanner == "smb_scan":
            slot["service"] = "smb"
            slot["detail"] = (f"SMBv1={'on' if d.get('smbv1_enabled') else 'off'} "
                              f"SMB2={'on' if d.get('smb2_supported') else 'off'}")
    return rollup


def _render_summary(profile_name: str, rollup: dict, scanned: int) -> None:
    line = "=" * 64
    print(line)
    print(f"  SCAN SUMMARY   profile={profile_name}   "
          f"{PROFILES[profile_name]['blurb']}")
    print(line)
    if not rollup:
        print("  no live / observed hosts in scope")
        print(line)
        return

    total_ports = 0
    for host in sorted(rollup, key=_ip_key):
        rec = rollup[host]
        if rec.get("source") == "passive":
            via = ", ".join(rec.get("announced_via", [])) or "passive"
            hints = "; ".join(rec.get("hints", []))
            print(f"\n  {host:<18} observed via {via}")
            if hints:
                print(f"      hint: {hints[:90]}")
            continue
        ports = rec.get("ports", {})
        total_ports += len(ports)
        print(f"\n  {host:<18} {len(ports)} open port(s)")
        for p in sorted(ports):
            info = ports[p]
            svc = info.get("service") or ""
            detail = info.get("detail") or ""
            tail = f"  {detail}" if detail else ""
            print(f"      {str(p) + '/tcp':<10} open   {svc[:40]}{tail}"[:110])

    print(f"\n{line}")
    if any(r.get("source") == "passive" for r in rollup.values()):
        print(f"  {len(rollup)} host(s) observed (passive, 0 packets sent)")
    else:
        print(f"  {len(rollup)} live host(s), {total_ports} open port(s) "
              f"— scanned {scanned} target(s)")
    print(line)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Staged, profile-aware scan pipeline (collection only)")
    p.add_argument("-t", "--targets", nargs="+", required=True,
                   help="targets: CIDR, IP, hostname, or range a-b")
    p.add_argument("-s", "--scope", required=True,
                   help="authorization allowlist file (REQUIRED)")
    p.add_argument("--profile", required=True, choices=list(PROFILES.keys()),
                   help="it (active full) | iot (active gentle) | ot (passive only)")
    p.add_argument("--scanners", nargs="*", default=None,
                   help="(active profiles) restrict deep stage, e.g. tls web")
    p.add_argument("--listen-seconds", type=float, default=60.0,
                   help="(ot profile) passive listen window (default 60s)")
    p.add_argument("--disc-timeout", type=float, default=None,
                   help="(active) per-probe timeout for the discovery stage; "
                        "overrides the profile default (it=1.5s, iot=2.0s). "
                        "Raise for slow/remote targets.")
    p.add_argument("-o", "--output", help="write full raw JSONL to this file")
    p.add_argument("--raw", action="store_true",
                   help="also stream raw JSONL to stdout (default: summary only)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    setup_logging(args.verbose)

    profile = PROFILES[args.profile]

    # HARD GATE: in the ot profile, active scanning is structurally unreachable.
    if args.profile == "ot" and args.scanners:
        LOG.error("ot profile is PASSIVE ONLY — it cannot run active scanners "
                  "(%s). An unsolicited probe can disrupt an ICS device. Use "
                  "--profile it/iot for active scanning of a non-OT segment.",
                  ", ".join(args.scanners))
        sys.exit(2)
    if args.scanners and profile["mode"] == "active":
        profile = dict(profile)
        profile["deep"] = [s for s in args.scanners if s in ("tls", "web", "smb", "db")]

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        raw_writer = None
        if args.output or args.raw:
            raw_writer = ResultWriter(args.output, also_stdout=args.raw)
        collector = _Collector(raw_writer)
        try:
            if profile["mode"] == "passive":
                rollup = await _run_passive(args, scope, collector)
                scanned = 0
            else:
                targets = expand_targets(args.targets)
                rollup = await _run_active(args, profile, scope, targets, collector)
                scanned = len(targets)
        finally:
            if raw_writer:
                raw_writer.close()
        _render_summary(args.profile, rollup, scanned)

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
