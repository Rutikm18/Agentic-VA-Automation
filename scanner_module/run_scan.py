#!/usr/bin/env python3
"""
run_scan.py — orchestrator that runs any subset of scanners in one pass.

It does NOT correlate or score — it just runs the selected pure-collection
scanners against the in-scope targets and writes all results to one JSONL file
(plus per-scanner files if you want to measure FP rate separately).

Examples
--------
  # everything pure-Python, top ports:
  python run_scan.py -t 10.0.0.0/24 -s scope.txt --all -o results.jsonl

  # just discovery + ports + banners:
  python run_scan.py -t 10.0.0.0/24 -s scope.txt \
       --scanners host_discovery port_scan service_banner -o out.jsonl

  # per-scanner output files for accuracy/FP measurement:
  python run_scan.py -t 10.0.0.0/24 -s scope.txt --all --split-output ./runs/
"""

from __future__ import annotations

import argparse
import os

from scanner.scanner_base import (
    ScopeGuard, ResultWriter, expand_targets, setup_logging, LOG,
    TOP_TCP_PORTS, main_entrypoint,
)
from scanner.host_discovery import HostDiscoveryScanner
from scanner.port_scanner import PortScanner
from scanner.service_banner import ServiceBannerScanner
from scanner.tls_scanner import TLSScanner, DEFAULT_TLS_PORTS
from scanner.udp_scanner import UDPScanner
from scanner.smb_scanner import SMBScanner
from scanner.snmp_scanner import SNMPScanner
from scanner.web_scanner import WebScanner, DEFAULT_WEB_PORTS
from scanner.mcp_ai_scanner import MCPAIScanner, DEFAULT_AI_PORTS
from scanner.db_scanner import DBScanner, DEFAULT_DB_PORTS
from scanner.mass_scan import run_mass_scan
# NOTE: credentialed collectors (ssh_collector, windows_collector) are run
# separately via their own CLIs, because they require credentials and a
# different invocation model than the unauthenticated network scanners above.

# Registry: name -> factory(scope, common_kwargs) -> scanner instance.
SCANNERS = {
    "host_discovery": lambda scope, k: HostDiscoveryScanner(scope, **k),
    "port_scan":      lambda scope, k: PortScanner(scope, ports=TOP_TCP_PORTS, **k),
    "service_banner": lambda scope, k: ServiceBannerScanner(
                          scope, ports=TOP_TCP_PORTS, **k),
    "tls_scan":       lambda scope, k: TLSScanner(scope, ports=DEFAULT_TLS_PORTS, **k),
    "udp_scan":       lambda scope, k: UDPScanner(scope, **k),
    "smb_scan":       lambda scope, k: SMBScanner(scope, **k),
    "snmp_scan":      lambda scope, k: SNMPScanner(scope, **k),
    "web_scan":       lambda scope, k: WebScanner(scope, ports=DEFAULT_WEB_PORTS, **k),
    "mcp_ai_scan":    lambda scope, k: MCPAIScanner(scope, ports=DEFAULT_AI_PORTS, **k),
    "db_scan":        lambda scope, k: DBScanner(scope, port_map=DEFAULT_DB_PORTS, **k),
}


async def _orchestrate(args):
    targets = expand_targets(args.targets)
    scope = ScopeGuard.from_file(args.scope)
    common = dict(rate=args.rate, concurrency=args.concurrency, timeout=args.timeout)

    chosen = (list(SCANNERS.keys()) if args.all
              else [s for s in args.scanners if s in SCANNERS])
    if not chosen:
        LOG.error("no valid scanners selected. Available: %s",
                  ", ".join(SCANNERS))
        return

    if args.split_output:
        os.makedirs(args.split_output, exist_ok=True)

    combined = ResultWriter(args.output, also_stdout=not args.quiet) \
        if args.output else None

    # mass_scan runs separately because it consumes raw specs (CIDRs/ranges),
    # not pre-expanded host lists — that's the whole point of its speed.
    if args.mass_scan:
        LOG.info("=== running mass_scan (fast sweep) ===")
        mwriter = combined
        per_m = None
        if args.split_output:
            per_m = ResultWriter(
                os.path.join(args.split_output, "mass_scan.jsonl"),
                also_stdout=False)

        class _MassFan:
            def write(self, r):
                if combined:
                    combined.write(r)
                if per_m:
                    per_m.write(r)
                if not combined and not per_m:
                    print(r.to_json())
        await run_mass_scan(
            list(args.targets), scope, ports=args.mass_ports,
            rate=args.mass_rate, concurrency=args.concurrency,
            per_op_timeout=args.timeout, force_fallback=args.mass_fallback,
            writer=_MassFan())
        if per_m:
            per_m.close()

    for name in chosen:
        per_writer = None
        if args.split_output:
            per_writer = ResultWriter(
                os.path.join(args.split_output, f"{name}.jsonl"),
                also_stdout=False)
        scanner = SCANNERS[name](scope, common)
        LOG.info("=== running %s ===", name)

        # Wrap writer to fan out to both combined + per-scanner files.
        class _Fan:
            def write(self, r):
                if combined:
                    combined.write(r)
                if per_writer:
                    per_writer.write(r)
                if not combined and not per_writer:
                    print(r.to_json())
        await scanner.run(targets, _Fan())
        if per_writer:
            per_writer.close()
            LOG.info("wrote %s/%s.jsonl", args.split_output, name)

    if combined:
        combined.close()
        LOG.info("combined results -> %s (%d rows)", args.output, combined.count)


def main():
    p = argparse.ArgumentParser(description="VA scanner orchestrator (collection only)")
    p.add_argument("-t", "--targets", nargs="+", required=True)
    p.add_argument("-s", "--scope", required=True,
                   help="authorization allowlist file (REQUIRED)")
    p.add_argument("--scanners", nargs="*", default=[],
                   help=f"subset to run: {', '.join(SCANNERS)}")
    p.add_argument("--all", action="store_true", help="run all scanners")
    p.add_argument("--mass-scan", action="store_true",
                   help="run a fast mass port sweep (masscan) before/with others")
    p.add_argument("--mass-ports", default="1-1000",
                   help="ports for mass_scan (default 1-1000)")
    p.add_argument("--mass-rate", type=int, default=10000,
                   help="masscan packets/sec (default 10000)")
    p.add_argument("--mass-fallback", action="store_true",
                   help="force mass_scan pure-Python fallback (no masscan)")
    p.add_argument("-o", "--output", help="combined JSONL output file")
    p.add_argument("--split-output", help="dir for per-scanner JSONL files (FP testing)")
    p.add_argument("--rate", type=float, default=200.0)
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    setup_logging(args.verbose)

    main_entrypoint(lambda: _orchestrate(args))


if __name__ == "__main__":
    main()
