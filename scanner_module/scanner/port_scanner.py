"""
port_scanner.py — TCP connect scan.

METHOD (collection only): a full TCP connect() per port via the OS stack
(unprivileged). Interpretation is the classic three-state model:
    connection succeeds      -> OPEN     (got SYN/ACK)
    connection refused       -> CLOSED   (got RST)
    timeout / no response    -> FILTERED (dropped by a firewall)

No raw packets, no SYN/stealth (that needs root). For SYN scanning at scale use
nmap_wrapper.py. This module is deliberately simple and deterministic so its
false-positive / accuracy rate is easy to measure on its own.
"""

from __future__ import annotations

import argparse
import asyncio

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, TOP_TCP_PORTS, setup_logging, run_cli, base_argparser,
    main_entrypoint,
)


class PortScanner(BaseScanner):
    name = "port_scan"

    def __init__(self, *args, ports: list[int] | None = None,
                 report_closed: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports or TOP_TCP_PORTS
        self.report_closed = report_closed   # off by default: only emit OPEN

    async def _scan_port(self, target: str, port: int) -> ScanResult | None:
        await self.limiter.wait()
        try:
            fut = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ScanResult(self.name, target, port=port, proto="tcp",
                              status="open", evidence="tcp connect succeeded")
        except ConnectionRefusedError:
            if self.report_closed:
                return ScanResult(self.name, target, port=port, proto="tcp",
                                  status="closed", evidence="connection refused (RST)")
            return None
        except asyncio.TimeoutError:
            if self.report_closed:
                return ScanResult(self.name, target, port=port, proto="tcp",
                                  status="filtered", evidence="no response (timeout)")
            return None
        except OSError as exc:
            if self.report_closed:
                return ScanResult(self.name, target, port=port, proto="tcp",
                                  status="filtered", error=str(exc))
            return None

    async def scan_target(self, target: str) -> list[ScanResult]:
        tasks = [self._scan_port(target, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


def main() -> None:
    parser = base_argparser("TCP connect port scanner")
    parser.add_argument("-p", "--ports", default=None,
                        help="ports e.g. '22,80,443,8000-8100' (default: top ports)")
    parser.add_argument("--report-closed", action="store_true",
                        help="also emit closed/filtered results (noisier)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        ports = parse_ports(args.ports) if args.ports else None
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = PortScanner(scope, rate=args.rate, concurrency=args.concurrency,
                              timeout=args.timeout, ports=ports,
                              report_closed=args.report_closed)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
