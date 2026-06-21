"""
host_discovery.py — determine which hosts are alive.

METHOD (collection only): for each target we attempt lightweight TCP connects
to a small set of very common ports. ANY response (open OR connection-refused)
proves the host exists, because a refused connection means a host answered with
a RST. Silence on every port = treated as down/filtered.

This is a userland (unprivileged) approach — it does not send raw ICMP. For
ICMP/ARP-based discovery use nmap_wrapper.py, which is more thorough on a LAN.

No exploitation, no payloads — just "is something there".
"""

from __future__ import annotations

import asyncio

from .scanner_base import (
    BaseScanner, ScanResult, base_argparser, run_cli, setup_logging,
    main_entrypoint,
)

# Ports chosen because almost every live host answers on at least one of these
# (web, windows, ssh, dns). A RST counts as alive just as much as a SYN/ACK.
PROBE_PORTS = [80, 443, 445, 22, 3389, 53, 135, 139]


class HostDiscoveryScanner(BaseScanner):
    name = "host_discovery"

    async def _probe(self, target: str, port: int) -> str | None:
        """Return 'open', 'refused', or None (no response)."""
        await self.limiter.wait()
        try:
            fut = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return "open"
        except ConnectionRefusedError:
            return "refused"        # host is alive, port just closed
        except (asyncio.TimeoutError, OSError):
            return None

    async def scan_target(self, target: str) -> list[ScanResult]:
        evidence_ports: list[tuple[int, str]] = []
        # Probe ports concurrently; first proof of life is enough but we collect
        # all responders for richer evidence.
        results = await asyncio.gather(
            *(self._probe(target, p) for p in PROBE_PORTS)
        )
        for port, state in zip(PROBE_PORTS, results):
            if state in ("open", "refused"):
                evidence_ports.append((port, state))

        alive = len(evidence_ports) > 0
        return [ScanResult(
            scanner=self.name,
            target=target,
            status="open" if alive else "filtered",
            data={
                "alive": alive,
                "responding_ports": [
                    {"port": p, "state": s} for p, s in evidence_ports
                ],
            },
            evidence=(
                "responded on: " +
                ", ".join(f"{p}/{s}" for p, s in evidence_ports)
                if alive else "no response on any probe port"
            ),
        )]


def main() -> None:
    parser = base_argparser("Host discovery (liveness) scanner")
    args = parser.parse_args()
    setup_logging(args.verbose)
    main_entrypoint(lambda: run_cli(HostDiscoveryScanner, args))


if __name__ == "__main__":
    main()
