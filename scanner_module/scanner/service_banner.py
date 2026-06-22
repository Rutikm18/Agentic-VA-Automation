"""
service_banner.py — grab service banners and light version strings.

METHOD (collection only): connect to a port and read whatever the service
voluntarily announces. For services that speak first (SSH, SMTP, FTP) we just
read. For services that wait (HTTP) we send a minimal, benign request and read
the response head. We RECORD the banner verbatim as evidence — we do NOT map it
to a CVE or decide a version is vulnerable. That is the (separate) detection
layer's job.

This keeps the module's output purely factual so its accuracy is measurable:
"port 22 returned banner X".
"""

from __future__ import annotations

import argparse
import asyncio

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint,
)

# Probe sent to a port if the service does not greet us first.
# Keep these minimal and non-intrusive — a bare request, nothing exploit-like.
_HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: va-scanner\r\n\r\n"
_GENERIC_PROBE = b"\r\n"

# Ports where the client must speak first.
_CLIENT_FIRST = {80, 8080, 8000, 8888, 443, 8443}


class ServiceBannerScanner(BaseScanner):
    name = "service_banner"

    def __init__(self, *args, ports: list[int], read_bytes: int = 512, **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports
        self.read_bytes = read_bytes

    async def _grab(self, target: str, port: int) -> ScanResult | None:
        await self.limiter.wait()
        async with self.sem:
            try:
                fut = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None   # not open; nothing to grab

            banner = b""
            try:
                # First, give a "speak-first" service a moment to greet us.
                if port not in _CLIENT_FIRST:
                    try:
                        banner = await asyncio.wait_for(
                            reader.read(self.read_bytes), timeout=1.5)
                    except asyncio.TimeoutError:
                        banner = b""
                # If nothing yet, send a minimal probe and read the reply.
                if not banner:
                    probe = (_HTTP_PROBE % target.encode()
                             if port in _CLIENT_FIRST or port in (80, 8080, 8000, 8888)
                             else _GENERIC_PROBE)
                    try:
                        writer.write(probe)
                        await writer.drain()
                        banner = await asyncio.wait_for(
                            reader.read(self.read_bytes), timeout=self.timeout)
                    except (asyncio.TimeoutError, OSError):
                        banner = banner or b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        if not banner:
            return ScanResult(self.name, target, port=port, proto="tcp",
                              status="open",
                              data={"banner": None},
                              evidence="open, no banner returned")

        text = banner.decode("latin-1", errors="replace").strip()
        first_line = text.splitlines()[0] if text.splitlines() else ""
        return ScanResult(
            self.name, target, port=port, proto="tcp", status="open",
            data={
                "banner": text[:1000],
                "first_line": first_line[:300],
                "byte_len": len(banner),
            },
            evidence=first_line[:300] or text[:300],
        )

    async def scan_target(self, target: str) -> list[ScanResult]:
        tasks = [self._grab(target, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


def main() -> None:
    parser = base_argparser("Service banner / version-string grabber")
    parser.add_argument("-p", "--ports", required=True,
                        help="ports to grab, e.g. '22,80,443,3306'")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        ports = parse_ports(args.ports)
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = ServiceBannerScanner(scope, rate=args.rate,
                                       concurrency=args.concurrency,
                                       timeout=args.timeout, ports=ports)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
