"""
tls_scanner.py — collect TLS/SSL configuration facts.

METHOD (collection only): for each TLS port we attempt handshakes and record:
  * which protocol versions the server agrees to (TLS 1.0/1.1/1.2/1.3)
  * the negotiated cipher
  * certificate subject / issuer / validity / SANs
We only OBSERVE and RECORD. We do not judge "weak" or "vulnerable" here — the
detection layer decides that from these facts. Reporting raw facts keeps FP
measurement clean (e.g. "server accepted TLSv1.0" is a verifiable fact).

Pure standard library (ssl + socket); runs in a thread executor so it fits the
async base without blocking the loop.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import ssl
import warnings
from datetime import datetime

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint,
)

# Protocol versions we probe individually to learn what the server accepts.
_PROTOCOLS = [
    ("TLSv1_3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ("TLSv1_2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1_1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1_0", ssl.TLSVersion.TLSv1),
]

DEFAULT_TLS_PORTS = [443, 8443, 993, 995, 465, 636, 989, 990, 5986]


def _try_version(host: str, port: int, version, timeout: float):
    """Attempt a handshake forcing one protocol version. Returns cipher or None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Pinning to TLSv1.0/1.1 deliberately, to find out whether the server
        # still accepts them — silence the stdlib's DeprecationWarning about
        # using those names, it would otherwise spam stderr on every probe.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError):
        return None  # this Python/OpenSSL build can't pin that version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "cipher": ssock.cipher(),
                    "version": ssock.version(),
                }
    except Exception:
        return None


def _get_cert(host: str, port: int, timeout: float):
    """Fetch the peer certificate (best-effort, no validation)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                try:
                    cert = ssock.getpeercert()  # parsed dict (may be empty w/o verify)
                except Exception:
                    cert = {}
                return cert, len(der) if der else 0
    except Exception:
        return None, 0


def _scan_tls_sync(host: str, port: int, timeout: float) -> dict | None:
    accepted: list[str] = []
    cipher_by_ver: dict[str, str] = {}
    for label, ver in _PROTOCOLS:
        if ver is None:
            continue
        res = _try_version(host, port, ver, timeout)
        if res:
            accepted.append(label)
            c = res["cipher"]
            cipher_by_ver[res["version"] or label] = c[0] if c else None
    if not accepted:
        return None  # not a TLS service / unreachable

    cert, der_len = _get_cert(host, port, timeout)
    cert_info = {}
    if cert:
        cert_info = {
            "subject": _flatten_name(cert.get("subject")),
            "issuer": _flatten_name(cert.get("issuer")),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
            "expired": _is_expired(cert.get("notAfter")),
        }
    return {
        "accepted_versions": accepted,
        "cipher_by_version": cipher_by_ver,
        "certificate": cert_info or {"raw_der_bytes": der_len},
    }


def _flatten_name(rdn_seq) -> dict:
    out = {}
    if not rdn_seq:
        return out
    for rdn in rdn_seq:
        for k, v in rdn:
            out[k] = v
    return out


def _is_expired(not_after: str | None) -> bool | None:
    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return exp < datetime.utcnow()
    except Exception:
        return None


class TLSScanner(BaseScanner):
    name = "tls_scan"

    def __init__(self, *args, ports: list[int], **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports

    async def _scan_port(self, target: str, port: int) -> ScanResult | None:
        await self.limiter.wait()
        loop = asyncio.get_running_loop()
        async with self.sem:
            try:
                info = await loop.run_in_executor(
                    None, _scan_tls_sync, target, port, self.timeout)
            except Exception as exc:
                return ScanResult(self.name, target, port=port, proto="tcp",
                                  status="error", error=str(exc))
        if not info:
            return None
        return ScanResult(
            self.name, target, port=port, proto="tcp", status="open",
            data=info,
            evidence="accepts: " + ", ".join(info["accepted_versions"]),
        )

    async def scan_target(self, target: str) -> list[ScanResult]:
        tasks = [self._scan_port(target, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


def main() -> None:
    parser = base_argparser("TLS/SSL configuration scanner")
    parser.add_argument("-p", "--ports", default=None,
                        help="TLS ports (default: common TLS ports)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        ports = parse_ports(args.ports) if args.ports else DEFAULT_TLS_PORTS
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = TLSScanner(scope, rate=args.rate, concurrency=args.concurrency,
                             timeout=args.timeout, ports=ports)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
