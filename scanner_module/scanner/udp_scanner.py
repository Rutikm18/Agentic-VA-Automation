"""
udp_scanner.py — detect common UDP services via protocol-specific probes.

METHOD (collection only): UDP has no handshake, so a bare empty datagram is
ambiguous. Instead we send a small, valid, READ-ONLY protocol request for each
well-known service and look for a positive reply:
    DNS    -> a status query
    NTP    -> a mode-3 client request
    SNMP   -> a v1 GET of sysDescr (community 'public')
    NetBIOS-> a node status request
A reply = service is open and speaking. No reply = open|filtered (ambiguous).

All probes are standard read requests. Nothing is modified on the target.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import struct

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    setup_logging, base_argparser, main_entrypoint,
)


def _dns_probe() -> bytes:
    # Standard query for 'version.bind' CHAOS TXT is noisy; use a simple A query
    # for a root-ish name. Transaction id + flags + 1 question.
    tid = b"\x13\x37"
    header = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    # QNAME: "www" "example" "com"
    qname = b"\x03www\x07example\x03com\x00"
    question = qname + b"\x00\x01" + b"\x00\x01"  # type A, class IN
    return header + question


def _ntp_probe() -> bytes:
    # NTP v3, mode 3 (client). 48-byte packet, first byte 0x1B.
    return b"\x1b" + b"\x00" * 47


def _snmp_probe(community: bytes = b"public") -> bytes:
    # Minimal SNMPv1 GET-request for sysDescr.0 (1.3.6.1.2.1.1.1.0).
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # 1.3.6.1.2.1.1.1.0 BER
    varbind = b"\x30" + bytes([len(oid) + 4]) + \
              b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
    request_id = b"\x02\x01\x01"     # integer 1
    err_status = b"\x02\x01\x00"
    err_index = b"\x02\x01\x00"
    pdu_body = request_id + err_status + err_index + varbind_list
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body   # GET-request PDU
    version = b"\x02\x01\x00"        # SNMPv1
    comm = b"\x04" + bytes([len(community)]) + community
    msg_body = version + comm + pdu
    return b"\x30" + bytes([len(msg_body)]) + msg_body


def _netbios_probe() -> bytes:
    # NBSTAT node status request for wildcard name '*'.
    tid = b"\x80\x00"
    flags = b"\x00\x10"
    counts = b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    encoded = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    question = encoded + b"\x00\x21" + b"\x00\x01"
    return tid + flags + counts + question


UDP_PROBES: dict[int, tuple[str, bytes]] = {
    53: ("dns", _dns_probe()),
    123: ("ntp", _ntp_probe()),
    161: ("snmp", _snmp_probe()),
    137: ("netbios-ns", _netbios_probe()),
}


class UDPScanner(BaseScanner):
    name = "udp_scan"

    def __init__(self, *args, ports: list[int] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports or list(UDP_PROBES.keys())

    async def _probe(self, target: str, port: int) -> ScanResult | None:
        if port not in UDP_PROBES:
            return None
        svc, payload = UDP_PROBES[port]
        await self.limiter.wait()
        loop = asyncio.get_running_loop()
        async with self.sem:
            try:
                data = await loop.run_in_executor(
                    None, self._send_recv, target, port, payload)
            except Exception as exc:
                return ScanResult(self.name, target, port=port, proto="udp",
                                  status="error", error=str(exc))
        if data is None:
            # No reply: ambiguous. Report as open|filtered with no positive proof.
            return ScanResult(self.name, target, port=port, proto="udp",
                              status="filtered",
                              data={"service_guess": svc, "responded": False},
                              evidence="no reply (open|filtered)")
        return ScanResult(
            self.name, target, port=port, proto="udp", status="open",
            data={"service": svc, "responded": True,
                  "reply_bytes": len(data),
                  "reply_hex_head": data[:48].hex()},
            evidence=f"{svc} replied with {len(data)} bytes",
        )

    def _send_recv(self, target: str, port: int, payload: bytes) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (target, port))
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except OSError:
            return None
        finally:
            sock.close()

    async def scan_target(self, target: str) -> list[ScanResult]:
        tasks = [self._probe(target, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        # Only emit positive (open) results by default to keep noise down;
        # filtered/ambiguous are still returned for completeness.
        return [r for r in results if r is not None]


def main() -> None:
    parser = base_argparser("UDP service scanner (DNS/NTP/SNMP/NetBIOS)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = UDPScanner(scope, rate=args.rate, concurrency=args.concurrency,
                             timeout=args.timeout)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
