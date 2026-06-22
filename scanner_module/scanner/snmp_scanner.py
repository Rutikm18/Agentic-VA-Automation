"""
snmp_scanner.py — detect SNMP and read sysDescr via common community strings.

METHOD (collection only): send a standard SNMPv1 GET-request for sysDescr.0
using a small list of common READ community strings ('public', 'private', ...).
A reply means SNMP is reachable with that community — we record sysDescr (a
device description string) as evidence.

This is read-only enumeration (a GET, never a SET). It does not modify device
configuration. Reading device info with a default community is standard VA
behaviour; recording "responds to community 'public'" is a fact for the
detection layer to act on, not an exploit performed here.
"""

from __future__ import annotations

import argparse
import asyncio
import socket

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    setup_logging, base_argparser, main_entrypoint,
)

COMMON_COMMUNITIES = ["public", "private", "community", "manager", "snmp"]
_SYSDESCR_OID = b"\x2b\x06\x01\x02\x01\x01\x01\x00"   # 1.3.6.1.2.1.1.1.0


def _build_get(community: str) -> bytes:
    comm = community.encode()
    varbind = (b"\x30" + bytes([len(_SYSDESCR_OID) + 4]) +
               b"\x06" + bytes([len(_SYSDESCR_OID)]) + _SYSDESCR_OID +
               b"\x05\x00")
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
    pdu_body = b"\x02\x01\x01" + b"\x02\x01\x00" + b"\x02\x01\x00" + varbind_list
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    msg_body = (b"\x02\x01\x00" +                                 # version v1
                b"\x04" + bytes([len(comm)]) + comm +             # community
                pdu)
    return b"\x30" + bytes([len(msg_body)]) + msg_body


def _extract_sysdescr(resp: bytes) -> str | None:
    # Very small BER walk: find the last OCTET STRING (0x04) in the response,
    # which for a sysDescr GET-response is the description value.
    try:
        i = 0
        last = None
        while i < len(resp):
            tag = resp[i]
            ln = resp[i + 1]
            # Handle long-form length (rare for these small packets).
            if ln & 0x80:
                nbytes = ln & 0x7F
                ln = int.from_bytes(resp[i + 2:i + 2 + nbytes], "big")
                val_start = i + 2 + nbytes
            else:
                val_start = i + 2
            if tag == 0x04:  # OCTET STRING
                last = resp[val_start:val_start + ln]
            # Descend into constructed types (SEQUENCE 0x30, context 0xa2 etc.)
            if tag in (0x30, 0xa0, 0xa1, 0xa2, 0xa3):
                i = val_start
            else:
                i = val_start + ln
        if last:
            return last.decode("latin-1", "replace")
    except Exception:
        return None
    return None


class SNMPScanner(BaseScanner):
    name = "snmp_scan"

    def __init__(self, *args, port: int = 161,
                 communities: list[str] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = port
        self.communities = communities or COMMON_COMMUNITIES

    def _query(self, target: str, community: str) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(_build_get(community), (target, self.port))
            data, _ = sock.recvfrom(4096)
            return data
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    async def scan_target(self, target: str) -> list[ScanResult]:
        loop = asyncio.get_running_loop()
        for community in self.communities:
            await self.limiter.wait()
            async with self.sem:
                resp = await loop.run_in_executor(
                    None, self._query, target, community)
            if resp:
                sysdescr = _extract_sysdescr(resp)
                return [ScanResult(
                    self.name, target, port=self.port, proto="udp",
                    status="open",
                    data={"community": community,
                          "sysdescr": sysdescr,
                          "responded": True},
                    evidence=(f"community '{community}' -> "
                              f"{(sysdescr or '')[:160]}"),
                )]
        return [ScanResult(
            self.name, target, port=self.port, proto="udp", status="filtered",
            data={"responded": False},
            evidence="no SNMP reply to common communities (open|filtered)")]


def main() -> None:
    parser = base_argparser("SNMP enumeration scanner (read-only)")
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--communities", default=None,
                        help="comma-separated community strings")
    args = parser.parse_args()
    setup_logging(args.verbose)
    communities = (args.communities.split(",") if args.communities
                   else COMMON_COMMUNITIES)

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = SNMPScanner(scope, rate=args.rate, concurrency=args.concurrency,
                              timeout=args.timeout, port=args.port,
                              communities=communities)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
