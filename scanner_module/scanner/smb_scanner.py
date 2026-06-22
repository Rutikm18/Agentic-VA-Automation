"""
smb_scanner.py — detect which SMB dialects a host supports.

METHOD (collection only): we perform SMB protocol NEGOTIATION, nothing more.
  * Send an SMBv1 SMB_COM_NEGOTIATE listing the legacy "NT LM 0.12" dialect.
    A valid SMBv1 negotiate response = SMBv1 is ENABLED on this host (a fact
    worth recording; legacy SMBv1 is widely deprecated).
  * Send an SMB2 NEGOTIATE. A response = SMB2/3 supported.
We only read the negotiate response. We do NOT authenticate, do NOT access
shares, do NOT exploit anything (no MS17-010 trigger). This is pure capability
detection — equivalent to nmap's smb-protocols, hand-rolled so output is yours.

NOTE: raw SMB framing is fiddly; for production-grade reliability you may prefer
nmap_wrapper.py (smb-protocols NSE). This module is intentionally minimal and
clearly scoped so you can measure its accuracy against nmap.
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


def _netbios_session(payload: bytes) -> bytes:
    # Direct-hosted SMB over TCP/445 uses a 4-byte length prefix (NBT session).
    return struct.pack(">I", len(payload)) + payload


def _smb1_negotiate() -> bytes:
    # SMBv1 header: 0xFF 'SMB' + command 0x72 (NEGOTIATE) + zeroed fields.
    header = b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18\x53\xc8" + \
             b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2 + b"\x00" * 2 + \
             b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 2
    # Dialect list (each: 0x02 + ascii name + null). Include legacy NT LM 0.12.
    dialects = b"".join(
        b"\x02" + d + b"\x00" for d in (
            b"PC NETWORK PROGRAM 1.0",
            b"LANMAN1.0",
            b"Windows for Workgroups 3.1a",
            b"LM1.2X002",
            b"LANMAN2.1",
            b"NT LM 0.12",
        )
    )
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects  # wordcount, bytecount
    return header + body


def _smb2_negotiate() -> bytes:
    # SMB2 header (64 bytes) with NEGOTIATE command (0x0000).
    proto = b"\xfeSMB"
    structure_size = struct.pack("<H", 64)
    header = (proto + structure_size + b"\x00" * 2 +    # credit charge
              b"\x00" * 4 +                              # status
              struct.pack("<H", 0x0000) +               # command NEGOTIATE
              b"\x00" * 2 +                              # credit request
              b"\x00" * 4 +                              # flags
              b"\x00" * 4 +                              # next command
              b"\x00" * 8 +                              # message id
              b"\x00" * 4 +                              # reserved
              b"\x00" * 4 +                              # tree id
              b"\x00" * 8 +                              # session id
              b"\x00" * 16)                              # signature
    # NEGOTIATE request body advertising SMB2/3 dialects.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    body = (struct.pack("<H", 36) +                      # structure size
            struct.pack("<H", len(dialects)) +           # dialect count
            struct.pack("<H", 0x0001) +                  # security mode (signing enabled)
            b"\x00" * 2 +                                # reserved
            b"\x00" * 4 +                                # capabilities
            b"\x00" * 16 +                               # client guid
            b"\x00" * 8 +                                # negotiate context off/count
            b"".join(struct.pack("<H", d) for d in dialects))
    return header + body


class SMBScanner(BaseScanner):
    name = "smb_scan"

    def __init__(self, *args, port: int = 445, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = port

    def _negotiate(self, target: str, payload: bytes) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, self.port))
            sock.sendall(_netbios_session(payload))
            resp = sock.recv(1024)
            return resp
        except OSError:
            return None
        finally:
            sock.close()

    async def scan_target(self, target: str) -> list[ScanResult]:
        await self.limiter.wait()
        loop = asyncio.get_running_loop()

        async with self.sem:
            smb1 = await loop.run_in_executor(
                None, self._negotiate, target, _smb1_negotiate())
            smb2 = await loop.run_in_executor(
                None, self._negotiate, target, _smb2_negotiate())

        smb1_enabled = bool(smb1 and len(smb1) > 8 and smb1[4:8] == b"\xffSMB")
        smb2_supported = bool(smb2 and len(smb2) > 8 and smb2[4:8] == b"\xfeSMB")

        if not smb1 and not smb2:
            return [ScanResult(self.name, target, port=self.port, proto="tcp",
                               status="filtered",
                               evidence="no SMB response on 445")]

        return [ScanResult(
            self.name, target, port=self.port, proto="tcp", status="open",
            data={
                "smbv1_enabled": smb1_enabled,
                "smb2_supported": smb2_supported,
            },
            evidence=(f"SMBv1={'on' if smb1_enabled else 'off'}, "
                      f"SMB2={'on' if smb2_supported else 'off'}"),
        )]


def main() -> None:
    parser = base_argparser("SMB dialect detection (SMBv1/SMB2 negotiate)")
    parser.add_argument("--port", type=int, default=445)
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = SMBScanner(scope, rate=args.rate, concurrency=args.concurrency,
                             timeout=args.timeout, port=args.port)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
