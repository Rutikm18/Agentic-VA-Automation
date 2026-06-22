"""
db_scanner.py — fingerprint database services.

WHY: databases are everywhere on internal networks and frequently exposed. A
plain banner grab does NOT identify most of them, because they speak BINARY
protocols, not text banners. This module sends each DB's minimal, valid,
READ-ONLY handshake/ping and identifies the service (and version where the
protocol volunteers it).

Covered: MySQL/MariaDB, PostgreSQL, Microsoft SQL Server, Redis, MongoDB,
and a light Oracle TNS probe.

COLLECTION ONLY: we perform protocol negotiation / server-greeting reads and, at
most, an unauthenticated INFO/version ping that the protocol offers publicly
(e.g. Redis INFO, MySQL server greeting). We do NOT authenticate with guessed
credentials, run queries, enumerate data, or modify anything. The output is
"a PostgreSQL server (v14.x) is listening here" — a fact, not an intrusion.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import struct

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint,
)

# Default port -> probe kind. Multiple ports can map to the same engine.
DEFAULT_DB_PORTS = {
    3306: "mysql",
    5432: "postgres",
    1433: "mssql",
    6379: "redis",
    27017: "mongodb",
    1521: "oracle",
}


# --------------------------------------------------------------------------- #
# Per-engine probes. Each returns a dict of facts or None.
# --------------------------------------------------------------------------- #
async def _probe_mysql(reader, writer, timeout) -> dict | None:
    # MySQL/MariaDB server speaks first: initial handshake packet contains the
    # server version as a null-terminated string after a few header bytes.
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except asyncio.TimeoutError:
        return None
    if len(data) < 6:
        return None
    # packet: 3-byte len + 1-byte seq + 1-byte protocol + version\0
    proto = data[4]
    if proto not in (10, 9):  # handshake protocol versions
        return None
    rest = data[5:]
    end = rest.find(b"\x00")
    version = rest[:end].decode("latin-1", "replace") if end > 0 else None
    return {"engine": "mysql/mariadb", "protocol_version": proto,
            "server_version": version}


async def _probe_postgres(reader, writer, timeout) -> dict | None:
    # Send an SSLRequest (8 bytes). Postgres replies 'S' (ssl ok) or 'N' (no ssl)
    # — either single-byte reply confirms a PostgreSQL server.
    try:
        writer.write(struct.pack("!ii", 8, 80877103))  # length=8, SSLRequest code
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if data in (b"S", b"N"):
        return {"engine": "postgresql",
                "ssl_supported": data == b"S"}
    return None


async def _probe_mssql(reader, writer, timeout) -> dict | None:
    # TDS pre-login packet. A TDS response (type 0x04) confirms SQL Server.
    prelogin = bytes.fromhex(
        "12010000000000000000")  # minimal TDS pre-login header-ish
    try:
        # Build a minimal valid TDS pre-login.
        body = bytes.fromhex("00001a000600010002000300"
                             "00040000ff")
        header = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(body), 0, 0, 0)
        writer.write(header + body)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if data and data[0] == 0x04:
        return {"engine": "microsoft sql server", "tds_response": True}
    return None


async def _probe_redis(reader, writer, timeout) -> dict | None:
    # Redis: send INFO server (RESP). Unauthenticated servers reply with a bulk
    # string of server info incl. version; auth-required servers reply -NOAUTH.
    try:
        writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if not data:
        return None
    text = data.decode("latin-1", "replace")
    if "NOAUTH" in text or "redis_version" in text or text.startswith("$"):
        m = re.search(r"redis_version:([0-9.]+)", text)
        return {"engine": "redis",
                "auth_required": "NOAUTH" in text,
                "server_version": m.group(1) if m else None}
    return None


async def _probe_mongodb(reader, writer, timeout) -> dict | None:
    # MongoDB wire protocol: send an OP_QUERY for {isMaster:1} on admin.$cmd.
    # A valid BSON reply confirms MongoDB.
    try:
        doc = bytes.fromhex(
            "13000000")  # bson length placeholder; build a real isMaster below
        bson = (b"\x10ismaster\x00\x01\x00\x00\x00\x00")  # int32 field ismaster=1
        bson = struct.pack("<i", len(bson) + 5) + bson + b"\x00"
        full_collection = b"admin.$cmd\x00"
        query = (struct.pack("<i", 0) + full_collection +
                 struct.pack("<i", 0) + struct.pack("<i", -1) + bson)
        # msg header: messageLength, requestID, responseTo, opCode(2004=OP_QUERY)
        body = struct.pack("<i", 0) + query  # flags + query
        header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)
        writer.write(header + body)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if len(data) >= 16:
        opcode = struct.unpack("<i", data[12:16])[0]
        if opcode in (1, 2004, 2013):  # OP_REPLY / OP_MSG family
            ver = None
            m = re.search(rb"version\x00.{0,4}([0-9]+\.[0-9]+\.[0-9]+)", data)
            if m:
                ver = m.group(1).decode("latin-1", "replace")
            return {"engine": "mongodb", "wire_reply_opcode": opcode,
                    "server_version": ver}
    return None


async def _probe_oracle(reader, writer, timeout) -> dict | None:
    # Oracle TNS: a connect packet elicits a TNS response (type 2=accept,
    # 4=refuse, 11=resend). Any TNS reply confirms an Oracle listener.
    try:
        # Minimal TNS connect packet.
        data_payload = (b"(CONNECT_DATA=(COMMAND=ping))")
        # TNS header: length(2), checksum(2), type(1=connect? use 1), reserved...
        tns = struct.pack(">HHBBH", 0, 0, 1, 0, 0) + data_payload
        tns = struct.pack(">H", len(tns)) + tns[2:]
        writer.write(tns)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    if len(data) >= 5:
        tns_type = data[4]
        if tns_type in (2, 4, 11):
            return {"engine": "oracle tns", "tns_packet_type": tns_type}
    return None


_PROBES = {
    "mysql": _probe_mysql,
    "postgres": _probe_postgres,
    "mssql": _probe_mssql,
    "redis": _probe_redis,
    "mongodb": _probe_mongodb,
    "oracle": _probe_oracle,
}


class DBScanner(BaseScanner):
    name = "db_scan"

    def __init__(self, *args, port_map: dict[int, str] | None = None,
                 try_all_on_port: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.port_map = port_map or DEFAULT_DB_PORTS
        # If True, try every probe on each port (useful for non-standard ports).
        self.try_all = try_all_on_port

    async def _probe_one(self, target: str, port: int, kind: str) -> dict | None:
        await self.limiter.wait()
        async with self.sem:
            try:
                fut = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            try:
                return await _PROBES[kind](reader, writer, self.timeout)
            except Exception:
                return None
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _scan_port(self, target: str, port: int) -> ScanResult | None:
        kinds = list(_PROBES.keys()) if self.try_all else \
            [self.port_map.get(port, "")]
        for kind in kinds:
            if not kind:
                continue
            facts = await self._probe_one(target, port, kind)
            if facts:
                return ScanResult(
                    self.name, target, port=port, proto="tcp", status="open",
                    data=facts,
                    evidence=(f"{facts.get('engine')} "
                              f"{facts.get('server_version') or ''}".strip()))
        return None

    async def scan_target(self, target: str) -> list[ScanResult]:
        ports = list(self.port_map.keys())
        tasks = [self._scan_port(target, p) for p in ports]
        return [r for r in await asyncio.gather(*tasks) if r is not None]


def main() -> None:
    parser = base_argparser("Database service fingerprint scanner")
    parser.add_argument("-p", "--ports", default=None,
                        help="ports to probe (default: standard DB ports)")
    parser.add_argument("--try-all", action="store_true",
                        help="try every DB probe on each port (non-standard ports)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        if args.ports:
            # Unknown custom ports: enable try-all so we still identify them.
            port_map = {p: "" for p in parse_ports(args.ports)}
            try_all = True
        else:
            port_map = DEFAULT_DB_PORTS
            try_all = args.try_all

        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = DBScanner(scope, rate=args.rate, concurrency=args.concurrency,
                            timeout=args.timeout, port_map=port_map,
                            try_all_on_port=try_all)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
