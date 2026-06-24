"""Database service fingerprint — MySQL/MariaDB, PostgreSQL, MSSQL, Redis,
MongoDB, Oracle. Pure-Python (raw sockets), no external CLI tool.

WHY: databases are everywhere on internal networks and frequently exposed. A
plain banner grab does NOT identify most of them, because they speak BINARY
protocols, not text banners. This sends each DB's minimal, valid, READ-ONLY
handshake/ping and identifies the service (and version where the protocol
volunteers it).

COLLECTION ONLY: protocol negotiation / server-greeting reads and, at most,
an unauthenticated INFO/ping that the protocol offers publicly (e.g. Redis
INFO, MySQL's own server greeting). Never authenticates with guessed
credentials, runs queries, enumerates data, or modifies anything.

FINDINGS: only ONE fact is well-evidenced enough from these lightweight
handshakes alone to call a risk rather than plain inventory — see
_db_findings below for why MongoDB/MSSQL/etc. intentionally stay
inventory-only despite a successful handshake.
"""
from __future__ import annotations

import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from .base import BUILTIN_DB, expand_hosts, normalize_targets, now, result, scanner, split_host_port

DEFAULT_DB_PORTS: dict[int, str] = {
    3306: "mysql", 5432: "postgres", 1433: "mssql",
    6379: "redis", 27017: "mongodb", 1521: "oracle",
}


def _probe_mysql(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # MySQL/MariaDB speaks first: the initial handshake packet contains the
    # server version as a null-terminated string after a few header bytes.
    sock.settimeout(timeout)
    try:
        data = sock.recv(256)
    except OSError:
        return None
    if len(data) < 6:
        return None
    proto = data[4]
    if proto not in (10, 9):  # handshake protocol versions
        return None
    rest = data[5:]
    end = rest.find(b"\x00")
    version = rest[:end].decode("latin-1", "replace") if end > 0 else None
    return {"engine": "mysql/mariadb", "protocol_version": proto, "server_version": version}


def _probe_postgres(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # An SSLRequest (8 bytes) elicits a single-byte 'S' (ssl ok) or 'N' (no
    # ssl) reply — either one confirms a PostgreSQL server.
    sock.settimeout(timeout)
    try:
        sock.sendall(struct.pack("!ii", 8, 80877103))  # length=8, SSLRequest code
        data = sock.recv(1)
    except OSError:
        return None
    if data in (b"S", b"N"):
        return {"engine": "postgresql", "ssl_supported": data == b"S"}
    return None


def _probe_mssql(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # A minimal TDS pre-login packet; a TDS response (type 0x04) confirms SQL Server.
    sock.settimeout(timeout)
    try:
        body = bytes.fromhex("00001a000600010002000300" "00040000ff")
        header = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(body), 0, 0, 0)
        sock.sendall(header + body)
        data = sock.recv(256)
    except OSError:
        return None
    if data and data[0] == 0x04:
        return {"engine": "microsoft sql server", "tds_response": True}
    return None


def _probe_redis(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # INFO server: unauthenticated servers reply with real data (public on
    # most default installs); auth-required servers reply -NOAUTH instead.
    sock.settimeout(timeout)
    try:
        sock.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        data = sock.recv(2048)
    except OSError:
        return None
    if not data:
        return None
    text = data.decode("latin-1", "replace")
    if "NOAUTH" in text or "redis_version" in text or text.startswith("$"):
        m = re.search(r"redis_version:([0-9.]+)", text)
        return {"engine": "redis", "auth_required": "NOAUTH" in text,
                "server_version": m.group(1) if m else None}
    return None


def _probe_mongodb(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # MongoDB wire protocol: an OP_QUERY for {isMaster:1} on admin.$cmd. A
    # valid BSON reply confirms MongoDB, but does NOT by itself prove data
    # access is unauthenticated — see _db_findings.
    sock.settimeout(timeout)
    try:
        bson = b"\x10ismaster\x00\x01\x00\x00\x00\x00"  # int32 field ismaster=1
        bson = struct.pack("<i", len(bson) + 5) + bson + b"\x00"
        full_collection = b"admin.$cmd\x00"
        query = (struct.pack("<i", 0) + full_collection +
                 struct.pack("<i", 0) + struct.pack("<i", -1) + bson)
        body = struct.pack("<i", 0) + query  # flags + query
        header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)  # opCode=OP_QUERY
        sock.sendall(header + body)
        data = sock.recv(512)
    except OSError:
        return None
    if len(data) >= 16:
        opcode = struct.unpack("<i", data[12:16])[0]
        if opcode in (1, 2004, 2013):  # OP_REPLY / OP_MSG family
            ver = None
            m = re.search(rb"version\x00.{0,4}([0-9]+\.[0-9]+\.[0-9]+)", data)
            if m:
                ver = m.group(1).decode("latin-1", "replace")
            return {"engine": "mongodb", "wire_reply_opcode": opcode, "server_version": ver}
    return None


def _probe_oracle(sock: socket.socket, timeout: float) -> dict[str, Any] | None:
    # Minimal TNS connect packet. Any TNS reply (accept/refuse/resend)
    # confirms an Oracle listener.
    sock.settimeout(timeout)
    try:
        data_payload = b"(CONNECT_DATA=(COMMAND=ping))"
        tns = struct.pack(">HHBBH", 0, 0, 1, 0, 0) + data_payload
        tns = struct.pack(">H", len(tns)) + tns[2:]
        sock.sendall(tns)
        data = sock.recv(256)
    except OSError:
        return None
    if len(data) >= 5:
        tns_type = data[4]
        if tns_type in (2, 4, 11):  # accept / refuse / resend
            return {"engine": "oracle tns", "tns_packet_type": tns_type}
    return None


_PROBES: dict[str, Callable[[socket.socket, float], dict[str, Any] | None]] = {
    "mysql": _probe_mysql, "postgres": _probe_postgres, "mssql": _probe_mssql,
    "redis": _probe_redis, "mongodb": _probe_mongodb, "oracle": _probe_oracle,
}


def _scan_one(host: str, port: int, kind: str, timeout: float) -> dict[str, Any] | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        facts = _PROBES[kind](sock, timeout)
    except Exception:  # one probe's parsing bug must never sink the scan
        facts = None
    finally:
        sock.close()
    if not facts:
        return None
    return {"host": host, "port": port, **facts}


def _db_findings(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The only risk fact well-evidenced enough from these lightweight
    handshakes alone to call a finding rather than plain inventory: Redis
    answering INFO with real server data (not a -NOAUTH rejection) proves
    authentication is not enabled — a classic, actively-exploited exposure
    (full read/write, and in older versions RCE via MODULE LOAD).

    Every other engine here stays inventory-only on purpose. MongoDB's
    isMaster handshake succeeds whether or not actual data access later
    requires auth — claiming "unauthenticated MongoDB" from that alone would
    be the same class of overclaim already found and fixed in mcp_ai.py
    (trusting a generic protocol-level success as proof of a specific,
    stronger claim it doesn't actually support). MySQL/MSSQL/Postgres/Oracle
    never reveal auth status from a pre-login handshake at all.
    """
    findings = []
    for s in services:
        if s.get("engine") == "redis" and s.get("auth_required") is False:
            ver = f"; version={s['server_version']}" if s.get("server_version") else ""
            findings.append({
                "target": s["host"], "port": s["port"],
                "title": "Unauthenticated Redis exposed",
                "severity": "critical",
                "detail": f"INFO command succeeded without authentication{ver}",
            })
    return findings


@scanner("db_fingerprint", BUILTIN_DB,
         "Database service fingerprint — MySQL/Postgres/MSSQL/Redis/MongoDB/Oracle")
def db_fingerprint(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("db_fingerprint", BUILTIN_DB, [], ok=False, error="no targets provided")
    started = now()
    concurrency = int(params.get("concurrency", 40))
    timeout = float(params.get("timeout", 4.0))
    max_hosts = int(params.get("max_hosts", 1024))

    # Standard DB ports map 1:1 to a known engine. A custom port list means
    # "I don't know what's there" — try every probe on each of those ports.
    custom_ports = params.get("ports")
    if custom_ports:
        if isinstance(custom_ports, str):
            custom_ports = [int(p.strip()) for p in custom_ports.split(",") if p.strip()]
        port_map: dict[int, str | None] = {int(p): None for p in custom_ports}
    else:
        port_map = dict(DEFAULT_DB_PORTS)

    work: list[tuple[str, int, str]] = []
    for tok in targets:
        host, pin = split_host_port(tok)
        ports_here = {pin: port_map.get(pin)} if pin else port_map
        for h in expand_hosts([host], max_hosts=max_hosts):
            for port, kind in ports_here.items():
                kinds = [kind] if kind else list(_PROBES.keys())
                work += [(h, port, k) for k in kinds]

    services: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_scan_one, h, p, k, timeout) for h, p, k in work]
        for fut in as_completed(futs):
            try:
                found = fut.result()
            except Exception:
                found = None
            if found:
                services.append(found)

    # de-dupe (host, port) — trying every probe on a custom port could
    # theoretically match more than one engine's loose acceptance criteria.
    seen: set[tuple] = set()
    uniq: list[dict[str, Any]] = []
    for s in services:
        key = (s["host"], s["port"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)

    findings = _db_findings(uniq)
    return result("db_fingerprint", BUILTIN_DB, targets, db_services=uniq,
                  service_count=len(uniq), findings=findings,
                  finding_count=len(findings), endpoints_probed=len(work), started=started)
