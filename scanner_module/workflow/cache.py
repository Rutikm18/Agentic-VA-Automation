"""
cache.py — (host, port, scanner) -> CacheEntry, so deterministic facts are
collected once per engagement (or across re-scans) and never re-probed.

Certainty classification (FACT_CERTAINTY) decides whether a cached entry
can be trusted indefinitely within an engagement or should be rechecked:
  deterministic — banner/TLS/web/SMB/SNMP/DB/AI-endpoint/credentialed
                  facts. The service's configuration doesn't change
                  minute-to-minute; re-probing it mid-engagement wastes
                  packets for no new information.
  uncertain     — host_discovery (wifi/LAN churn — a host can go up/down
                  between passes), UDP port_scan/udp_scan (no-reply is
                  fundamentally ambiguous: closed | filtered | dropped —
                  worth a recheck), passive_collect (time-windowed by
                  nature; new announcements appear as devices join/leave).
Any result with status=="error" or a populated .error field is ALWAYS
uncertain regardless of scanner — a transient network failure is not a
fact about the target, it's a fact about that one probe attempt.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scanner.scanner_base import ScanResult

FACT_CERTAINTY = {
    "host_discovery": "uncertain",
    "port_scan": "deterministic",       # TCP; UDP overridden in classify_certainty
    "service_banner": "deterministic",
    "tls_scan": "deterministic",
    "web_scan": "deterministic",
    "smb_scan": "deterministic",
    "snmp_scan": "deterministic",
    "db_scan": "deterministic",
    "mcp_ai_scan": "deterministic",
    "udp_scan": "uncertain",
    "passive_collect": "uncertain",
    "ssh_inventory": "deterministic",   # credentialed, authoritative, host-stable
    "windows_inventory": "deterministic",
}


def classify_certainty(result: ScanResult) -> str:
    if result.status == "error" or result.error:
        return "uncertain"
    if result.scanner == "port_scan" and result.proto == "udp":
        return "uncertain"
    return FACT_CERTAINTY.get(result.scanner, "uncertain")  # unknown scanner: fail conservative


@dataclass
class CacheEntry:
    host: str
    port: int | None
    proto: str | None
    scanner: str
    result: ScanResult
    collected_at: str       # ISO 8601 — kept as the string ScanResult.timestamp
                             # already is, never re-parsed unless a caller needs to
    fact_certainty: str

    def to_jsonl_dict(self) -> dict:
        d = asdict(self)
        d["result"] = asdict(self.result)
        return d

    @classmethod
    def from_jsonl_dict(cls, d: dict) -> "CacheEntry":
        result = ScanResult(**d["result"])
        return cls(host=d["host"], port=d["port"], proto=d["proto"],
                  scanner=d["scanner"], result=result,
                  collected_at=d["collected_at"], fact_certainty=d["fact_certainty"])


class WorkflowCache:
    """In-memory (host, port, scanner) -> CacheEntry, optionally JSONL-backed
    for cross-session reuse (re-scan mode loads a prior engagement's file).
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._store: dict[tuple, CacheEntry] = {}
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        with self.path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = CacheEntry.from_jsonl_dict(json.loads(line))
                self._store[(entry.host, entry.port, entry.scanner)] = entry

    def save(self) -> None:
        if not self.path:
            raise ValueError("WorkflowCache has no path configured — pass path= to persist")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w") as fh:
            for entry in self._store.values():
                fh.write(json.dumps(entry.to_jsonl_dict(), default=str) + "\n")

    def get(self, host: str, port: int | None, scanner: str) -> CacheEntry | None:
        return self._store.get((host, port, scanner))

    def put(self, result: ScanResult) -> CacheEntry:
        entry = CacheEntry(
            host=result.target, port=result.port, proto=result.proto,
            scanner=result.scanner, result=result,
            collected_at=result.timestamp, fact_certainty=classify_certainty(result))
        self._store[(entry.host, entry.port, entry.scanner)] = entry
        return entry

    def should_recheck(self, host: str, port: int | None, scanner: str, *,
                       force_recheck_after: timedelta | None = None) -> bool:
        """True if there's no cached entry, OR the entry is uncertain
        (always worth a fresh look), OR the entry is older than
        force_recheck_after (re-scan mode's explicit staleness override,
        which can apply even to deterministic facts — a service really
        could have been upgraded since last week).
        """
        entry = self.get(host, port, scanner)
        if entry is None:
            return True
        if entry.fact_certainty == "uncertain":
            return True
        if force_recheck_after is not None:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(entry.collected_at)
            if age > force_recheck_after:
                return True
        return False

    def all_entries_for_host(self, host: str) -> list[CacheEntry]:
        return [e for (h, _, _), e in self._store.items() if h == host]
