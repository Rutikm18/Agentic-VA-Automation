"""
ingest.py — stream-read scanner_module JSONL output, validate, assemble
per-host Assets.

SCOPE: this validates against scanner_module's ScanResult schema specifically
(scanner/target/timestamp/port/proto/status/data/evidence/error — see
scanner_module/scanner/scanner_base.py). Ingesting Intrynx probe's different
result envelope shape (scan_type/engine/tool/ok/hosts|findings) would be a
separate, additive parser, not assumed here.

Malformed lines are quarantined to IngestResult.quarantined rather than
raised — a single truncated/corrupt line must never take down an entire
ingestion pass over what could be hundreds of thousands of records.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from models import Asset, Fact, SourceConfidence

# Scanners that read a host's OWN authoritative state via credentials
# (installed package lists, real OS/registry reads) rather than guessing
# from network-observable banners. This single classification is what lets
# Phase 1.4's matcher treat a credentialed package-version match as
# "confirmed" and a banner-version match as merely "suspected".
_AUTHORITATIVE_SCANNERS = {"ssh_inventory", "windows_inventory"}

REQUIRED_FIELDS = {"scanner", "target", "timestamp", "status"}


@dataclass
class QuarantinedLine:
    source_file: str
    source_line: int
    raw: str
    reason: str


class IngestResult:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.quarantined: list[QuarantinedLine] = []
        self.fact_count = 0

    def get_or_create_asset(self, key: str) -> Asset:
        if key not in self.assets:
            self.assets[key] = Asset(ip=key, is_ip_keyed=_is_ip(key))
        return self.assets[key]


def _classify_confidence(scanner: str) -> SourceConfidence:
    return (SourceConfidence.authoritative if scanner in _AUTHORITATIVE_SCANNERS
            else SourceConfidence.inferred)


def _validate(record: dict) -> str | None:
    """Returns an error reason string if invalid, else None."""
    if not isinstance(record, dict):
        return "not a JSON object"
    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        return f"missing required field(s): {sorted(missing)}"
    if not isinstance(record.get("target"), str) or not record["target"]:
        return "target must be a non-empty string"
    port = record.get("port")
    if port is not None and not isinstance(port, int):
        return "port must be an int or null"
    return None


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _extract_aliases(scanner: str, data: dict) -> list[str]:
    """Real, verified hostname-alias sources in scanner_module's output —
    deliberately narrow. Not every scanner has a clean hostname field
    (passive_collector's device_hints is descriptive text, not a hostname,
    and is intentionally NOT treated as an alias here).
    """
    aliases: list[str] = []
    if scanner == "ssh_inventory":
        raw = (data.get("inventory") or {}).get("hostname")
        if raw:
            aliases.append(raw.strip())
    if scanner == "tls_scan":
        san = (data.get("certificate") or {}).get("san") or []
        aliases.extend(s for s in san if isinstance(s, str))
    return aliases


def ingest_file(path: str | Path, result: IngestResult | None = None) -> IngestResult:
    """Stream-read one JSONL file, validating and assembling Assets as it goes.

    Pass an existing IngestResult to accumulate across multiple files (e.g.
    one per scanner from run_scan.py's --split-output) into one merged set
    of Assets keyed by target.
    """
    result = result if result is not None else IngestResult()
    path = Path(path)
    source_file = str(path)

    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                result.quarantined.append(QuarantinedLine(
                    source_file, lineno, line[:300], f"invalid JSON: {exc}"))
                continue

            err = _validate(record)
            if err:
                result.quarantined.append(QuarantinedLine(
                    source_file, lineno, line[:300], err))
                continue

            target = record["target"]
            data = record.get("data") or {}
            fact = Fact(
                scanner=record["scanner"], target=target,
                timestamp=record.get("timestamp", ""), port=record.get("port"),
                proto=record.get("proto"), status=record["status"], data=data,
                evidence=record.get("evidence"), error=record.get("error"),
                source_confidence=_classify_confidence(record["scanner"]),
                source_file=source_file, source_line=lineno,
            )
            # IP is the join key (per spec). A hostname-only target becomes
            # an asset keyed by that hostname string itself — this module
            # does not perform DNS resolution to merge it into some other
            # IP's asset; that would require live lookups this ingester
            # deliberately doesn't do. is_ip is recorded for downstream
            # consumers that want to treat the two cases differently.
            asset = result.get_or_create_asset(target)
            asset.add_fact(fact)
            for alias in _extract_aliases(record["scanner"], data):
                asset.add_alias(alias)
            result.fact_count += 1

    return result


def ingest_files(paths: list[str | Path]) -> IngestResult:
    result = IngestResult()
    for p in paths:
        ingest_file(p, result)
    return result
