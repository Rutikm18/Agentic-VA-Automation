"""
asset.py — per-host fact model the workflow engine reasons about.

This is an ORCHESTRATION-time model: "what do we already know about this
host, so what should we run next" — distinct from detection_engine's Asset
(a detection-time model built from the JSONL scanner_module emits). The two
packages don't import each other; this one only ever consumes real
scanner.scanner_base.ScanResult objects, never modifies them.

Every merge_* method below is keyed off the EXACT field names
scanner_module's real scanners emit in ScanResult.data (confirmed by
reading scanner_base.py and each scanner module directly — see this
module's companion gates.py/router.py for the same discipline) — not the
illustrative field names from any planning document.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# scanner_module's package is "scanner" relative to scanner_module/; this
# workflow package lives at scanner_module/workflow/, so the import is a
# plain sibling-package reference, run from inside scanner_module/.
from scanner.scanner_base import ScanResult


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


@dataclass
class PortFact:
    proto: str
    status: str            # open | closed | filtered
    last_scan_time: datetime
    certainty: str = "deterministic"  # TCP results are deterministic enough
                                       # to trust within an engagement; UDP
                                       # results get "uncertain" explicitly
                                       # by the caller (see cache.py's
                                       # FACT_CERTAINTY table — port-level
                                       # certainty can vary by proto, so
                                       # this lives on the fact, not a
                                       # static per-scanner table alone).


@dataclass
class Asset:
    host: str
    aliases: set[str] = field(default_factory=set)
    last_seen_alive: datetime | None = None
    open_ports: dict[int, PortFact] = field(default_factory=dict)
    services: dict[int, dict] = field(default_factory=dict)       # port -> banner fact
    tls_facts: dict[int, dict] = field(default_factory=dict)
    web_facts: dict[int, dict] = field(default_factory=dict)
    smb_state: dict | None = None
    snmp_state: dict[int, dict] = field(default_factory=dict)
    db_facts: dict[int, dict] = field(default_factory=dict)
    ai_facts: dict[int, dict] = field(default_factory=dict)
    passive_facts: list[dict] = field(default_factory=list)
    credential_inventory: dict | None = None

    profile: str = "it"
    cred_collected: bool = False
    last_engagement_uuid: str | None = None

    def needs_recheck_live(self, threshold: timedelta) -> bool:
        """Is liveness unknown, or stale past `threshold`? Threshold is
        profile-dependent (5 min for iot/wifi churn, 60 min for hardened
        corporate it) — caller (gates.py) supplies it, this method has no
        opinion on the actual duration so the policy lives in one place.
        """
        if self.last_seen_alive is None:
            return True
        return _utcnow() - self.last_seen_alive > threshold

    def open_ports_for_deep_scan(self) -> set[int]:
        return {p for p, f in self.open_ports.items() if f.status == "open"}

    def merge_result(self, result: ScanResult) -> None:
        """Dispatch a real ScanResult into the right sub-structure, keyed
        on result.scanner — the exact names scanner_base.BaseScanner
        subclasses set as their `name` class attribute / pass to ScanResult.
        """
        handler = _MERGE_DISPATCH.get(result.scanner)
        if handler:
            handler(self, result)

    # --- per-scanner merge handlers -------------------------------------

    def _merge_host_discovery(self, r: ScanResult) -> None:
        if r.data.get("alive"):
            self.last_seen_alive = _parse_ts(r.timestamp)
        for entry in r.data.get("responding_ports") or []:
            port = entry.get("port")
            if port is not None:
                self.open_ports.setdefault(port, PortFact(
                    proto="tcp", status=entry.get("state", "open"),
                    last_scan_time=_parse_ts(r.timestamp), certainty="uncertain"))

    def _merge_port_scan(self, r: ScanResult) -> None:
        if r.port is None:
            return
        self.open_ports[r.port] = PortFact(
            proto=r.proto or "tcp", status=r.status,
            last_scan_time=_parse_ts(r.timestamp),
            certainty="deterministic" if r.proto != "udp" else "uncertain")

    def _merge_service_banner(self, r: ScanResult) -> None:
        if r.port is not None:
            self.services[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_tls_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.tls_facts[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_web_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.web_facts[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_smb_scan(self, r: ScanResult) -> None:
        # host-level, not per-port — smb_scanner.py probes one fixed port
        # (default 445) but the *fact* (smbv1_enabled/smb2_supported)
        # describes the host's SMB stack, not that one port specifically.
        self.smb_state = {**r.data, "_collected_at": r.timestamp}

    def _merge_snmp_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.snmp_state[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_db_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.db_facts[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_mcp_ai_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.ai_facts[r.port] = {**r.data, "_collected_at": r.timestamp}

    def _merge_udp_scan(self, r: ScanResult) -> None:
        if r.port is not None:
            self.open_ports[r.port] = PortFact(
                proto="udp", status=r.status, last_scan_time=_parse_ts(r.timestamp),
                certainty="uncertain")
            self.services[r.port] = {**self.services.get(r.port, {}), **r.data,
                                     "_collected_at": r.timestamp, "_proto": "udp"}

    def _merge_passive_collect(self, r: ScanResult) -> None:
        self.passive_facts.append({**r.data, "_collected_at": r.timestamp})
        for hint in r.data.get("device_hints") or []:
            if isinstance(hint, str):
                self.aliases.add(hint)

    def _merge_ssh_inventory(self, r: ScanResult) -> None:
        self.credential_inventory = {**r.data, "_collected_at": r.timestamp, "_via": "ssh"}
        self.cred_collected = True

    def _merge_windows_inventory(self, r: ScanResult) -> None:
        self.credential_inventory = {**r.data, "_collected_at": r.timestamp, "_via": "windows"}
        self.cred_collected = True


# Maps ScanResult.scanner -> Asset method. Built once, module load time —
# every entry's right-hand side must be a real `name` a BaseScanner
# subclass actually sets (verified, not assumed) before adding it here.
_MERGE_DISPATCH = {
    "host_discovery": Asset._merge_host_discovery,
    "port_scan": Asset._merge_port_scan,
    "service_banner": Asset._merge_service_banner,
    "tls_scan": Asset._merge_tls_scan,
    "web_scan": Asset._merge_web_scan,
    "smb_scan": Asset._merge_smb_scan,
    "snmp_scan": Asset._merge_snmp_scan,
    "db_scan": Asset._merge_db_scan,
    "mcp_ai_scan": Asset._merge_mcp_ai_scan,
    "udp_scan": Asset._merge_udp_scan,
    "passive_collect": Asset._merge_passive_collect,
    "ssh_inventory": Asset._merge_ssh_inventory,
    "windows_inventory": Asset._merge_windows_inventory,
}
