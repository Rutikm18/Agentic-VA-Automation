"""
models.py — shared schema for the detection/correlation layer.

Two core objects:
  Asset   — per-host aggregation of every ScanResult fact observed about it.
  Finding — a CVE/CPE match derived from an Asset's facts, with full
            provenance back to the raw observations that justify it.

Neither object ever discards a raw fact — Asset.facts retains every Fact
exactly as ingested (see ingest.py), so any derived field (port lists, CPE
guesses, findings) can always be traced back to source. This is the
"evidence_refs must be resolvable back to raw facts" requirement — it's
enforced structurally here, not by convention: Finding.__post_init__ refuses
to construct a Finding with zero evidence_refs.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class SourceConfidence(str, Enum):
    """How was this fact obtained? Drives every downstream confidence decision
    (CPE match confidence, finding state, suppression rules) — this single
    field is the load-bearing one for the whole anti-false-positive design.

    authoritative — credentialed collection (dpkg/rpm package list, a real
                    Windows hotfix/KB list, a registry read). The host told
                    us directly what's installed; nothing to infer.
    inferred      — guessed from network-observable evidence (a banner
                    string, a TLS cert field, an HTTP Server header). Can be
                    wrong: honeypots lie, reverse proxies front a different
                    real backend, and distros backport security fixes while
                    keeping the upstream version string unchanged (the
                    classic RHEL/Debian backport false-positive trap).
    """
    authoritative = "authoritative"
    inferred = "inferred"


@dataclass
class Fact:
    """One ScanResult line, carried forward with its ingestion-time
    confidence tag and its exact source position (for evidence_refs)."""
    scanner: str
    target: str
    timestamp: str
    port: int | None
    proto: str | None
    status: str
    data: dict[str, Any]
    evidence: str | None
    error: str | None
    source_confidence: SourceConfidence
    source_file: str
    source_line: int

    def ref(self) -> str:
        """A stable, human-readable pointer back to this exact observation —
        what an evidence_ref actually points at. Resolvable: re-open
        source_file, seek to source_line, and you're looking at the exact
        raw JSONL record this Fact (and anything derived from it) came from.
        """
        return f"{self.source_file}:{self.source_line}"


@dataclass
class Asset:
    """Every fact known about one host, merged across all scanners/runs.

    IP is the join key (per spec: "Reconcile host identity across scanners —
    IP is the join key; carry hostname/mDNS name as aliases, don't treat them
    as separate assets"). Facts are never deduplicated/discarded on add —
    Phase 1.7's dedup happens at the Finding layer, not here; this object's
    job is to preserve everything observed, not to decide what matters.
    """
    ip: str
    aliases: set[str] = field(default_factory=set)
    facts: list[Fact] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    # False when this asset is keyed by a hostname rather than a real IP
    # (ingest.py doesn't do DNS resolution to merge hostname-only targets
    # into some other IP's asset) — set by the ingester, not computed here,
    # since ipaddress parsing belongs at the ingestion boundary.
    is_ip_keyed: bool = True

    def add_fact(self, fact: Fact) -> None:
        self.facts.append(fact)
        if self.first_seen is None or fact.timestamp < self.first_seen:
            self.first_seen = fact.timestamp
        if self.last_seen is None or fact.timestamp > self.last_seen:
            self.last_seen = fact.timestamp

    def add_alias(self, name: str | None) -> None:
        if name:
            self.aliases.add(name)

    def facts_by_scanner(self, scanner: str) -> list[Fact]:
        return [f for f in self.facts if f.scanner == scanner]

    def open_ports(self) -> list[int]:
        return sorted({f.port for f in self.facts if f.status == "open" and f.port})

    def as_of(self, cutoff_ts: str) -> "Asset":
        """Reconstruct this asset using only facts observed at or before
        cutoff_ts — point-in-time replay, needed for Phase 5 diffing
        ("what did we know about this host as of date X").
        """
        snap = Asset(ip=self.ip, aliases=set(self.aliases))
        for f in self.facts:
            if f.timestamp <= cutoff_ts:
                snap.add_fact(f)
        return snap


class FindingState(str, Enum):
    confirmed = "confirmed"   # authoritative source confirms the vulnerable version
    suspected = "suspected"   # inferred source — version-inferred, backport-possible
    potential = "potential"   # weak / single-signal corroboration only


def make_finding_id(asset_ip: str, cve_id: str, cpe: str) -> str:
    """Deterministic finding ID: the SAME (asset, CVE, CPE) triple always
    hashes to the SAME id, on this run or any future one. This is what makes
    Phase 1.7 dedup and Phase 5's "track this finding's appearance rate
    across N runs" possible at all — a random id (uuid4) would make a finding
    unrecognizable as "the same one" the moment detection re-runs on fresh
    facts, even if nothing about the underlying vulnerability changed.
    """
    raw = f"{asset_ip}|{cve_id}|{cpe}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Finding:
    finding_id: str
    asset_ip: str
    cpe: str
    cve_id: str
    match_basis: str              # "range" | "exact"
    state: FindingState
    source_confidence: SourceConfidence
    evidence_refs: list[str]
    db_snapshot_hash: str
    created_at: str
    matched_version: str          # the exact version string that was range-
                                   # compared to produce this finding — stored
                                   # directly rather than left to be parsed
                                   # back out of the human-readable `notes`
                                   # text, which is for display, not machine
                                   # consumption (correlate.py's
                                   # suppress_negated needs this precisely).
    # populated later, by enrichment (1.6) — optional until that stage runs
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    kev: bool | None = None
    priority: str | None = None
    internet_facing: bool | None = None
    auth_enforced: bool | None = None
    ai_assisted: bool = False     # True iff this Finding's CPECandidate came
                                   # from ai_normalizer.py (Phase 2) rather
                                   # than a rule-based normalize_* function —
                                   # surfaced distinctly so a reviewer can
                                   # apply extra scrutiny to AI-derived
                                   # findings specifically.
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Structural guarantee, not a convention: no evidence, no Finding.
        if not self.evidence_refs:
            raise ValueError(
                f"refusing to construct Finding {self.finding_id} "
                f"({self.cve_id} on {self.asset_ip}) with zero evidence_refs "
                f"— no evidence means no finding")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        d["source_confidence"] = self.source_confidence.value
        return d
