"""
matcher.py — does this CPE candidate's version fall inside a vulnerable
range, per the offline snapshot?

OSV's range format (not NVD's versionStart/EndIncluding/Excluding fields —
see vuln_db.py's docstring for why this project uses OSV): each `ranges[]`
entry holds an `events[]` sequence, version-ordered, alternating
`introduced` / `fixed` / `last_affected` markers. A version is vulnerable if
it falls in any [introduced, fixed) or [introduced, last_affected] interval
the sequence describes. There can be multiple such intervals in one
sequence (vulnerable, fixed, regressed, fixed again) — this walks the whole
sequence, not just the first pair.

THE CORE ANTI-FALSE-POSITIVE RULE (per spec 1.4): a version-range match
alone is never enough to call a finding "confirmed". Confirmed requires
BOTH a range match AND Fact.source_confidence == authoritative (the host's
own credentialed package list said so). A match from an inferred source
(a banner, a header) can only ever produce "suspected" — distros backport
security fixes while keeping the upstream version string unchanged, so a
banner-only version match against a backport-patched host is a classic,
well-documented false-positive trap, not a confirmed vulnerability.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cpe_normalizer import CPECandidate
from models import Finding, FindingState, SourceConfidence, make_finding_id
from version_compare import dpkg_compare, has_ambiguous_epoch
from vuln_db import VulnDB


def _safe_compare(a: str, b: str) -> int | None:
    """dpkg_compare, but None instead of a misleading answer when one side
    has an explicit epoch the other structurally can never carry (see
    version_compare.has_ambiguous_epoch's docstring — found via testing a
    real banner-derived MariaDB version against a real epoch-1 CVE range).
    """
    if has_ambiguous_epoch(a, b):
        return None
    return dpkg_compare(a, b)


def _version_in_ranges(version: str, ranges: list[dict]) -> tuple[bool, str | None]:
    """Returns (matched, matched_interval_desc) — the latter for evidence_reason.
    A range boundary this version's epoch can't be safely compared against
    is treated as "cannot determine" (skipped), never as a coincidental
    match or non-match — see _safe_compare.
    """
    for rng in ranges:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = rng.get("events", [])
        introduced = None
        for ev in events:
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev:
                if introduced is not None:
                    lo, hi = _safe_compare(introduced, version), _safe_compare(version, ev["fixed"])
                    if lo is not None and hi is not None and lo <= 0 and hi < 0:
                        return True, f"[{introduced}, {ev['fixed']})"
                introduced = None
            elif "last_affected" in ev:
                if introduced is not None:
                    lo = _safe_compare(introduced, version)
                    hi = _safe_compare(version, ev["last_affected"])
                    if lo is not None and hi is not None and lo <= 0 and hi <= 0:
                        return True, f"[{introduced}, {ev['last_affected']}]"
                introduced = None
        # Sequence ended with an open lower bound and no closing event —
        # OSV convention: still vulnerable from `introduced` onward.
        if introduced is not None:
            lo = _safe_compare(introduced, version)
            if lo is not None and lo <= 0:
                return True, f"[{introduced}, unbounded)"
    return False, None


def match_candidate(asset_ip: str, candidate: CPECandidate, db: VulnDB) -> list[Finding]:
    """All Findings this single CPE candidate produces against the snapshot.
    Empty list if the product isn't in the snapshot or no range matches —
    that's a correct negative, not a failure. asset_ip is passed explicitly
    by the caller (which already knows which Asset this candidate's
    underlying Fact came from) — CPECandidate.source_ref only points at a
    file:line, not the asset, by design (see cpe_normalizer.py).
    """
    # version_raw, not version_normalized — OSV's Debian-ecosystem range
    # strings are FULL dpkg version strings (epoch:upstream-revision).
    # version_normalized deliberately strips epoch/revision for CPE display
    # purposes (cpe_normalizer.py), but epoch dominates dpkg comparison: a
    # stripped "9.6p1" (implicit epoch 0) would compare as OLDER than a
    # range string like "1:3.9p1-1" (epoch 1) purely from the missing
    # epoch — found via testing against real data, not a hypothetical.
    version = candidate.version_raw or candidate.version_normalized
    if not version:
        return []  # a wildcard-version candidate (e.g. a tech_hint) has
                    # nothing to range-match against; correlate.py may still
                    # want to surface "product present, version unknown"
                    # separately, but that's not this function's job.

    # lookup_key, not product — the vuln_db snapshot is indexed by OSV
    # source-package name, which can differ from the CPE product name
    # (e.g. "apache2" vs "http_server"). See cpe_normalizer.py's
    # _PACKAGE_TO_CPE module comment for the full explanation.
    records = db.lookup(candidate.lookup_key)
    findings: list[Finding] = []
    for rec in records:
        cve_ids = rec.get("upstream") or [rec["id"]]
        for aff in rec.get("affected", []):
            if aff.get("package", {}).get("name") != candidate.lookup_key:
                continue
            matched, interval = _version_in_ranges(version, aff.get("ranges", []))
            if not matched:
                continue

            for cve_id in cve_ids:
                # Confirmed requires authoritative evidence, not just a range
                # match — see module docstring. This is the spec's "Rule: if
                # source_confidence != authoritative, the finding is
                # suspected, never confirmed" applied directly. Keyed off
                # Fact.source_confidence (threaded through onto the
                # candidate by cpe_normalizer.py), NOT candidate.confidence
                # — those are different axes (product/version identification
                # certainty vs. observation-method authoritativeness).
                is_authoritative = candidate.source_confidence == SourceConfidence.authoritative
                state = FindingState.confirmed if is_authoritative else FindingState.suspected
                fid = make_finding_id(asset_ip, cve_id, candidate.cpe23())
                findings.append(Finding(
                    finding_id=fid,
                    asset_ip=asset_ip,
                    cpe=candidate.cpe23(),
                    cve_id=cve_id,
                    match_basis="range",
                    state=state,
                    source_confidence=(SourceConfidence.authoritative if is_authoritative
                                       else SourceConfidence.inferred),
                    evidence_refs=[candidate.source_ref],
                    db_snapshot_hash=db.meta.content_hash,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    matched_version=version,
                    ai_assisted=candidate.ai_assisted,
                    notes=[f"{candidate.basis} | matched range {interval}"]
                          + (["version-inferred, backport-possible"] if not is_authoritative else [])
                          + (["AI-assisted normalization — extra scrutiny advised"] if candidate.ai_assisted else []),
                ))
    return findings
