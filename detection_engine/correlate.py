"""
correlate.py — dedup, authoritative-suppression, and cross-fact composite
correlation.

Three distinct jobs, in order:
  1. dedup_findings()      — collapse the same (asset, cve, cpe) reported
                             multiple times (multiple Debian-release entries
                             in one OSV record, multiple sensors) into one
                             Finding with a UNION of evidence_refs. If any
                             contributing match was authoritative, the
                             merged Finding is confirmed — authoritative
                             evidence upgrades, it never gets diluted by
                             also being seen from a weaker source.
  2. suppress_negated()    — if a host has AUTHORITATIVE package data for a
                             product and that data does NOT confirm a given
                             CVE (i.e. the credentialed version is patched),
                             any SUSPECTED finding for that same CVE+product
                             from an INFERRED source on the same host is
                             suppressed. Authoritative data wins.
  3. correlate_smb_patch() — the one composite cross-fact rule this phase
                             implements: SMBv1 enabled + missing the known
                             MS17-010 hotfixes -> a composite "suspected"
                             finding (never confirmed/exploited — this is
                             collection, not exploitation).
"""
from __future__ import annotations

from datetime import datetime, timezone

from cpe_normalizer import CPECandidate
from models import Asset, Finding, FindingState, SourceConfidence, make_finding_id
from version_compare import dpkg_compare


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse by finding_id (deterministic: same asset+cve+cpe always
    hashes the same — see models.make_finding_id). Keeps the strongest
    state seen and the union of all evidence_refs and notes.
    """
    by_id: dict[str, Finding] = {}
    for f in findings:
        existing = by_id.get(f.finding_id)
        if existing is None:
            by_id[f.finding_id] = f
            continue
        # Union evidence, dedup-preserving order
        for ref in f.evidence_refs:
            if ref not in existing.evidence_refs:
                existing.evidence_refs.append(ref)
        for note in f.notes:
            if note not in existing.notes:
                existing.notes.append(note)
        # Authoritative evidence upgrades the merged finding; it is never
        # downgraded by also having been seen from a weaker source.
        if f.source_confidence == SourceConfidence.authoritative:
            existing.source_confidence = SourceConfidence.authoritative
            existing.state = FindingState.confirmed
    return list(by_id.values())


def suppress_negated(findings: list[Finding],
                     candidates_by_asset: dict[str, list[CPECandidate]]) -> list[Finding]:
    """Suppress a suspected/potential (inferred-source) finding when the
    SAME host also has an AUTHORITATIVE candidate for the SAME product
    whose version is >= the inferred candidate's version.

    Deliberately does NOT use "any confirmed finding on this product
    suppresses other CVEs on it" — that would be wrong: a single installed
    version can genuinely be vulnerable to multiple distinct CVEs, so
    confirming one must never silently hide another. The actual, narrow,
    correct signal is a VERSION comparison: if the host's real credentialed
    version is at least as new as whatever a banner claimed, the banner's
    older-looking version string is stale/wrong (custom build reporting an
    old string, an out-of-date banner cache, a proxy fronting a different
    real version) — and the suspected finding built on it should not stand
    next to better evidence that contradicts it.
    """
    # (asset_ip, cpe vendor:product) -> best (highest-version) authoritative
    # candidate. Keyed by CPE product, NOT lookup_key — lookup_key is the
    # OSV source-package name (e.g. "apache2"), which can legitimately
    # differ from the CPE product (e.g. "http_server"); comparing
    # lookup_key against a CPE-derived product string here would silently
    # never match, the exact bug already found and fixed in matcher.py.
    # Both sides must go through the same cpe23()-based extraction.
    best_authoritative: dict[tuple[str, str], CPECandidate] = {}
    for asset_ip, candidates in candidates_by_asset.items():
        for c in candidates:
            if c.source_confidence != SourceConfidence.authoritative:
                continue
            version = c.version_raw or c.version_normalized
            if not version:
                continue
            key = (asset_ip, _product_from_cpe(c.cpe23()))
            existing = best_authoritative.get(key)
            if existing is None or dpkg_compare(version, existing.version_raw or existing.version_normalized) > 0:
                best_authoritative[key] = c

    out = []
    for f in findings:
        if f.source_confidence == SourceConfidence.authoritative:
            out.append(f)  # never suppress an authoritative finding itself
            continue
        product = _product_from_cpe(f.cpe)
        auth = best_authoritative.get((f.asset_ip, product))
        if auth is not None:
            auth_version = auth.version_raw or auth.version_normalized
            if f.matched_version and dpkg_compare(auth_version, f.matched_version) >= 0:
                continue  # suppressed: real credentialed version is at
                          # least as new as whatever this finding matched on
        out.append(f)
    return out


def _product_from_cpe(cpe: str) -> str:
    """The CPE 'product' field — used as the join key on BOTH sides (a
    Finding's cpe and an authoritative CPECandidate's cpe23()), since
    CPECandidate.lookup_key (the OSV source-package name) can legitimately
    differ from the CPE product name and comparing across the two would
    silently never match — the exact bug already found and fixed once in
    matcher.py; keeping both sides of this comparison CPE-derived avoids
    reintroducing it here.
    """
    parts = cpe.split(":")
    return parts[4] if len(parts) > 4 else cpe


# Known Microsoft KB IDs for the MS17-010 (EternalBlue) SMBv1 RCE, across the
# Windows versions Microsoft patched it on — used only to check ABSENCE in a
# credentialed hotfix list, never to claim presence proves anything.
_MS17_010_KBS = {"KB4012212", "KB4012213", "KB4012214", "KB4012215",
                 "KB4012216", "KB4012217", "KB4012598"}


def correlate_smb_patch(asset: Asset) -> Finding | None:
    """SMBv1 enabled + (credentialed hotfix list present AND missing every
    known MS17-010 KB) -> one composite suspected finding. Requires BOTH
    signals on the SAME host; SMBv1 alone is already its own (separate,
    non-composite) signal smb_scan/smb_enum's own finding logic handles.
    """
    smb_facts = asset.facts_by_scanner("smb_scan") + asset.facts_by_scanner("smb_enum")
    smbv1_on = any(f.data.get("smbv1_enabled") for f in smb_facts)
    if not smbv1_on:
        return None

    cred_facts = asset.facts_by_scanner("ssh_inventory") + asset.facts_by_scanner("windows_inventory")
    hotfix_text = ""
    have_authoritative_hotfixes = False
    for f in cred_facts:
        inv = f.data.get("inventory") or {}
        hf = inv.get("hotfixes")
        if hf:
            have_authoritative_hotfixes = True
            hotfix_text += hf

    if not have_authoritative_hotfixes:
        return None  # no credentialed hotfix data to correlate against —
                     # SMBv1-alone signal already covers this host elsewhere

    missing_all = all(kb not in hotfix_text for kb in _MS17_010_KBS)
    if not missing_all:
        return None  # at least one MS17-010 KB is present — patched

    fid = make_finding_id(asset.ip, "CVE-2017-0144", "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*")
    return Finding(
        finding_id=fid, asset_ip=asset.ip,
        cpe="cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
        cve_id="CVE-2017-0144", match_basis="composite",
        # Deliberate exception to the usual confirmed<->authoritative,
        # suspected<->inferred pairing (matcher.py's rule): the INPUT here
        # (the hotfix list) genuinely is authoritative/credentialed, but a
        # missing patch only ever implies a real exploit COULD work, never
        # that it does — per spec, this composite signal is "still
        # suspected, you don't exploit", regardless of how good the input was.
        state=FindingState.suspected,
        source_confidence=SourceConfidence.authoritative,
        evidence_refs=[f.ref() for f in smb_facts] + [f.ref() for f in cred_facts],
        db_snapshot_hash="composite-rule:ms17-010",
        created_at=datetime.now(timezone.utc).isoformat(),
        matched_version="N/A (composite rule: SMBv1 + missing-hotfix signal, no version range)",
        notes=["SMBv1 enabled AND no MS17-010 (EternalBlue) hotfix found in "
               "credentialed hotfix list — composite suspicion only, not "
               "confirmed and never exploited from this signal."],
    )
