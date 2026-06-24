"""
pipeline.py — Phase 1 + Phase 2 end to end: JSONL in, Findings out.

  ingest          -> Assets (per-host fact aggregation)
  normalize       -> CPECandidates per Fact (rule-based; AI-assisted fallback
                     on a miss, only when use_ai_assist=True — see Phase 2)
  match           -> raw Findings per candidate, against the pinned snapshot
  dedup           -> collapse same (asset, cve, cpe)
  suppress        -> drop inferred findings a better authoritative source negates
  correlate       -> composite cross-fact findings (SMBv1 + missing hotfix)
  enrich          -> CVSS/EPSS/KEV + priority tier

Deterministic and offline at every step except the explicit, separate
update_snapshot.py sync, and the optional Phase 2 AI-assist fallback (which
itself fails closed to the same deterministic behavior when unavailable —
see ai_normalizer.py's module docstring for the hard rules that keep it
from ever becoming a hard dependency or a CVE source).
"""
from __future__ import annotations

from pathlib import Path

from ai_normalizer import AIClient, AINormalizerCache, extract_raw_text, propose_candidates
from correlate import correlate_smb_patch, dedup_findings, suppress_negated
from cpe_normalizer import CPECandidate, normalize
from enrichment import enrich_finding
from enrichment_db import EpssDB, KevDB, load_epss, load_kev
from ingest import IngestResult, ingest_files
from matcher import match_candidate
from models import Finding
from vuln_db import VulnDB, load_snapshot


def run_pipeline(jsonl_paths: list[str | Path], vuln_db: VulnDB | None = None,
                 kev_db: KevDB | None = None, epss_db: EpssDB | None = None,
                 exposure: dict[str, dict] | None = None,
                 use_ai_assist: bool = False, ai_client: AIClient | None = None,
                 ai_cache: AINormalizerCache | None = None) -> tuple[list[Finding], IngestResult]:
    """exposure: optional {asset_ip: {"internet_facing": bool, "auth_enforced":
    bool}} — exposure context this pipeline cannot derive from scan facts
    alone (see enrichment.py's docstring); caller-supplied, never guessed.

    use_ai_assist/ai_client: Phase 2 fallback. Off by default — the
    pipeline's core behavior never changes unless explicitly opted into.
    When on, any Fact the rule-based normalizer misses on is retried
    through ai_normalizer.py before being given up on; a missing ai_client
    or any AI-side failure silently yields the same result as
    use_ai_assist=False for that fact (see ai_normalizer.py's hard rules).
    """
    vuln_db = vuln_db or load_snapshot()
    kev_db = kev_db or load_kev()
    epss_db = epss_db or load_epss()
    exposure = exposure or {}
    if use_ai_assist and ai_client is not None:
        ai_cache = ai_cache or AINormalizerCache()

    ingest_result = ingest_files(jsonl_paths)

    candidates_by_asset: dict[str, list[CPECandidate]] = {}
    all_findings: list[Finding] = []
    for ip, asset in ingest_result.assets.items():
        candidates: list[CPECandidate] = []
        for fact in asset.facts:
            fact_candidates = normalize(fact)
            if not fact_candidates and use_ai_assist and ai_client is not None:
                raw_text = extract_raw_text(fact)
                if raw_text:
                    fact_candidates = propose_candidates(fact, raw_text, ai_client, cache=ai_cache)
            candidates.extend(fact_candidates)
        candidates_by_asset[ip] = candidates
        for c in candidates:
            all_findings.extend(match_candidate(ip, c, vuln_db))

    all_findings = dedup_findings(all_findings)
    all_findings = suppress_negated(all_findings, candidates_by_asset)

    for ip, asset in ingest_result.assets.items():
        composite = correlate_smb_patch(asset)
        if composite is not None:
            all_findings.append(composite)
    all_findings = dedup_findings(all_findings)  # composite finding could
                                                  # re-collide on re-runs

    for f in all_findings:
        exp = exposure.get(f.asset_ip, {})
        f.internet_facing = exp.get("internet_facing")
        f.auth_enforced = exp.get("auth_enforced")
        enrich_finding(f, vuln_db, kev_db, epss_db)

    return all_findings, ingest_result


def ab_evaluate(jsonl_paths: list[str | Path], ai_client: AIClient, **kwargs) -> dict:
    """Phase 2 exit criteria: recall gain from AI assist, with zero precision
    regression. Runs the SAME input through the pipeline twice — once
    rule-based-only (the control), once with AI assist on — and reports the
    diff. "Zero precision regression" is checked structurally, not just
    measured: every finding gained ONLY exists with AI assist on (recall_gain
    is a pure addition, never a removal-and-replacement) and every one of
    them is state=suspected (ai_normalizer.py's candidates are never
    source_confidence=authoritative, so matcher.py can never mark them
    confirmed — see matcher.py's rule) — a regression would mean either
    invariant broke, not just a number changing.
    """
    baseline, _ = run_pipeline(jsonl_paths, use_ai_assist=False, **kwargs)
    with_ai, _ = run_pipeline(jsonl_paths, use_ai_assist=True, ai_client=ai_client, **kwargs)

    baseline_ids = {f.finding_id for f in baseline}
    with_ai_ids = {f.finding_id for f in with_ai}
    gained = with_ai_ids - baseline_ids
    lost = baseline_ids - with_ai_ids  # any non-empty set here IS a regression

    gained_findings = [f for f in with_ai if f.finding_id in gained]
    non_suspected_ai = [f for f in gained_findings if f.state.value != "suspected"]

    return {
        "baseline_count": len(baseline),
        "with_ai_count": len(with_ai),
        "recall_gain": len(gained),
        "lost_findings": len(lost),  # must be 0 — AI assist should only add
        "precision_regression": bool(lost) or bool(non_suspected_ai),
        "gained_finding_ids": sorted(gained),
        "non_suspected_ai_findings": [f.finding_id for f in non_suspected_ai],
    }
