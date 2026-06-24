"""
enrichment.py — join CVSS + KEV + EPSS onto a Finding, compute a priority
tier.

PRIORITY IS A TIER LABEL WITH VISIBLE INPUTS, NOT A COLLAPSED SCORE — per
spec: "Keep the inputs visible, don't collapse to one opaque number." A
Finding's cvss_score/epss_score/kev fields all stay independently readable;
`priority` is a small, explainable ordering on top of them
(KEV-listed > high-EPSS > raw-CVSS), and `notes` records WHY a tier was
assigned, not just what it is.

Exposure context (internet_facing, auth_enforced) is taken as given on the
Finding (the caller — pipeline.py — is responsible for setting these from
the Asset's facts, e.g. mcp_ai_scanner's auth_enforced field, db_scanner's
auth_required) — this module only reasons about it, never derives it from
raw scan data itself.
"""
from __future__ import annotations

from cvss import base_score
from enrichment_db import EpssDB, KevDB
from models import Finding
from vuln_db import VulnDB

# EPSS thresholds: FIRST.org's own guidance treats >0.5 as "high probability
# of exploitation in the wild within 30 days" and >0.1 as notably elevated —
# these aren't arbitrary cutoffs invented here.
_EPSS_HIGH = 0.5
_EPSS_ELEVATED = 0.1


def enrich_finding(finding: Finding, vuln_db: VulnDB, kev_db: KevDB, epss_db: EpssDB) -> Finding:
    """Mutates and returns `finding` with cvss_score/cvss_vector/epss_score/
    kev/priority populated. Safe to call on a Finding more than once
    (idempotent — re-deriving the same inputs produces the same outputs).
    """
    vector = vuln_db.get_cvss_vector(finding.cve_id)
    if vector:
        finding.cvss_vector = vector
        finding.cvss_score = base_score(vector)

    finding.kev = kev_db.is_kev(finding.cve_id)

    epss = epss_db.get(finding.cve_id)
    finding.epss_score = epss["epss"] if epss else None

    finding.priority, reason = _compute_priority(finding)
    finding.notes.append(reason)
    return finding


def _compute_priority(finding: Finding) -> tuple[str, str]:
    """Returns (tier, human-readable reason). Order of precedence, per spec:
    KEV-listed > high-EPSS > raw-CVSS — each checked in that order, first
    match wins, so the reason always names the actual deciding factor.
    """
    unauth_reachable = finding.auth_enforced is False and finding.internet_facing is True

    if finding.kev and unauth_reachable:
        return "critical", (
            "CISA KEV-listed (actively exploited in the wild) AND reachable "
            "without authentication from outside — top of stack")
    if finding.kev:
        return "critical", "CISA KEV-listed (actively exploited in the wild)"

    if finding.epss_score is not None and finding.epss_score >= _EPSS_HIGH:
        return "critical", f"EPSS {finding.epss_score:.2f} — high probability of exploitation"
    if finding.epss_score is not None and finding.epss_score >= _EPSS_ELEVATED:
        return "high", f"EPSS {finding.epss_score:.2f} — elevated exploitation probability"

    if finding.cvss_score is not None:
        if finding.cvss_score >= 9.0:
            return "critical", f"CVSS {finding.cvss_score} (critical)"
        if finding.cvss_score >= 7.0:
            return "high", f"CVSS {finding.cvss_score} (high)"
        if finding.cvss_score >= 4.0:
            return "medium", f"CVSS {finding.cvss_score} (medium)"
        return "low", f"CVSS {finding.cvss_score} (low)"

    return "unknown", "no CVSS/EPSS/KEV data available for this CVE in the pinned snapshot"
