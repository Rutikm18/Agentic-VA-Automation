"""
HallucinationGuard — post-generation validation of LLM report text against the
ground-truth engagement data.

LLMs can invent CVE IDs, misquote CVSS scores, or emit dangerous shell commands.
This guard cross-checks generated text against the actual findings and flags
anything unverifiable or destructive *before* a human reviews it. It does not
edit the text — it produces a verdict the reviewer (and the API) can act on.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger()

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# CVSS-looking decimals 0.0–10.0 (avoids matching arbitrary numbers via context words).
_CVSS_RE = re.compile(r"(?:CVSS[^\d]{0,12})(\d{1,2}(?:\.\d)?)", re.IGNORECASE)

# Destructive / dangerous command patterns that should never appear in a
# remediation guide (which should describe fixes, not destruction).
_DESTRUCTIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\brm\s+-rf?\b", re.I),
    re.compile(r"\bmkfs\.", re.I),
    re.compile(r"\bdd\s+if=.*\bof=/dev/", re.I),
    re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", re.I),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.I),
    re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.I),  # unbounded DELETE
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;", re.I),       # fork bomb
    re.compile(r">\s*/dev/sda", re.I),
    re.compile(r"\bchmod\s+-R\s+777\s+/\b", re.I),
    re.compile(r"\bshutdown\b|\breboot\b|\bhalt\b", re.I),
    re.compile(r"\bformat\s+[A-Za-z]:", re.I),
    re.compile(r"Remove-Item.+-Recurse.+-Force", re.I),
]


class HallucinationGuard:

    # ── validate_cve_claims ───────────────────────────────────────────────────────

    def validate_cve_claims(self, text: str, actual_cve_ids: list[str]) -> dict[str, Any]:
        """Flag any CVE ID mentioned in ``text`` that isn't in the real finding set."""
        actual = {c.upper() for c in (actual_cve_ids or [])}
        mentioned = {m.upper() for m in _CVE_RE.findall(text or "")}
        invented = sorted(mentioned - actual)
        issues = [f"Unverified CVE referenced (not in finding data): {c}" for c in invented]
        return {
            "valid": not invented,
            "issues": issues,
            "mentioned": sorted(mentioned),
            "invented": invented,
        }

    # ── validate_cvss_scores ──────────────────────────────────────────────────────

    def validate_cvss_scores(self, text: str, actual_scores: dict[str, float]) -> dict[str, Any]:
        """
        Flag CVSS scores in the text that don't match any real score.

        ``actual_scores`` maps an identifier (CVE or finding id) → score. We treat
        a stated score as valid if it matches *any* real score within 0.1 (the
        text may not name which finding the score belongs to).
        """
        real = {round(float(v), 1) for v in (actual_scores or {}).values() if v is not None}
        stated = []
        for m in _CVSS_RE.findall(text or ""):
            try:
                val = round(float(m), 1)
                if 0.0 <= val <= 10.0:
                    stated.append(val)
            except ValueError:
                continue

        mismatched = sorted({s for s in stated if not any(abs(s - r) <= 0.1 for r in real)})
        issues = [f"CVSS score {s} stated in report does not match any finding score" for s in mismatched]
        return {
            "valid": not mismatched,
            "issues": issues,
            "stated": stated,
            "mismatched": mismatched,
        }

    # ── validate_remediation_commands ─────────────────────────────────────────────

    def validate_remediation_commands(self, text: str) -> dict[str, Any]:
        """Flag destructive-looking commands that shouldn't appear in a fix guide."""
        flagged = []
        for pattern in _DESTRUCTIVE_PATTERNS:
            m = pattern.search(text or "")
            if m:
                flagged.append(m.group(0).strip())
        issues = [f"Potentially destructive command in remediation text: '{c}'" for c in flagged]
        return {"valid": not flagged, "issues": issues, "flagged_commands": flagged}

    # ── aggregate ──────────────────────────────────────────────────────────────────

    def validate(
        self,
        text: str,
        *,
        actual_cve_ids: list[str] | None = None,
        actual_scores: dict[str, float] | None = None,
        check_commands: bool = True,
    ) -> dict[str, Any]:
        """
        Run all relevant checks and return a combined verdict:
        ``{valid, issues, confidence}`` plus the per-check detail.

        ``confidence`` is 1.0 with no issues and degrades 0.2 per issue (floored
        at 0.0) — a quick signal for the reviewer, not a calibrated probability.
        """
        cve = self.validate_cve_claims(text, actual_cve_ids or [])
        cvss = self.validate_cvss_scores(text, actual_scores or {})
        cmds = self.validate_remediation_commands(text) if check_commands else {"valid": True, "issues": []}

        issues = [*cve["issues"], *cvss["issues"], *cmds["issues"]]
        confidence = round(max(0.0, 1.0 - 0.2 * len(issues)), 2)
        verdict = {
            "valid": not issues,
            "issues": issues,
            "confidence": confidence,
            "checks": {"cve": cve, "cvss": cvss, "commands": cmds},
        }
        if issues:
            logger.warning("ai.hallucination.flagged", issue_count=len(issues))
        return verdict
