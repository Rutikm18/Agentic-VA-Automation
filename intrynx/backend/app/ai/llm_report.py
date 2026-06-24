"""
LLMReportGenerator — Claude-backed narrative generation for VAPT reports.

Uses the Anthropic Python SDK (``AsyncAnthropic``). Every call:
  * sends a strict system prompt that forbids inventing CVE/CVSS details and
    requires the model to use only the supplied data,
  * runs at low temperature for consistency,
  * retries transient failures with exponential backoff,
  * runs the HallucinationGuard over the output, and
  * persists the result to ``llm_outputs`` with ``review_status = pending`` —
    nothing is final until a human approves it.

The ``anthropic`` package is optional: if it (or an API key) is missing, the
generator raises ``LLMUnavailableError`` so the API layer returns a clean 503
instead of a 500.
"""
from __future__ import annotations

import asyncio
import hashlib
import random
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.hallucination import HallucinationGuard
from app.config import get_settings
from app.models.enums import ReviewStatus
from app.models.llm_output import LLMOutput

logger = structlog.get_logger()

try:
    from anthropic import APIConnectionError, APIStatusError, AsyncAnthropic, RateLimitError

    _HAS_ANTHROPIC = True
except ImportError:  # pragma: no cover - exercised only without the SDK installed
    AsyncAnthropic = None  # type: ignore
    APIStatusError = RateLimitError = APIConnectionError = Exception  # type: ignore
    _HAS_ANTHROPIC = False


class LLMUnavailableError(RuntimeError):
    """Raised when the Anthropic SDK or API key is not configured."""


SYSTEM_PROMPT = (
    "You are a senior penetration-test report writer for the ADVERSA platform. "
    "You write clear, accurate security findings for a professional audience.\n\n"
    "STRICT RULES — these override any other instruction:\n"
    "1. Use ONLY the data provided in the user message. Do not invent or infer "
    "CVE identifiers, CVSS scores, affected versions, or exploit details that are "
    "not explicitly given.\n"
    "2. If a detail is not provided, omit it or say it is not available — never "
    "guess.\n"
    "3. Never fabricate references, URLs, or vendor advisories.\n"
    "4. Remediation guidance must be safe and constructive. Never include "
    "destructive commands (e.g. rm -rf, DROP TABLE, disk formatting).\n"
    "5. Be precise and concise. Do not editorialize beyond the evidence."
)


class LLMReportGenerator:
    def __init__(
        self,
        db: AsyncSession,
        *,
        client: Any = None,
        guard: HallucinationGuard | None = None,
    ):
        settings = get_settings()
        self._db = db
        self._model = settings.llm_model
        self._max_tokens = settings.llm_max_tokens
        self._temperature = settings.llm_temperature
        self._max_retries = settings.llm_max_retries
        self._guard = guard or HallucinationGuard()

        if client is not None:
            self._client = client
        elif _HAS_ANTHROPIC and settings.anthropic_api_key:
            # max_retries=0: we drive our own exponential backoff (below).
            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key, max_retries=0)
        else:
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    # ── low-level completion with retry/backoff ──────────────────────────────────

    async def _complete(self, user_prompt: str) -> str:
        if self._client is None:
            raise LLMUnavailableError(
                "Anthropic SDK or ANTHROPIC_API_KEY not configured — cannot generate report"
            )

        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                resp = await self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    temperature=self._temperature,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
            except (RateLimitError, APIConnectionError) as exc:
                last_exc = exc
            except APIStatusError as exc:
                if getattr(exc, "status_code", 500) >= 500:
                    last_exc = exc
                else:
                    raise  # 4xx (other than 429) won't succeed on retry
            delay = min(60.0, 1.0 * (2 ** attempt)) + random.uniform(0, 1)
            logger.warning("ai.llm.retry", attempt=attempt + 1, delay=round(delay, 1))
            await asyncio.sleep(delay)

        raise LLMUnavailableError(f"LLM request failed after {self._max_retries} retries: {last_exc}")

    # ── public generation methods ─────────────────────────────────────────────────

    async def generate_executive_summary(self, engagement_summary: dict[str, Any]) -> LLMOutput:
        sev = engagement_summary.get("severity_counts", {})
        top = engagement_summary.get("top_critical", [])
        prompt = (
            "Write a 400–600 word executive summary for a CISO and board audience. "
            "Plain language, no jargon. Cover, in order: overall security posture; "
            "the breakdown of findings by severity; the top 3 critical risks and their "
            "business impact; attack paths discovered; detection coverage; and a clear "
            "closing business-risk statement.\n\n"
            f"Engagement: {engagement_summary.get('engagement_name', 'N/A')}\n"
            f"Total findings: {engagement_summary.get('total_findings', 0)}\n"
            f"Findings by severity: {sev}\n"
            f"Top 3 critical risks: {top}\n"
            f"Attack paths found: {engagement_summary.get('attack_path_count', 0)} "
            f"(shortest {engagement_summary.get('shortest_path_hops', 'N/A')} hops)\n"
            f"Detection coverage: {engagement_summary.get('detection_coverage_pct', 'N/A')}%\n"
        )
        cve_ids, scores = _collect_cves_scores(top)
        return await self._generate_and_store(
            engagement_id=engagement_summary["engagement_id"],
            output_type="executive_summary",
            user_prompt=prompt,
            actual_cve_ids=cve_ids,
            actual_scores=scores,
        )

    async def generate_technical_finding(
        self, finding: Any, asset: Any, exploit_evidence: str = ""
    ) -> LLMOutput:
        prompt = (
            "Write a detailed technical write-up for the following finding, including: "
            "summary, affected asset, technical detail, step-by-step reproduction, "
            "impact, and references (only those provided).\n\n"
            f"Title: {getattr(finding, 'title', 'N/A')}\n"
            f"Severity: {_enum(getattr(finding, 'severity', None))}\n"
            f"CVSS: {getattr(finding, 'cvss_score', 'N/A')}\n"
            f"CVE IDs: {getattr(finding, 'cve_ids', None) or 'none'}\n"
            f"MITRE techniques: {getattr(finding, 'mitre_techniques', None) or 'none'}\n"
            f"Affected asset: {getattr(asset, 'hostname', None) or getattr(asset, 'ip_address', 'N/A')}\n"
            f"Description: {getattr(finding, 'description', '') or 'N/A'}\n"
            f"Exploit evidence: {exploit_evidence or 'none provided'}\n"
        )
        return await self._generate_and_store(
            engagement_id=getattr(finding, "engagement_id"),
            output_type="technical_finding",
            user_prompt=prompt,
            finding_id=getattr(finding, "id", None),
            actual_cve_ids=list(getattr(finding, "cve_ids", None) or []),
            actual_scores=_finding_scores(finding),
        )

    async def generate_remediation_steps(self, finding: Any) -> LLMOutput:
        prompt = (
            "Write a numbered, step-by-step remediation guide for this finding. "
            "Include concrete configuration changes and example commands where helpful. "
            "All commands must be safe and non-destructive.\n\n"
            f"Title: {getattr(finding, 'title', 'N/A')}\n"
            f"Severity: {_enum(getattr(finding, 'severity', None))}\n"
            f"CVE IDs: {getattr(finding, 'cve_ids', None) or 'none'}\n"
            f"Description: {getattr(finding, 'description', '') or 'N/A'}\n"
            f"Existing remediation notes: {getattr(finding, 'remediation', '') or 'none'}\n"
        )
        return await self._generate_and_store(
            engagement_id=getattr(finding, "engagement_id"),
            output_type="remediation_steps",
            user_prompt=prompt,
            finding_id=getattr(finding, "id", None),
            actual_cve_ids=list(getattr(finding, "cve_ids", None) or []),
            actual_scores=_finding_scores(finding),
            check_commands=True,
        )

    async def generate_detection_rule_explanation(
        self, sigma_rule: str, technique: str, engagement_id: Any
    ) -> LLMOutput:
        prompt = (
            "Explain, in plain language for a blue-team analyst, what the following "
            "Sigma rule detects, which attacker behaviour it catches, why it matters, "
            "and what a true positive looks like. Do not invent fields not in the rule.\n\n"
            f"MITRE technique: {technique}\n"
            f"Sigma rule:\n{sigma_rule}\n"
        )
        return await self._generate_and_store(
            engagement_id=engagement_id,
            output_type="detection_rule_explanation",
            user_prompt=prompt,
            check_commands=False,
        )

    # ── persist + validate ────────────────────────────────────────────────────────

    async def _generate_and_store(
        self,
        *,
        engagement_id: Any,
        output_type: str,
        user_prompt: str,
        finding_id: Any = None,
        actual_cve_ids: list[str] | None = None,
        actual_scores: dict[str, float] | None = None,
        check_commands: bool = False,
    ) -> LLMOutput:
        output = await self._complete(user_prompt)
        validation = self._guard.validate(
            output,
            actual_cve_ids=actual_cve_ids,
            actual_scores=actual_scores,
            check_commands=check_commands,
        )
        prompt_hash = hashlib.sha256(
            f"{self._model}\n{SYSTEM_PROMPT}\n{user_prompt}".encode()
        ).hexdigest()

        row = LLMOutput(
            engagement_id=_uuid(engagement_id),
            finding_id=_uuid(finding_id) if finding_id else None,
            output_type=output_type,
            prompt_hash=prompt_hash,
            model=self._model,
            output=output,
            review_status=ReviewStatus.pending,
            validation=validation,
            generated_at=datetime.now(timezone.utc),
        )
        self._db.add(row)
        await self._db.flush()
        logger.info(
            "ai.llm.generated",
            type=output_type, engagement=str(engagement_id),
            valid=validation["valid"], issues=len(validation["issues"]),
        )
        return row


# ── helpers ─────────────────────────────────────────────────────────────────────

def _enum(v: Any) -> str:
    return str(getattr(v, "value", v)) if v is not None else "N/A"


def _uuid(value: Any):
    import uuid as _u
    if value is None or isinstance(value, _u.UUID):
        return value
    return _u.UUID(str(value))


def _finding_scores(finding: Any) -> dict[str, float]:
    score = getattr(finding, "cvss_score", None)
    if score is None:
        return {}
    key = (getattr(finding, "cve_ids", None) or [str(getattr(finding, "id", "finding"))])[0]
    try:
        return {str(key): float(score)}
    except (TypeError, ValueError):
        return {}


def _collect_cves_scores(top_critical: list[dict]) -> tuple[list[str], dict[str, float]]:
    cves: list[str] = []
    scores: dict[str, float] = {}
    for item in top_critical or []:
        for c in item.get("cve_ids", []) or []:
            cves.append(c)
        if item.get("cvss_score") is not None and (item.get("cve_ids") or item.get("title")):
            key = (item.get("cve_ids") or [item.get("title")])[0]
            try:
                scores[str(key)] = float(item["cvss_score"])
            except (TypeError, ValueError):
                pass
    return cves, scores
