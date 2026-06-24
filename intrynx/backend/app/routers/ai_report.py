"""
AI report API (AIReportAPI).

POST /engagements/{id}/ai-report/generate  — async generation, returns job_id
GET  /engagements/{id}/ai-report/status/{job_id}
GET  /engagements/{id}/ai-report/draft     — draft outputs pending human review
POST /engagements/{id}/ai-report/approve   — human approves (marks final)
POST /engagements/{id}/ai-report/reject    — human rejects + feedback, regenerates

Every generated section lands in ``llm_outputs`` as ``pending`` and is surfaced
through /draft for human review before it is considered part of the final report.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.models.asset import Asset
from app.models.attack_path import AttackPath
from app.models.detection import DetectionResult
from app.models.engagement import Engagement
from app.utils.db import get_or_404
from app.models.enums import ReviewStatus, ScanJobStatus, ScanJobType
from app.models.finding import Finding
from app.models.llm_output import LLMOutput
from app.models.scan_job import ScanJob

router = APIRouter(prefix="/engagements/{engagement_id}/ai-report", tags=["ai-report"])
logger = structlog.get_logger()


# ── Schemas ───────────────────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    include_technical: bool = Field(default=True, description="Per-finding technical write-ups")
    include_remediation: bool = Field(default=True, description="Per-finding remediation guides")
    max_findings: int = Field(default=10, ge=1, le=50, description="Cap on findings written up")


class ReviewRequest(BaseModel):
    output_ids: list[uuid.UUID] | None = Field(default=None, description="Specific outputs; omit for all pending")


class RejectRequest(ReviewRequest):
    feedback: str = Field(..., min_length=3)
    regenerate: bool = True


# ── POST /generate ────────────────────────────────────────────────────────────

@router.post("/generate", status_code=status.HTTP_202_ACCEPTED, summary="Generate an AI report")
async def generate_report(
    engagement_id: uuid.UUID,
    body: GenerateRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "analyst", "tester"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)

    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.ai_report,
        status=ScanJobStatus.pending,
        result={"stage": "queued"},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(
        _run_generation, str(engagement_id), str(job.id), body.model_dump()
    )
    return {"job_id": str(job.id), "status": "queued"}


# ── GET /status/{job_id} ──────────────────────────────────────────────────────

@router.get("/status/{job_id}", summary="Poll AI report generation status")
async def report_status(
    engagement_id: uuid.UUID,
    job_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    job = (await db.execute(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.engagement_id == engagement_id,
            ScanJob.job_type == ScanJobType.ai_report,
        )
    )).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "AI report job not found")
    return {
        "job_id": str(job.id),
        "status": job.status.value,
        "progress": (job.result or {}).get("progress"),
        "result": job.result,
    }


# ── GET /draft ────────────────────────────────────────────────────────────────

@router.get("/draft", summary="Draft report sections pending review")
async def get_draft(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
    review_status: ReviewStatus | None = Query(default=None, alias="status"),
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    q = select(LLMOutput).where(LLMOutput.engagement_id == engagement_id)
    q = q.where(LLMOutput.review_status == (review_status or ReviewStatus.pending))
    q = q.order_by(LLMOutput.output_type, LLMOutput.generated_at.desc())
    rows = (await db.execute(q)).scalars().all()
    return {"count": len(rows), "sections": [_output_out(r) for r in rows]}


# ── POST /approve ─────────────────────────────────────────────────────────────

@router.post("/approve", summary="Approve report sections (mark final)")
async def approve_report(
    engagement_id: uuid.UUID,
    body: ReviewRequest,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    rows = await _pending_outputs(db, engagement_id, body.output_ids)
    if not rows:
        raise HTTPException(404, "No pending sections to approve")
    for r in rows:
        r.review_status = ReviewStatus.approved
        r.reviewed_by = str(current_user.user_id)
        r.reviewed_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info("ai.report.approved", engagement=str(engagement_id), count=len(rows))
    return {"approved": len(rows), "ids": [str(r.id) for r in rows]}


# ── POST /reject ──────────────────────────────────────────────────────────────

@router.post("/reject", summary="Reject sections with feedback; trigger regeneration")
async def reject_report(
    engagement_id: uuid.UUID,
    body: RejectRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    rows = await _pending_outputs(db, engagement_id, body.output_ids)
    if not rows:
        raise HTTPException(404, "No pending sections to reject")

    rejected = []
    for r in rows:
        r.review_status = ReviewStatus.rejected
        r.reviewed_by = str(current_user.user_id)
        r.reviewed_at = datetime.now(timezone.utc)
        r.review_feedback = body.feedback
        rejected.append({"output_type": r.output_type, "finding_id": str(r.finding_id) if r.finding_id else None})
    await db.flush()

    if body.regenerate:
        background_tasks.add_task(
            _run_regeneration, str(engagement_id), rejected, body.feedback
        )
    logger.info("ai.report.rejected", engagement=str(engagement_id), count=len(rows), regenerate=body.regenerate)
    return {"rejected": len(rows), "regenerating": body.regenerate}


# ── helpers ───────────────────────────────────────────────────────────────────



async def _pending_outputs(db: AsyncSession, engagement_id: uuid.UUID, ids: list[uuid.UUID] | None):
    q = select(LLMOutput).where(
        LLMOutput.engagement_id == engagement_id,
        LLMOutput.review_status == ReviewStatus.pending,
    )
    if ids:
        q = q.where(LLMOutput.id.in_(ids))
    return list((await db.execute(q)).scalars().all())


def _output_out(r: LLMOutput) -> dict:
    return {
        "id": str(r.id),
        "output_type": r.output_type,
        "finding_id": str(r.finding_id) if r.finding_id else None,
        "model": r.model,
        "output": r.output,
        "review_status": r.review_status.value,
        "validation": r.validation,
        "generated_at": r.generated_at,
    }


async def _build_engagement_summary(db: AsyncSession, engagement_id: uuid.UUID, eng: Engagement) -> dict:
    sev_rows = (await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.engagement_id == engagement_id)
        .group_by(Finding.severity)
    )).all()
    severity_counts = {s.value if hasattr(s, "value") else str(s): c for s, c in sev_rows}
    total = sum(severity_counts.values())

    top_rows = (await db.execute(
        select(Finding).where(Finding.engagement_id == engagement_id)
        .order_by(Finding.risk_score.desc().nullslast()).limit(3)
    )).scalars().all()
    top_critical = [
        {
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "cve_ids": f.cve_ids or [],
            "cvss_score": float(f.cvss_score) if f.cvss_score is not None else None,
            "risk_score": float(f.risk_score) if f.risk_score is not None else None,
        }
        for f in top_rows
    ]

    path_rows = (await db.execute(
        select(AttackPath).where(AttackPath.engagement_id == engagement_id)
    )).scalars().all()
    shortest = min((len(p.path_nodes or []) - 1 for p in path_rows if p.path_nodes), default=None)

    det_rows = (await db.execute(
        select(DetectionResult.detection_status, func.count(DetectionResult.id))
        .where(DetectionResult.engagement_id == engagement_id)
        .group_by(DetectionResult.detection_status)
    )).all()
    det = {s.value if hasattr(s, "value") else str(s): c for s, c in det_rows}
    det_total = sum(det.values())
    covered = det.get("detected", 0) + det.get("prevented", 0)
    coverage_pct = round((covered / det_total) * 100, 1) if det_total else None

    return {
        "engagement_id": str(engagement_id),
        "engagement_name": eng.name,
        "total_findings": total,
        "severity_counts": severity_counts,
        "top_critical": top_critical,
        "attack_path_count": len(path_rows),
        "shortest_path_hops": shortest,
        "detection_coverage_pct": coverage_pct,
    }


async def _run_generation(engagement_id: str, job_id: str, opts: dict) -> None:
    """Background task: build the summary, generate every section, persist as pending."""
    from app.ai.llm_report import LLMReportGenerator, LLMUnavailableError
    from app.database import AsyncSessionLocal

    eng_uuid = uuid.UUID(engagement_id)
    async with AsyncSessionLocal() as db:
        await _set_job(db, job_id, ScanJobStatus.running, {"stage": "summarizing", "progress": 0})
        await db.commit()

        eng = (await db.execute(select(Engagement).where(Engagement.id == eng_uuid))).scalar_one_or_none()
        if not eng:
            await _set_job(db, job_id, ScanJobStatus.failed, {"error": "engagement gone"})
            await db.commit()
            return

        gen = LLMReportGenerator(db)
        if not gen.available:
            await _set_job(db, job_id, ScanJobStatus.failed,
                           {"error": "LLM not configured (set ANTHROPIC_API_KEY)"})
            await db.commit()
            return

        summary = await _build_engagement_summary(db, eng_uuid, eng)
        sections = 0
        try:
            await gen.generate_executive_summary(summary)
            sections += 1
            await _set_job(db, job_id, ScanJobStatus.running, {"stage": "findings", "progress": 25})
            await db.flush()

            if opts.get("include_technical") or opts.get("include_remediation"):
                findings = (await db.execute(
                    select(Finding).where(Finding.engagement_id == eng_uuid)
                    .order_by(Finding.risk_score.desc().nullslast())
                    .limit(opts.get("max_findings", 10))
                )).scalars().all()
                for f in findings:
                    asset = None
                    if f.asset_id:
                        asset = (await db.execute(select(Asset).where(Asset.id == f.asset_id))).scalar_one_or_none()
                    if opts.get("include_technical"):
                        await gen.generate_technical_finding(f, asset, (f.evidence or {}).get("stdout_snippet", ""))
                        sections += 1
                    if opts.get("include_remediation"):
                        await gen.generate_remediation_steps(f)
                        sections += 1
        except LLMUnavailableError as exc:
            await _set_job(db, job_id, ScanJobStatus.failed, {"error": str(exc), "sections": sections})
            await db.commit()
            return

        await _set_job(db, job_id, ScanJobStatus.completed,
                       {"stage": "done", "progress": 100, "sections": sections})
        await db.commit()
    logger.info("ai.report.generated", engagement=engagement_id, sections=sections)


async def _run_regeneration(engagement_id: str, rejected: list[dict], feedback: str) -> None:
    """Background task: regenerate rejected sections after human feedback."""
    from app.ai.llm_report import LLMReportGenerator, LLMUnavailableError
    from app.database import AsyncSessionLocal

    eng_uuid = uuid.UUID(engagement_id)
    async with AsyncSessionLocal() as db:
        eng = (await db.execute(select(Engagement).where(Engagement.id == eng_uuid))).scalar_one_or_none()
        if not eng:
            return
        gen = LLMReportGenerator(db)
        if not gen.available:
            logger.warning("ai.report.regen_skipped", reason="llm unavailable")
            return
        try:
            for item in rejected:
                otype = item["output_type"]
                if otype == "executive_summary":
                    await gen.generate_executive_summary(await _build_engagement_summary(db, eng_uuid, eng))
                elif otype in ("technical_finding", "remediation_steps") and item.get("finding_id"):
                    f = (await db.execute(
                        select(Finding).where(Finding.id == uuid.UUID(item["finding_id"]))
                    )).scalar_one_or_none()
                    if not f:
                        continue
                    asset = None
                    if f.asset_id:
                        asset = (await db.execute(select(Asset).where(Asset.id == f.asset_id))).scalar_one_or_none()
                    if otype == "technical_finding":
                        await gen.generate_technical_finding(f, asset, (f.evidence or {}).get("stdout_snippet", ""))
                    else:
                        await gen.generate_remediation_steps(f)
                # detection_rule_explanation regeneration needs the original sigma input,
                # which isn't stored on the output row — skipped intentionally.
            await db.commit()
        except LLMUnavailableError as exc:
            logger.warning("ai.report.regen_failed", error=str(exc))


async def _set_job(db: AsyncSession, job_id: str, status_value: ScanJobStatus, result_patch: dict) -> None:
    job = (await db.execute(select(ScanJob).where(ScanJob.id == uuid.UUID(job_id)))).scalar_one_or_none()
    if not job:
        return
    job.status = status_value
    if status_value == ScanJobStatus.running and job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    if status_value in (ScanJobStatus.completed, ScanJobStatus.failed):
        job.completed_at = datetime.now(timezone.utc)
    job.result = {**(job.result or {}), **result_patch}
