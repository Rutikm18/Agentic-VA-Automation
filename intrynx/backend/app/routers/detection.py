"""
Detection validation API (DetectionValidationAPI).

POST /engagements/{id}/detection-validation/run        — run correlation job
GET  /engagements/{id}/detection-validation/results    — full result set
GET  /engagements/{id}/detection-validation/coverage   — ATT&CK coverage matrix
GET  /engagements/{id}/detection-validation/gaps       — missed techniques + Sigma
POST /engagements/{id}/detection-validation/siem-config — configure SIEM/EDR

The run correlates the engagement's attack_timeline against SIEM alerts and EDR
detections pulled from the configured providers, then persists DetectionResults.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.detection.correlator import AttackAction, DetectionCorrelator
from app.detection.edr import build_edr_engine
from app.detection.siem import build_siem_engine
from app.models.attack_timeline import AttackTimeline
from app.models.detection import DetectionResult
from app.models.detection_config import DetectionConfig
from app.models.engagement import Engagement
from app.utils.db import get_or_404
from app.models.enums import DetectionStatus, ScanJobStatus, ScanJobType
from app.models.scan_job import ScanJob

router = APIRouter(prefix="/engagements/{engagement_id}/detection-validation", tags=["detection-validation"])
logger = structlog.get_logger()


# ── Schemas ───────────────────────────────────────────────────────────────────

class SIEMConfigIn(BaseModel):
    siem_provider: str | None = Field(default=None, description="splunk | sentinel | elastic")
    siem_config: dict | None = None
    edr_provider: str | None = Field(default=None, description="crowdstrike | defender | sentinelone")
    edr_config: dict | None = None


class RunRequest(BaseModel):
    time_start: datetime | None = Field(default=None, description="Defaults to earliest attack action - 5m")
    time_end: datetime | None = Field(default=None, description="Defaults to latest attack action + 5m")
    window_minutes: int = Field(default=5, ge=1, le=60)


# ── POST /siem-config ─────────────────────────────────────────────────────────

@router.post("/siem-config", status_code=status.HTTP_200_OK,
             summary="Configure SIEM/EDR connection for this engagement")
async def configure_siem(
    engagement_id: uuid.UUID,
    body: SIEMConfigIn,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)

    cfg = (await db.execute(
        select(DetectionConfig).where(DetectionConfig.engagement_id == engagement_id)
    )).scalar_one_or_none()
    if cfg is None:
        cfg = DetectionConfig(engagement_id=engagement_id)
        db.add(cfg)

    if body.siem_provider is not None:
        cfg.siem_provider = body.siem_provider
        cfg.siem_config = body.siem_config
    if body.edr_provider is not None:
        cfg.edr_provider = body.edr_provider
        cfg.edr_config = body.edr_config
    await db.flush()

    # Never echo secrets — report only what is configured.
    return {
        "configured": True,
        "siem_provider": cfg.siem_provider,
        "edr_provider": cfg.edr_provider,
    }


# ── POST /run ─────────────────────────────────────────────────────────────────

@router.post("/run", status_code=status.HTTP_202_ACCEPTED,
             summary="Run detection correlation against SIEM/EDR")
async def run_validation(
    engagement_id: uuid.UUID,
    body: RunRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "analyst"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)

    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.detection,
        status=ScanJobStatus.pending,
        result={"stage": "queued"},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(
        _run_correlation,
        str(engagement_id), str(job.id),
        body.time_start.isoformat() if body.time_start else None,
        body.time_end.isoformat() if body.time_end else None,
        body.window_minutes,
    )
    return {"job_id": str(job.id), "status": "queued"}


# ── GET /results ──────────────────────────────────────────────────────────────

@router.get("/results", summary="Full detection result set")
async def get_results(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
    status_filter: DetectionStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    q = select(DetectionResult).where(DetectionResult.engagement_id == engagement_id)
    if status_filter:
        q = q.where(DetectionResult.detection_status == status_filter)
    q = q.order_by(DetectionResult.attack_timestamp.desc().nullslast())
    rows = (await db.execute(q.offset((page - 1) * page_size).limit(page_size))).scalars().all()
    return {"items": [_result_out(r) for r in rows]}


# ── GET /coverage ─────────────────────────────────────────────────────────────

@router.get("/coverage", summary="ATT&CK coverage matrix data")
async def get_coverage(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    rows = (await db.execute(
        select(DetectionResult).where(DetectionResult.engagement_id == engagement_id)
    )).scalars().all()

    total = len(rows)
    detected = sum(1 for r in rows if r.detection_status == DetectionStatus.detected)
    prevented = sum(1 for r in rows if r.detection_status == DetectionStatus.prevented)
    missed = sum(1 for r in rows if r.detection_status == DetectionStatus.missed)

    by_technique: dict[str, dict] = {}
    for r in rows:
        tech = r.mitre_technique or "unknown"
        b = by_technique.setdefault(tech, {"detected": 0, "prevented": 0, "missed": 0, "total": 0})
        b["total"] += 1
        b[r.detection_status.value] = b.get(r.detection_status.value, 0) + 1
    for b in by_technique.values():
        b["covered"] = b["detected"] + b["prevented"]
        b["status"] = "covered" if b["covered"] > 0 else "gap"

    return {
        "total_actions": total,
        "total_techniques": len(by_technique),
        "detected": detected,
        "prevented": prevented,
        "missed": missed,
        "coverage_pct": round(((detected + prevented) / total) * 100, 1) if total else 0.0,
        "matrix": [{"technique": k, **v} for k, v in sorted(by_technique.items())],
    }


# ── GET /gaps ─────────────────────────────────────────────────────────────────

@router.get("/gaps", summary="Missed techniques with recommended Sigma rules")
async def get_gaps(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)
    rows = (await db.execute(
        select(DetectionResult).where(
            DetectionResult.engagement_id == engagement_id,
            DetectionResult.detection_status == DetectionStatus.missed,
        )
    )).scalars().all()
    return {
        "gap_count": len(rows),
        "gaps": [
            {
                "mitre_technique": r.mitre_technique,
                "host": r.host_ip,
                "attack_timestamp": r.attack_timestamp,
                "recommended_sigma_rule": r.sigma_recommendation,
            }
            for r in rows
        ],
    }


# ── helpers ───────────────────────────────────────────────────────────────────



def _result_out(r: DetectionResult) -> dict:
    return {
        "id": str(r.id),
        "attack_action_id": str(r.attack_action_id) if r.attack_action_id else None,
        "mitre_technique": r.mitre_technique,
        "host": r.host_ip,
        "attack_timestamp": r.attack_timestamp,
        "status": r.detection_status.value,
        "siem_alerted": r.siem_alerted,
        "edr_alerted": r.edr_alerted,
        "detection_latency_sec": r.detection_latency_sec,
        "alert_ids": r.alert_ids,
        "has_sigma": bool(r.sigma_recommendation),
    }


async def _run_correlation(
    engagement_id: str,
    job_id: str,
    time_start_iso: str | None,
    time_end_iso: str | None,
    window_minutes: int,
) -> None:
    """Background task: pull SIEM/EDR telemetry, correlate, persist results."""
    from app.database import AsyncSessionLocal

    eng_uuid = uuid.UUID(engagement_id)
    logger.info("detection.run.start", engagement=engagement_id, job_id=job_id)

    async with AsyncSessionLocal() as db:
        await _set_job(db, job_id, ScanJobStatus.running, {"stage": "loading_timeline"})
        await db.commit()

        timeline = (await db.execute(
            select(AttackTimeline).where(AttackTimeline.engagement_id == eng_uuid)
            .order_by(AttackTimeline.timestamp.asc())
        )).scalars().all()

        if not timeline:
            await _set_job(db, job_id, ScanJobStatus.completed,
                           {"stage": "done", "actions": 0, "note": "no attack timeline"})
            await db.commit()
            return

        actions = [AttackAction(
            id=str(t.id), mitre_technique=t.mitre_technique, target_ip=t.target_ip,
            timestamp=t.timestamp, target_hostname=t.target_hostname, action=t.action,
            finding_id=str(t.finding_id) if t.finding_id else None,
            action_detail=t.action_detail or {},
        ) for t in timeline]

        # Time window: explicit, else derived from the timeline ± buffer.
        buffer = timedelta(minutes=window_minutes)
        ts = [a.timestamp for a in actions]
        time_start = datetime.fromisoformat(time_start_iso) if time_start_iso else (min(ts) - buffer)
        time_end = datetime.fromisoformat(time_end_iso) if time_end_iso else (max(ts) + buffer)

        cfg = (await db.execute(
            select(DetectionConfig).where(DetectionConfig.engagement_id == eng_uuid)
        )).scalar_one_or_none()

        siem_alerts, edr_detections = [], []
        if cfg and cfg.siem_provider:
            engine = build_siem_engine(cfg.siem_provider, cfg.siem_config or {})
            if engine:
                siem_alerts = await engine.query_alerts(time_start, time_end)
        if cfg and cfg.edr_provider:
            engine = build_edr_engine(cfg.edr_provider, cfg.edr_config or {})
            if engine:
                edr_detections = await engine.query_detections(time_start, time_end)

        correlator = DetectionCorrelator(window=buffer)
        results = correlator.correlate(actions, siem_alerts, edr_detections)
        coverage = correlator.compute_coverage(results)

        # Persist — replace prior results for this engagement.
        await db.execute(delete(DetectionResult).where(DetectionResult.engagement_id == eng_uuid))
        for r in results:
            db.add(DetectionResult(
                engagement_id=eng_uuid,
                attack_action_id=uuid.UUID(r.attack_action_id),
                finding_id=uuid.UUID(r.finding_id) if r.finding_id else None,
                mitre_technique=r.mitre_technique,
                host_ip=r.host,
                attack_timestamp=r.attack_timestamp,
                detection_status=r.status,
                siem_alerted=r.siem_alerted,
                edr_alerted=r.edr_alerted,
                detection_latency_sec=r.detection_latency_sec,
                alert_ids=r.alert_ids or None,
                sigma_recommendation=r.sigma_recommendation,
            ))

        await _set_job(db, job_id, ScanJobStatus.completed, {
            "stage": "done",
            "actions": len(actions),
            "siem_alerts": len(siem_alerts),
            "edr_detections": len(edr_detections),
            "coverage": {k: coverage[k] for k in
                         ("total_techniques", "detected", "prevented", "missed", "coverage_pct")},
        })
        await db.commit()
    logger.info("detection.run.done", engagement=engagement_id, results=len(results))


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
