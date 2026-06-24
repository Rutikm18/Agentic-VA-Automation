"""
Active Directory assessment API.

POST /engagements/{id}/ad/assess        — launch full AD assessment (background)
GET  /engagements/{id}/ad/{job_id}/status — poll assessment job + summary

Findings produced by the assessment are persisted into the shared ``findings``
table and surfaced through the existing /findings endpoints.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.models.engagement import Engagement
from app.utils.db import get_or_404
from app.models.enums import FindingSeverity, FindingStatus, ScanJobStatus, ScanJobType
from app.models.finding import Finding
from app.models.scan_job import ScanJob

router = APIRouter(prefix="/engagements/{engagement_id}/ad", tags=["active-directory"])
logger = structlog.get_logger()


# ── Schemas ───────────────────────────────────────────────────────────────────

class Neo4jConfig(BaseModel):
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str


class ADAssessRequest(BaseModel):
    dc_ip: str = Field(..., description="Domain Controller IP")
    domain: str = Field(..., description="AD domain, e.g. corp.local")
    username: str
    password: str
    use_kerberos: bool = False
    capture_hashes: bool = Field(
        default=False,
        description="Capture Kerberoast/AS-REP hashes as evidence (never cracked).",
    )
    run_bloodhound: bool = False
    ca_config: dict | None = Field(default=None, description="AD CS config for ESC8 check")
    neo4j: Neo4jConfig | None = None


# ── POST /assess ───────────────────────────────────────────────────────────────

@router.post(
    "/assess",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Launch an Active Directory assessment against a domain controller",
)
async def launch_ad_assessment(
    engagement_id: uuid.UUID,
    body: ADAssessRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
):
    await get_or_404(db, Engagement, db, engagement_id, current_user.tenant_id)

    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.ad_enum,
        status=ScanJobStatus.pending,
        result={"dc_ip": body.dc_ip, "domain": body.domain},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(
        _run_ad_assessment_and_save,
        str(engagement_id),
        str(job.id),
        body.model_dump(),
        str(current_user.user_id),
    )

    logger.info("ad.assess.queued", engagement=str(engagement_id), job_id=str(job.id),
                domain=body.domain)
    return {"job_id": str(job.id), "domain": body.domain, "dc_ip": body.dc_ip}


# ── GET /{job_id}/status ─────────────────────────────────────────────────────────

@router.get("/{job_id}/status", summary="Poll AD assessment job status + summary")
async def ad_assessment_status(
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
            ScanJob.job_type == ScanJobType.ad_enum,
        )
    )).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "AD assessment job not found")

    return {
        "job_id": str(job.id),
        "status": job.status.value,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "result": job.result,
    }


# ── helpers ───────────────────────────────────────────────────────────────────



async def _run_ad_assessment_and_save(
    engagement_id: str,
    job_id: str,
    params: dict,
    actor_id: str,
) -> None:
    """Background task: run the AD assessment and persist findings + job result."""
    from app.ad.orchestrator import ADAssessmentRunner
    from app.database import AsyncSessionLocal

    logger.info("ad.assess.background.start", engagement=engagement_id, domain=params.get("domain"))

    # Mark running.
    async with AsyncSessionLocal() as db:
        await _set_job_status(db, job_id, ScanJobStatus.running, started=True)
        await db.commit()

    runner = ADAssessmentRunner()
    neo4j = params.get("neo4j")
    try:
        outcome = await runner.run(
            params["dc_ip"], params["domain"], params["username"], params["password"],
            use_kerberos=params.get("use_kerberos", False),
            capture_hashes=params.get("capture_hashes", False),
            run_bloodhound=params.get("run_bloodhound", False),
            ca_config=params.get("ca_config"),
            neo4j=neo4j,
        )
    except Exception as exc:
        logger.error("ad.assess.background.failed", error=str(exc), exc_info=exc)
        async with AsyncSessionLocal() as db:
            await _set_job_status(db, job_id, ScanJobStatus.failed,
                                  result_patch={"error": str(exc)})
            await db.commit()
        return

    created = 0
    async with AsyncSessionLocal() as db:
        for item in outcome["findings"]:
            try:
                sev = item.get("severity")
                sev = sev if isinstance(sev, FindingSeverity) else FindingSeverity(str(sev).lower())
                db.add(Finding(
                    engagement_id=uuid.UUID(engagement_id),
                    severity=sev,
                    status=FindingStatus.open,
                    title=item.get("title", "AD finding"),
                    description=item.get("description"),
                    cve_ids=item.get("cve_ids"),
                    mitre_techniques=item.get("mitre_techniques"),
                    exploitable=item.get("exploitable", False),
                    exploit_validated=item.get("exploit_validated", False),
                    remediation=item.get("remediation"),
                    evidence=item.get("evidence"),
                ))
                created += 1
            except Exception as exc:
                logger.warning("ad.assess.finding.save_failed", error=str(exc))

        await _set_job_status(
            db, job_id, ScanJobStatus.completed,
            result_patch={
                "findings_created": created,
                "stats": outcome["stats"],
                "errors": outcome["errors"],
            },
        )
        await db.commit()

    logger.info("ad.assess.background.done", engagement=engagement_id, findings=created)


async def _set_job_status(
    db: AsyncSession,
    job_id: str,
    status_value: ScanJobStatus,
    *,
    started: bool = False,
    result_patch: dict | None = None,
) -> None:
    job = (await db.execute(
        select(ScanJob).where(ScanJob.id == uuid.UUID(job_id))
    )).scalar_one_or_none()
    if not job:
        return
    job.status = status_value
    if started:
        job.started_at = datetime.now(timezone.utc)
    if status_value in (ScanJobStatus.completed, ScanJobStatus.failed):
        job.completed_at = datetime.now(timezone.utc)
    if result_patch:
        job.result = {**(job.result or {}), **result_patch}
