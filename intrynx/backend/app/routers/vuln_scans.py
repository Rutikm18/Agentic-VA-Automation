"""
Vuln scan API — Nessus + Nuclei launch, status polling, and enrichment.
"""
from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.models.asset import Asset
from app.models.engagement import Engagement
from app.models.enums import FindingStatus, ScanJobStatus, ScanJobType
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.utils.db import get_or_404
from app.vuln.enrichment import VulnEnrichmentService
from app.vuln.nessus import NessusScanner
from app.vuln.nuclei import NucleiScanner
from app.vuln.tasks import run_post_scan_enrichment

router = APIRouter(prefix="/engagements/{engagement_id}/scans", tags=["vuln-scans"])
logger = structlog.get_logger()


# ── Schemas ───────────────────────────────────────────────────────────────────

class NessusScanRequest(BaseModel):
    nessus_url: str = Field(..., description="https://nessus-host:8834")
    access_key: str
    secret_key: str
    policy_id: int = 1
    credentials: dict | None = None


class NucleiScanRequest(BaseModel):
    rate_limit: int = Field(default=150, ge=1, le=500)
    templates: list[str] = Field(default_factory=list)
    timeout_sec: int = Field(default=300, ge=30, le=3600)


class FindingImport(BaseModel):
    title: str
    severity: str
    description: str | None = None
    cve_ids: list[str] = []
    cvss_score: float | None = None
    evidence: dict | None = None
    asset_id: str | None = None


# ── POST /nessus — create + launch Nessus scan ────────────────────────────────

@router.post(
    "/nessus",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Launch a Nessus scan against all assets in this engagement",
)
async def launch_nessus_scan(
    engagement_id: uuid.UUID,
    body: NessusScanRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
):
    eng = await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)

    # Collect target IPs from assets
    assets_result = await db.execute(
        select(Asset.ip_address).where(
            Asset.engagement_id == engagement_id,
            Asset.ip_address.is_not(None),
        )
    )
    target_ips = [row[0] for row in assets_result.all()]
    if not target_ips:
        # Fall back to scope CIDRs
        target_ips = eng.scope_cidrs or []
    if not target_ips:
        raise HTTPException(400, "No targets found — import assets or set scope_cidrs first")

    scanner = NessusScanner()
    await scanner.authenticate(body.nessus_url, body.access_key, body.secret_key)
    scan_id = await scanner.create_scan(
        str(engagement_id), target_ips, body.policy_id, body.credentials
    )
    await scanner.launch_scan(scan_id)
    await scanner.close()

    # Create a ScanJob record
    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.vuln_scan,
        status=ScanJobStatus.running,
        result={"nessus_scan_id": scan_id, "target_count": len(target_ips)},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    logger.info("nessus.scan.launched_via_api", scan_id=scan_id, job_id=str(job.id))
    return {"job_id": str(job.id), "nessus_scan_id": scan_id, "targets": len(target_ips)}


# ── POST /nuclei — run Nuclei scan ────────────────────────────────────────────

@router.post(
    "/nuclei",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Launch a Nuclei template scan against engagement assets",
)
async def launch_nuclei_scan(
    engagement_id: uuid.UUID,
    body: NucleiScanRequest,
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
):
    eng = await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)

    # Collect targets with services for smart template selection
    assets_result = await db.execute(
        select(Asset).where(Asset.engagement_id == engagement_id)
    )
    assets = list(assets_result.scalars().all())
    targets = [a.ip_address for a in assets if a.ip_address]

    # Auto-select templates if none provided
    templates = body.templates or ["cves", "misconfigs"]

    # Create scan job and run in background
    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.vuln_scan,
        status=ScanJobStatus.pending,
        result={"scanner": "nuclei", "templates": templates, "targets": len(targets)},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(
        _run_nuclei_and_save,
        str(engagement_id), str(job.id), targets, templates, body.rate_limit, body.timeout_sec,
    )

    return {"job_id": str(job.id), "targets": len(targets), "templates": templates}


# ── GET /{job_id}/status ──────────────────────────────────────────────────────

@router.get("/{job_id}/status", summary="Poll scan job status")
async def scan_status(
    engagement_id: uuid.UUID,
    job_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.engagement_id == engagement_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, "Job not found")

    return {
        "job_id": str(job.id),
        "status": job.status.value,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "result": job.result,
    }


# ── POST /{job_id}/enrich — manual enrichment trigger ────────────────────────

@router.post("/{job_id}/enrich", status_code=status.HTTP_202_ACCEPTED,
             summary="Trigger post-scan CVE enrichment")
async def trigger_enrichment(
    engagement_id: uuid.UUID,
    job_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "analyst"])],
):
    await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)
    background_tasks.add_task(
        run_post_scan_enrichment, str(engagement_id), str(job_id)
    )
    return {"queued": True, "job_id": str(job_id)}


# ── POST /import — bulk import findings from external scanner ─────────────────

@router.post(
    "/import",
    status_code=status.HTTP_201_CREATED,
    summary="Bulk import raw findings from any scanner",
)
async def import_findings(
    engagement_id: uuid.UUID,
    body: list[FindingImport],
    db: DB,
    background_tasks: BackgroundTasks,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
):
    eng = await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)

    from app.models.enums import FindingSeverity
    from decimal import Decimal

    created = 0
    for item in body:
        try:
            sev = FindingSeverity(item.severity.lower())
        except ValueError:
            sev = FindingSeverity.info

        finding = Finding(
            engagement_id=engagement_id,
            asset_id=uuid.UUID(item.asset_id) if item.asset_id else None,
            title=item.title,
            description=item.description,
            severity=sev,
            status=FindingStatus.open,
            cve_ids=item.cve_ids or None,
            cvss_score=Decimal(str(item.cvss_score)) if item.cvss_score else None,
            evidence=item.evidence,
        )
        db.add(finding)
        created += 1

    await db.flush()

    # Auto-trigger enrichment
    job = ScanJob(
        engagement_id=engagement_id,
        job_type=ScanJobType.vuln_scan,
        status=ScanJobStatus.completed,
        result={"scanner": "import", "count": created},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(
        run_post_scan_enrichment, str(engagement_id), str(job.id)
    )

    return {"created": created, "enrichment_job_id": str(job.id)}


# ── helpers ───────────────────────────────────────────────────────────────────

async def _run_nuclei_and_save(
    engagement_id: str,
    job_id: str,
    targets: list[str],
    templates: list[str],
    rate_limit: int,
    timeout_sec: int,
) -> None:
    """Background task: run nuclei, persist findings, trigger enrichment."""
    from app.models.enums import FindingSeverity
    from decimal import Decimal
    import uuid as _uuid

    logger.info("nuclei.background.start", engagement=engagement_id, targets=len(targets))

    scanner = NucleiScanner()
    raw_findings = await scanner.run_scan(targets, templates, rate_limit, timeout_sec)

    async with AsyncSessionLocal() as db:
        from app.database import AsyncSessionLocal
        from app.models.scan_job import ScanJob
        from app.models.enums import ScanJobStatus
        from datetime import datetime, timezone

        created = 0
        for item in raw_findings:
            try:
                sev_str = (item.get("severity") or FindingSeverity.info)
                sev = sev_str if isinstance(sev_str, FindingSeverity) else FindingSeverity(str(sev_str).lower())
                finding = Finding(
                    engagement_id=_uuid.UUID(engagement_id),
                    severity=sev,
                    status=FindingStatus.open,
                    title=item.get("title", "Unknown"),
                    description=item.get("description"),
                    cve_ids=item.get("cve_ids") or None,
                    cvss_score=item.get("cvss_score"),
                    mitre_techniques=item.get("mitre_techniques"),
                    exploitable=item.get("exploitable", False),
                    evidence=item.get("evidence"),
                )
                db.add(finding)
                created += 1
            except Exception as exc:
                logger.warning("nuclei.finding.save_failed", error=str(exc))

        # Update job
        job_result = await db.execute(
            select(ScanJob).where(ScanJob.id == _uuid.UUID(job_id))
        )
        job = job_result.scalar_one_or_none()
        if job:
            job.status = ScanJobStatus.completed
            job.completed_at = datetime.now(timezone.utc)
            job.result = {**(job.result or {}), "findings_created": created}

        await db.commit()
        logger.info("nuclei.background.done", created=created)

    await run_post_scan_enrichment(engagement_id, job_id)
