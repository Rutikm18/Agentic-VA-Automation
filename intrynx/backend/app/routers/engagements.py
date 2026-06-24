import json
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.models.asset import Asset
from app.models.engagement import Engagement
from app.models.enums import EngagementStatus, FindingSeverity, FindingStatus
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.schemas.common import PaginatedResponse, paginate
from app.schemas.asset import AssetIn, AssetOut, BulkAssetImportResult
from app.schemas.engagement import (
    EngagementCreate, EngagementDetail, EngagementOut, FindingSummary
)
from app.utils.csv_parser import parse_csv_assets
from app.utils.db import get_or_404
from app.utils.pagination import paginate_query

router = APIRouter(prefix="/engagements", tags=["engagements"])
logger = structlog.get_logger()


# ── POST /engagements ─────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=EngagementOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new engagement",
)
async def create_engagement(
    body: EngagementCreate,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager"])],
):
    eng = Engagement(
        tenant_id=current_user.tenant_id,
        **body.model_dump(),
    )
    db.add(eng)
    await db.flush()
    await db.refresh(eng)
    logger.info("engagement.created", id=str(eng.id), tenant=str(current_user.tenant_id))
    return eng


# ── GET /engagements ──────────────────────────────────────────────────────────

@router.get("", response_model=PaginatedResponse[EngagementOut], summary="List engagements")
async def list_engagements(
    db: DB,
    current_user: AuthUser,
    status_filter: EngagementStatus | None = Query(default=None, alias="status"),
    start_after: str | None = Query(default=None),
    start_before: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    q = select(Engagement).where(Engagement.tenant_id == current_user.tenant_id)

    if status_filter:
        q = q.where(Engagement.status == status_filter)
    if start_after:
        q = q.where(Engagement.start_time >= start_after)
    if start_before:
        q = q.where(Engagement.start_time <= start_before)

    q = q.order_by(Engagement.created_at.desc())
    items, total = await paginate_query(db, q, page, page_size)
    return paginate(items, total, page, page_size)


# ── GET /engagements/{id} ─────────────────────────────────────────────────────

@router.get("/{engagement_id}", response_model=EngagementDetail, summary="Engagement detail")
async def get_engagement(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    eng = await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)

    asset_count: int = (
        await db.execute(
            select(func.count(Asset.id)).where(Asset.engagement_id == engagement_id)
        )
    ).scalar_one()

    rows = (
        await db.execute(
            select(Finding.severity, Finding.status, func.count(Finding.id))
            .where(Finding.engagement_id == engagement_id)
            .group_by(Finding.severity, Finding.status)
        )
    ).all()

    sev_counts = {s.value: 0 for s in FindingSeverity}
    open_count = remediated_count = total = 0

    for sev, st, cnt in rows:
        sev_counts[sev.value] = sev_counts.get(sev.value, 0) + cnt
        total += cnt
        if st in (FindingStatus.open, FindingStatus.confirmed):
            open_count += cnt
        elif st == FindingStatus.remediated:
            remediated_count += cnt

    summary = FindingSummary(
        total=total,
        critical=sev_counts["critical"],
        high=sev_counts["high"],
        medium=sev_counts["medium"],
        low=sev_counts["low"],
        info=sev_counts["info"],
        open=open_count,
        remediated=remediated_count,
    )

    detail = EngagementDetail.model_validate(eng)
    detail.asset_count = asset_count
    detail.finding_summary = summary
    return detail


# ── PATCH /engagements/{id} — update fields ───────────────────────────────────

class EngagementUpdate(BaseModel):
    name: str | None = None
    status: EngagementStatus | None = None
    scope_cidrs: list[str] | None = None
    excluded_cidrs: list[str] | None = None
    rules_of_engagement: dict | None = None


@router.patch("/{engagement_id}", response_model=EngagementOut, summary="Update engagement fields")
async def update_engagement(
    engagement_id: uuid.UUID,
    body: EngagementUpdate,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
):
    eng = await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(eng, field, value)
    await db.flush()
    await db.refresh(eng)
    logger.info("engagement.patched", id=str(engagement_id))
    return eng


# ── POST /engagements/{id}/assets ─────────────────────────────────────────────

@router.post(
    "/{engagement_id}/assets",
    response_model=BulkAssetImportResult,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk import assets (JSON array or CSV upload)",
)
async def bulk_import_assets(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester"])],
    file: UploadFile | None = File(default=None),
    body: list[AssetIn] | None = None,
):
    await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)

    assets_in: list[AssetIn] = []
    parse_errors: list[str] = []

    if file is not None:
        content = (await file.read()).decode("utf-8")
        if file.content_type in ("text/csv", "application/csv") or file.filename.endswith(".csv"):
            assets_in, parse_errors = parse_csv_assets(content)
        else:
            try:
                raw = json.loads(content)
                assets_in = [AssetIn(**r) for r in raw]
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Cannot parse file: {exc}")
    elif body:
        assets_in = body
    else:
        raise HTTPException(status_code=400, detail="Provide either a file upload or JSON body")

    created = 0
    for asset_in in assets_in:
        try:
            asset = Asset(engagement_id=engagement_id, **asset_in.model_dump())
            db.add(asset)
            created += 1
        except Exception as exc:
            parse_errors.append(str(exc))

    await db.flush()
    logger.info("assets.bulk_import", engagement=str(engagement_id), created=created, failed=len(parse_errors))
    return BulkAssetImportResult(created=created, failed=len(parse_errors), errors=parse_errors)


# ── GET /{engagement_id}/jobs — list scan jobs + results ──────────────────────

@router.get("/{engagement_id}/jobs", summary="List scan jobs (and results) for an engagement")
async def list_engagement_jobs(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)
    rows = (await db.execute(
        select(ScanJob).where(ScanJob.engagement_id == engagement_id)
        .order_by(ScanJob.created_at.desc())
    )).scalars().all()
    return [
        {
            "id": str(j.id),
            "job_type": j.job_type.value if hasattr(j.job_type, "value") else str(j.job_type),
            "status": j.status.value if hasattr(j.status, "value") else str(j.status),
            "agent_id": j.agent_id,
            "result": j.result,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in rows
    ]


# ── GET /{engagement_id}/assets — attack surface (hosts + services) ───────────

@router.get("/{engagement_id}/assets", summary="List assets (hosts) and their services")
async def list_engagement_assets(
    engagement_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    await get_or_404(db, Engagement, engagement_id, current_user.tenant_id)
    assets = (await db.execute(
        select(Asset).where(Asset.engagement_id == engagement_id).order_by(Asset.ip_address)
    )).scalars().all()
    asset_ids = [a.id for a in assets]

    svc_by_asset: dict = {}
    if asset_ids:
        services = (await db.execute(
            select(Service).where(Service.asset_id.in_(asset_ids))
        )).scalars().all()
        for s in services:
            svc_by_asset.setdefault(s.asset_id, []).append({
                "port": s.port, "protocol": s.protocol, "service": s.service_name,
                "product": s.product, "version": s.version,
            })

    return [
        {
            "id": str(a.id),
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "os": a.os,
            "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
            "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
            "services": sorted(svc_by_asset.get(a.id, []), key=lambda x: x["port"] or 0),
        }
        for a in assets
    ]


# ── helpers ───────────────────────────────────────────────────────────────────
# `get_or_404` lives in app/utils/db.py — imported at top of file.
# Keeping this section as a placeholder for engagement-specific helpers.
