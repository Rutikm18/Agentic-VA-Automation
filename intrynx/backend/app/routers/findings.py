import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Query, status
from sqlalchemy import select

from app.auth.rbac import require_role
from app.dependencies import DB, AuthUser
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.schemas.common import PaginatedResponse, paginate
from app.schemas.finding import FindingFilter, FindingOut, FindingPatch
from app.utils.db import get_or_404
from app.utils.pagination import paginate_query

router = APIRouter(prefix="/findings", tags=["findings"])
logger = structlog.get_logger()


@router.get("", response_model=PaginatedResponse[FindingOut], summary="List findings with filters")
async def list_findings(
    db: DB,
    current_user: AuthUser,
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    asset_id: uuid.UUID | None = Query(default=None),
    mitre_technique: str | None = Query(default=None),
    engagement_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    # Scope to tenant via engagement join
    q = (
        select(Finding)
        .join(Engagement, Finding.engagement_id == Engagement.id)
        .where(Engagement.tenant_id == current_user.tenant_id)
    )

    if severity:
        q = q.where(Finding.severity == severity)
    if status_filter:
        q = q.where(Finding.status == status_filter)
    if asset_id:
        q = q.where(Finding.asset_id == asset_id)
    if engagement_id:
        q = q.where(Finding.engagement_id == engagement_id)
    if mitre_technique:
        q = q.where(Finding.mitre_techniques.any(mitre_technique))

    q = q.order_by(Finding.created_at.desc())
    items, total = await paginate_query(db, q, page, page_size)
    return paginate(items, total, page, page_size)


@router.get("/{finding_id}", response_model=FindingOut, summary="Finding detail")
async def get_finding(
    finding_id: uuid.UUID,
    db: DB,
    current_user: AuthUser,
):
    return await get_or_404(db, Finding, finding_id, current_user.tenant_id)


@router.patch("/{finding_id}", response_model=FindingOut, summary="Update finding status, owner, or notes")
async def patch_finding(
    finding_id: uuid.UUID,
    body: FindingPatch,
    db: DB,
    current_user: Annotated[AuthUser, require_role(["admin", "manager", "tester", "analyst"])],
):
    finding = await get_or_404(db, Finding, finding_id, current_user.tenant_id)

    patch = body.model_dump(exclude_unset=True)

    if "notes" in patch:
        notes = patch.pop("notes")
        finding.remediation = (
            f"{finding.remediation}\n\n[Note] {notes}" if finding.remediation else f"[Note] {notes}"
        )

    for field, value in patch.items():
        setattr(finding, field, value)

    await db.flush()
    await db.refresh(finding)
    logger.info("finding.patched", id=str(finding_id), changes=list(patch.keys()))
    return finding


# `get_or_404` lives in app/utils/db.py — imported at top of file.
