import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EngagementStatus, FindingSeverity


# ── Request schemas ────────────────────────────────────────────────────────────

class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scope_cidrs: list[str] = Field(..., min_length=1)
    excluded_cidrs: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    rules_of_engagement: dict | None = None


class EngagementFilter(BaseModel):
    status: EngagementStatus | None = None
    start_after: datetime | None = None
    start_before: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


# ── Response schemas ───────────────────────────────────────────────────────────

class FindingSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open: int
    remediated: int


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    status: EngagementStatus
    scope_cidrs: list[str]
    excluded_cidrs: list[str] | None
    start_time: datetime | None
    end_time: datetime | None
    rules_of_engagement: dict | None
    created_at: datetime
    updated_at: datetime


class EngagementDetail(EngagementOut):
    asset_count: int = 0
    finding_summary: FindingSummary = Field(
        default_factory=lambda: FindingSummary(
            total=0, critical=0, high=0, medium=0, low=0, info=0, open=0, remediated=0
        )
    )
