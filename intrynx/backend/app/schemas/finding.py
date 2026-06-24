import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import DetectionStatus, FindingSeverity, FindingStatus


class FindingFilter(BaseModel):
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    asset_id: uuid.UUID | None = None
    mitre_technique: str | None = None
    engagement_id: uuid.UUID | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class FindingPatch(BaseModel):
    """All fields optional — PATCH semantics."""
    status: FindingStatus | None = None
    owner: str | None = None          # mapped to asset.owner or stored in notes
    notes: str | None = None          # appended to remediation field
    exploitable: bool | None = None
    exploit_validated: bool | None = None
    detection_status: DetectionStatus | None = None
    remediation: str | None = None
    cvss_score: Decimal | None = Field(default=None, ge=0, le=10)
    epss_score: Decimal | None = Field(default=None, ge=0, le=1)
    risk_score: Decimal | None = Field(default=None, ge=0, le=100)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    asset_id: uuid.UUID | None
    cve_ids: list[str] | None
    title: str
    description: str | None
    cvss_score: Decimal | None
    cvss_vector: str | None
    epss_score: Decimal | None
    risk_score: Decimal | None
    severity: FindingSeverity
    status: FindingStatus
    exploitable: bool
    exploit_validated: bool
    mitre_techniques: list[str] | None
    detection_status: DetectionStatus
    evidence: dict | None
    remediation: str | None
    created_at: datetime
    updated_at: datetime
