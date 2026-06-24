import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import AssetCriticality, AssetType


class AssetIn(BaseModel):
    ip_address: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    os: str | None = None
    os_version: str | None = None
    asset_type: AssetType = AssetType.server
    criticality: AssetCriticality = AssetCriticality.medium
    owner: str | None = None
    environment: str | None = None
    tags: dict | None = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    ip_address: str | None
    hostname: str | None
    fqdn: str | None
    os: str | None
    os_version: str | None
    asset_type: AssetType
    criticality: AssetCriticality
    owner: str | None
    environment: str | None
    tags: dict | None
    last_seen: datetime | None
    created_at: datetime
    updated_at: datetime


class BulkAssetImportResult(BaseModel):
    created: int
    failed: int
    errors: list[str] = Field(default_factory=list)
