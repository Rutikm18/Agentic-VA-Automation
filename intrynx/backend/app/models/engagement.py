import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import EngagementStatus


class Engagement(Base, TimestampMixin):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default="gen_random_uuid()"
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus, name="engagementstatus"),
        nullable=False,
        server_default="draft",
    )
    scope_cidrs: Mapped[list[str]] = mapped_column(ARRAY(Text()), nullable=False, server_default="{}")
    excluded_cidrs: Mapped[list[str]] = mapped_column(ARRAY(Text()), nullable=True)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rules_of_engagement: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="engagements", lazy="noload")
    assets: Mapped[list["Asset"]] = relationship(back_populates="engagement", lazy="noload")
    findings: Mapped[list["Finding"]] = relationship(back_populates="engagement", lazy="noload")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="engagement", lazy="noload")
    attack_paths: Mapped[list["AttackPath"]] = relationship(back_populates="engagement", lazy="noload")
