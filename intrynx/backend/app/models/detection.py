import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import DetectionStatus


class DetectionResult(Base, TimestampMixin):
    __tablename__ = "detection_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default="gen_random_uuid()"
    )
    # Engagement scope + the specific attack action this result correlates.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True, index=True
    )
    attack_action_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_timeline.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # finding_id is now optional — correlation is per attack action, which may or
    # may not map to a single finding.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    mitre_technique: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    host_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    attack_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detection_status: Mapped[DetectionStatus] = mapped_column(
        Enum(DetectionStatus, name="detectionstatus"), nullable=False, server_default="unknown", index=True
    )
    siem_alerted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    edr_alerted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    detection_latency_sec: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text()), nullable=True)
    sigma_recommendation: Mapped[str | None] = mapped_column(Text(), nullable=True)

    finding: Mapped["Finding | None"] = relationship(back_populates="detection_results", lazy="noload")
