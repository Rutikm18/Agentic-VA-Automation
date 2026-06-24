import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class AttackTimeline(Base, TimestampMixin):
    """
    Append-only ledger of every attack action performed during an engagement.

    Written by the AttackLogger from all attack modules (discovery, exploit, AD,
    lateral movement) and consumed by the detection correlator to answer
    "did the blue team see this?". The exact ``timestamp`` is the anchor for the
    ±window correlation against SIEM/EDR alerts.
    """
    __tablename__ = "attack_timeline"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default="gen_random_uuid()"
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    mitre_technique: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    target_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    target_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    action_detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    engagement: Mapped["Engagement"] = relationship(lazy="noload")
