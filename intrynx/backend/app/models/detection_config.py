import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class DetectionConfig(Base, TimestampMixin):
    """
    Per-engagement SIEM + EDR connection settings used by the detection
    validation engine. One row per engagement (upserted via the API).

    Connection params (URLs, tokens, API keys) live in JSONB. They are secrets:
    the API never echoes them back — only which provider is configured.
    """
    __tablename__ = "detection_configs"
    __table_args__ = (
        UniqueConstraint("engagement_id", name="uq_detection_config_engagement"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default="gen_random_uuid()"
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    siem_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)  # splunk|sentinel|elastic
    siem_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    edr_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)  # crowdstrike|defender|sentinelone
    edr_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    engagement: Mapped["Engagement"] = relationship(lazy="noload")
