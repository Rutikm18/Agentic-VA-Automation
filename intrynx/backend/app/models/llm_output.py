import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import ReviewStatus


class LLMOutput(Base, TimestampMixin):
    """
    Every LLM generation is persisted here for human-in-the-loop review.

    AI output is *never* final until a human approves it: rows start as
    ``review_status = pending`` and only become part of the delivered report once
    a reviewer approves. ``prompt_hash`` lets us dedupe / cache identical prompts
    and audit exactly what produced each output.
    """
    __tablename__ = "llm_outputs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default="gen_random_uuid()"
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # executive_summary | technical_finding | remediation_steps | detection_rule_explanation
    output_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    prompt_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    output: Mapped[str] = mapped_column(Text, nullable=False)
    review_status: Mapped[ReviewStatus] = mapped_column(
        Enum(ReviewStatus, name="reviewstatus"), nullable=False, server_default="pending", index=True
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_feedback: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hallucination-guard verdict + any validation issues.
    validation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    engagement: Mapped["Engagement"] = relationship(lazy="noload")
