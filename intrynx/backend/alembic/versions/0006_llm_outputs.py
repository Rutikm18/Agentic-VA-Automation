"""AI engine: llm_outputs table + reviewstatus enum

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-11
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE reviewstatus AS ENUM ('pending','approved','rejected')")
    op.execute("ALTER TYPE scanjobtype ADD VALUE IF NOT EXISTS 'ai_report'")

    op.create_table(
        "llm_outputs",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id",   postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id",      postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("output_type",     sa.String(50),  nullable=False),
        sa.Column("prompt_hash",     sa.String(64),  nullable=False),
        sa.Column("model",           sa.String(100), nullable=False),
        sa.Column("output",          sa.Text,        nullable=False),
        sa.Column("review_status",   postgresql.ENUM("pending", "approved", "rejected", name="reviewstatus", create_type=False), nullable=False, server_default="pending"),
        sa.Column("reviewed_by",     sa.String(255), nullable=True),
        sa.Column("reviewed_at",     sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_feedback", sa.Text,        nullable=True),
        sa.Column("validation",      postgresql.JSONB, nullable=True),
        sa.Column("generated_at",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_llm_outputs_engagement_id", "llm_outputs", ["engagement_id"])
    op.create_index("ix_llm_outputs_finding_id",    "llm_outputs", ["finding_id"])
    op.create_index("ix_llm_outputs_output_type",   "llm_outputs", ["output_type"])
    op.create_index("ix_llm_outputs_prompt_hash",   "llm_outputs", ["prompt_hash"])
    op.create_index("ix_llm_outputs_review_status", "llm_outputs", ["review_status"])


def downgrade() -> None:
    op.drop_table("llm_outputs")
    op.execute("DROP TYPE IF EXISTS reviewstatus")
