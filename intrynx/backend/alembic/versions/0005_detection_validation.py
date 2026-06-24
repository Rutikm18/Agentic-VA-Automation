"""Detection validation: attack_timeline, detection_configs, extend detection_results

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-11
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New ScanJobType value (ALTER TYPE must run outside a transaction block on
    # some PG versions; Alembic autocommits DDL per statement here).
    op.execute("ALTER TYPE scanjobtype ADD VALUE IF NOT EXISTS 'detection'")

    # ── attack_timeline ───────────────────────────────────────────────────────
    op.create_table(
        "attack_timeline",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id",   postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id",      postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mitre_technique", sa.String(50),  nullable=True),
        sa.Column("target_ip",       sa.String(45),  nullable=True),
        sa.Column("target_hostname", sa.String(255), nullable=True),
        sa.Column("action",          sa.String(100), nullable=False),
        sa.Column("action_detail",   postgresql.JSONB, nullable=True),
        sa.Column("timestamp",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_attack_timeline_engagement_id", "attack_timeline", ["engagement_id"])
    op.create_index("ix_attack_timeline_finding_id",    "attack_timeline", ["finding_id"])
    op.create_index("ix_attack_timeline_mitre",         "attack_timeline", ["mitre_technique"])
    op.create_index("ix_attack_timeline_target_ip",     "attack_timeline", ["target_ip"])
    op.create_index("ix_attack_timeline_timestamp",     "attack_timeline", ["timestamp"])

    # ── detection_configs ─────────────────────────────────────────────────────
    op.create_table(
        "detection_configs",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("siem_provider", sa.String(50),  nullable=True),
        sa.Column("siem_config",   postgresql.JSONB, nullable=True),
        sa.Column("edr_provider",  sa.String(50),  nullable=True),
        sa.Column("edr_config",    postgresql.JSONB, nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("engagement_id", name="uq_detection_config_engagement"),
    )
    op.create_index("ix_detection_configs_engagement_id", "detection_configs", ["engagement_id"])

    # ── extend detection_results ──────────────────────────────────────────────
    op.add_column("detection_results", sa.Column("engagement_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True))
    op.add_column("detection_results", sa.Column("attack_action_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("attack_timeline.id", ondelete="SET NULL"), nullable=True))
    op.add_column("detection_results", sa.Column("host_ip", sa.String(45), nullable=True))
    op.add_column("detection_results", sa.Column(
        "detection_status",
        postgresql.ENUM("detected", "missed", "prevented", "unknown", name="detectionstatus", create_type=False),
        nullable=False, server_default="unknown",
    ))
    # finding_id becomes optional (correlation is per attack action).
    op.alter_column("detection_results", "finding_id", nullable=True)

    op.create_index("ix_detection_results_engagement_id", "detection_results", ["engagement_id"])
    op.create_index("ix_detection_results_attack_action_id", "detection_results", ["attack_action_id"])
    op.create_index("ix_detection_results_mitre", "detection_results", ["mitre_technique"])
    op.create_index("ix_detection_results_status", "detection_results", ["detection_status"])


def downgrade() -> None:
    op.drop_index("ix_detection_results_status", "detection_results")
    op.drop_index("ix_detection_results_mitre", "detection_results")
    op.drop_index("ix_detection_results_attack_action_id", "detection_results")
    op.drop_index("ix_detection_results_engagement_id", "detection_results")
    op.alter_column("detection_results", "finding_id", nullable=False)
    op.drop_column("detection_results", "detection_status")
    op.drop_column("detection_results", "host_ip")
    op.drop_column("detection_results", "attack_action_id")
    op.drop_column("detection_results", "engagement_id")

    op.drop_table("detection_configs")
    op.drop_table("attack_timeline")
    # Note: an enum value added via ALTER TYPE ... ADD VALUE cannot be dropped in
    # PostgreSQL without recreating the type; 'detection' is left in place.
