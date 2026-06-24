"""Add services and agents tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE agentstatus AS ENUM ('online','offline','busy')")

    # ── services ──────────────────────────────────────────────────────────────
    op.create_table(
        "services",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id",     postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port",         sa.Integer, nullable=False),
        sa.Column("protocol",     sa.String(10), nullable=False, server_default="tcp"),
        sa.Column("service_name", sa.String(100), nullable=True),
        sa.Column("product",      sa.String(255), nullable=True),
        sa.Column("version",      sa.String(100), nullable=True),
        sa.Column("cpe",          sa.String(255), nullable=True),
        sa.Column("banner",       sa.Text, nullable=True),
        sa.Column("extra_info",   postgresql.JSONB, nullable=True),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",   sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
    )
    op.create_index("ix_services_asset_id", "services", ["asset_id"])

    # ── agents ────────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",        postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name",             sa.String(255), nullable=False),
        sa.Column("location",         sa.String(255), nullable=True),
        sa.Column("capabilities",     postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("network_segments", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("status",           postgresql.ENUM("online","offline","busy", name="agentstatus", create_type=False), nullable=False, server_default="offline"),
        sa.Column("last_heartbeat",   sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_job_id",   postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at",       sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",       sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("agents")
    op.drop_table("services")
    op.execute("DROP TYPE IF EXISTS agentstatus")
