"""Initial schema — all tables

Revision ID: 0001
Revises:
Create Date: 2026-05-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── PostgreSQL 16 has gen_random_uuid() built-in — no extension needed ──

    # ── Enum types ──────────────────────────────────────────────────────────
    op.execute("CREATE TYPE userrole       AS ENUM ('admin','manager','tester','analyst','auditor')")
    op.execute("CREATE TYPE engagementstatus AS ENUM ('draft','active','paused','completed')")
    op.execute("CREATE TYPE assettype      AS ENUM ('server','workstation','network','cloud','container','iot')")
    op.execute("CREATE TYPE assetcriticality AS ENUM ('critical','high','medium','low')")
    op.execute("CREATE TYPE findingseverity AS ENUM ('critical','high','medium','low','info')")
    op.execute("CREATE TYPE findingstatus  AS ENUM ('open','confirmed','remediated','accepted','fp')")
    op.execute("CREATE TYPE detectionstatus AS ENUM ('detected','missed','prevented','unknown')")
    op.execute("CREATE TYPE scanjobtype    AS ENUM ('discovery','vuln_scan','exploit','ad_enum','lateral','cloud_scan')")
    op.execute("CREATE TYPE scanjobstatus  AS ENUM ('pending','running','completed','failed')")

    # ── tenants ─────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name",       sa.String(255), nullable=False),
        sa.Column("plan",       sa.String(50),  nullable=False, server_default="free"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",       postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email",           sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role",            postgresql.ENUM("admin","manager","tester","analyst","auditor", name="userrole", create_type=False), nullable=False),
        sa.Column("mfa_enabled",     sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    # ── engagements ──────────────────────────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id",                   postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",            postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name",                 sa.String(255), nullable=False),
        sa.Column("status",               postgresql.ENUM("draft","active","paused","completed", name="engagementstatus", create_type=False), nullable=False, server_default="draft"),
        sa.Column("scope_cidrs",          postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("excluded_cidrs",       postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("start_time",           sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_time",             sa.DateTime(timezone=True), nullable=True),
        sa.Column("rules_of_engagement",  postgresql.JSONB, nullable=True),
        sa.Column("created_at",           sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",           sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_engagements_tenant_id", "engagements", ["tenant_id"])
    op.create_index("ix_engagements_status",    "engagements", ["status"])

    # ── assets ────────────────────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address",    sa.String(45),  nullable=True),
        sa.Column("hostname",      sa.String(255), nullable=True),
        sa.Column("fqdn",          sa.String(255), nullable=True),
        sa.Column("os",            sa.String(100), nullable=True),
        sa.Column("os_version",    sa.String(100), nullable=True),
        sa.Column("asset_type",    postgresql.ENUM("server","workstation","network","cloud","container","iot", name="assettype", create_type=False), nullable=False, server_default="server"),
        sa.Column("criticality",   postgresql.ENUM("critical","high","medium","low", name="assetcriticality", create_type=False), nullable=False, server_default="medium"),
        sa.Column("owner",         sa.String(255), nullable=True),
        sa.Column("environment",   sa.String(100), nullable=True),
        sa.Column("tags",          postgresql.JSONB, nullable=True),
        sa.Column("last_seen",     sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_assets_engagement_id", "assets", ["engagement_id"])

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id",    postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id",         postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("cve_ids",          postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("title",            sa.String(500), nullable=False),
        sa.Column("description",      sa.Text, nullable=True),
        sa.Column("cvss_score",       sa.Numeric(4, 1), nullable=True),
        sa.Column("cvss_vector",      sa.String(200), nullable=True),
        sa.Column("epss_score",       sa.Numeric(5, 4), nullable=True),
        sa.Column("risk_score",       sa.Numeric(5, 2), nullable=True),
        sa.Column("severity",         postgresql.ENUM("critical","high","medium","low","info", name="findingseverity", create_type=False), nullable=False),
        sa.Column("status",           postgresql.ENUM("open","confirmed","remediated","accepted","fp", name="findingstatus", create_type=False), nullable=False, server_default="open"),
        sa.Column("exploitable",      sa.Boolean, nullable=False, server_default="false"),
        sa.Column("exploit_validated",sa.Boolean, nullable=False, server_default="false"),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("detection_status", postgresql.ENUM("detected","missed","prevented","unknown", name="detectionstatus", create_type=False), nullable=False, server_default="unknown"),
        sa.Column("evidence",         postgresql.JSONB, nullable=True),
        sa.Column("remediation",      sa.Text, nullable=True),
        sa.Column("created_at",       sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",       sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])
    op.create_index("ix_findings_asset_id",      "findings", ["asset_id"])
    op.create_index("ix_findings_severity",      "findings", ["severity"])
    op.create_index("ix_findings_status",        "findings", ["status"])

    # ── attack_paths ──────────────────────────────────────────────────────────
    op.create_table(
        "attack_paths",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path_nodes",    postgresql.ARRAY(postgresql.UUID(as_uuid=False)), nullable=True),
        sa.Column("path_edges",    postgresql.ARRAY(postgresql.JSONB), nullable=True),
        sa.Column("risk_score",    sa.Numeric(5, 2), nullable=True),
        sa.Column("chokepoints",   postgresql.ARRAY(postgresql.UUID(as_uuid=False)), nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_attack_paths_engagement_id", "attack_paths", ["engagement_id"])

    # ── detection_results ─────────────────────────────────────────────────────
    op.create_table(
        "detection_results",
        sa.Column("id",                    postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("finding_id",            postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mitre_technique",       sa.String(50), nullable=True),
        sa.Column("attack_timestamp",      sa.DateTime(timezone=True), nullable=True),
        sa.Column("siem_alerted",          sa.Boolean, nullable=False, server_default="false"),
        sa.Column("edr_alerted",           sa.Boolean, nullable=False, server_default="false"),
        sa.Column("detection_latency_sec", sa.Integer, nullable=True),
        sa.Column("alert_ids",             postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("sigma_recommendation",  sa.Text, nullable=True),
        sa.Column("created_at",            sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",            sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_detection_results_finding_id", "detection_results", ["finding_id"])

    # ── scan_jobs ─────────────────────────────────────────────────────────────
    op.create_table(
        "scan_jobs",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_type",      postgresql.ENUM("discovery","vuln_scan","exploit","ad_enum","lateral","cloud_scan", name="scanjobtype", create_type=False), nullable=False),
        sa.Column("status",        postgresql.ENUM("pending","running","completed","failed", name="scanjobstatus", create_type=False), nullable=False, server_default="pending"),
        sa.Column("agent_id",      sa.String(255), nullable=True),
        sa.Column("started_at",    sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("result",        postgresql.JSONB, nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_scan_jobs_engagement_id", "scan_jobs", ["engagement_id"])
    op.create_index("ix_scan_jobs_status",        "scan_jobs", ["status"])


def downgrade() -> None:
    op.drop_table("scan_jobs")
    op.drop_table("detection_results")
    op.drop_table("attack_paths")
    op.drop_table("findings")
    op.drop_table("assets")
    op.drop_table("engagements")
    op.drop_table("users")
    op.drop_table("tenants")

    for enum in [
        "scanjobstatus", "scanjobtype", "detectionstatus",
        "findingstatus", "findingseverity", "assetcriticality",
        "assettype", "engagementstatus", "userrole",
    ]:
        op.execute(f"DROP TYPE IF EXISTS {enum}")
