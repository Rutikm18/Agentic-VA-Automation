"""Add enrichment fields index + webhook column to engagements

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Partial index for un-enriched findings — speeds up post-scan enrichment query
    op.create_index(
        "ix_findings_not_enriched",
        "findings",
        ["engagement_id", "status"],
        postgresql_where=sa.text("epss_score IS NULL"),
    )

    # Index for MITRE technique array search (GIN for ANY operator)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_findings_mitre_gin "
        "ON findings USING GIN (mitre_techniques)"
    )

    # Index for CVE ID array search
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_findings_cve_ids_gin "
        "ON findings USING GIN (cve_ids)"
    )

    # Index for risk_score ordering (common sort in findings list)
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])


def downgrade() -> None:
    op.drop_index("ix_findings_risk_score", table_name="findings")
    op.execute("DROP INDEX IF EXISTS ix_findings_cve_ids_gin")
    op.execute("DROP INDEX IF EXISTS ix_findings_mitre_gin")
    op.drop_index("ix_findings_not_enriched", table_name="findings")
