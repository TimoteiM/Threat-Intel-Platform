"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-02-11
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Investigations
    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False, index=True),
        sa.Column("state", sa.String(50), nullable=False, server_default="created"),
        sa.Column("context", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("concluded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("classification", sa.String(50), nullable=True),
        sa.Column("confidence", sa.String(20), nullable=True),
        sa.Column("risk_score", sa.Integer, nullable=True),
        sa.Column("recommended_action", sa.String(50), nullable=True),
        sa.Column("analyst_iterations", sa.Integer, server_default="0"),
        sa.Column("max_analyst_iterations", sa.Integer, server_default="3"),
    )
    op.create_index("idx_investigations_state", "investigations", ["state"])
    op.create_index("idx_investigations_created", "investigations", ["created_at"])
    op.create_index("idx_investigations_classification", "investigations", ["classification"])

    # Collector Results
    op.create_table(
        "collector_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_name", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("version", sa.String(20), server_default="1.0.0"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("evidence_json", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("error", sa.Text),
        sa.Column("raw_artifact_hash", sa.String(64)),
    )
    op.create_index("idx_collector_results_inv", "collector_results", ["investigation_id"])
    op.create_index("uq_collector_per_investigation", "collector_results",
                     ["investigation_id", "collector_name"], unique=True)

    # Evidence (aggregated)
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("evidence_json", postgresql.JSONB, nullable=False),
        sa.Column("signals", postgresql.JSONB, server_default="[]"),
        sa.Column("data_gaps", postgresql.JSONB, server_default="[]"),
        sa.Column("external_context", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Reports
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("iteration", sa.Integer, nullable=False, server_default="0"),
        sa.Column("report_json", postgresql.JSONB, nullable=False),
        sa.Column("executive_summary", sa.Text),
        sa.Column("technical_narrative", sa.Text),
        sa.Column("recommendations", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_reports_inv", "reports", ["investigation_id"])

    # Artifacts
    op.create_table(
        "artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_name", sa.String(50), nullable=False),
        sa.Column("artifact_name", sa.String(255), nullable=False),
        sa.Column("sha256_hash", sa.String(64), nullable=False, index=True),
        sa.Column("content_type", sa.String(100)),
        sa.Column("size_bytes", sa.Integer),
        sa.Column("storage_path", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_artifacts_inv", "artifacts", ["investigation_id"])

    # IOCs
    op.create_table(
        "iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("context", sa.Text),
        sa.Column("confidence", sa.String(20)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_iocs_inv", "iocs", ["investigation_id"])
    op.create_index("idx_iocs_value", "iocs", ["value"])
    op.create_index("idx_iocs_type", "iocs", ["type"])

    # Lookup Cache
    op.create_table(
        "lookup_cache",
        sa.Column("cache_key", sa.String(512), primary_key=True),
        sa.Column("cache_value", postgresql.JSONB, nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_cache_expires", "lookup_cache", ["expires_at"])


def downgrade() -> None:
    op.drop_table("lookup_cache")
    op.drop_table("iocs")
    op.drop_table("artifacts")
    op.drop_table("reports")
    op.drop_table("evidence")
    op.drop_table("collector_results")
    op.drop_table("investigations")
