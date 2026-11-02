"""add alert body investigation runs

Revision ID: 014
Revises: 013
Create Date: 2026-08-05
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_body_investigation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("alert_body", sa.Text(), nullable=False),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("indicator_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overall_verdict", sa.String(length=20), nullable=True),
        sa.Column("highest_risk_score", sa.Integer(), nullable=True),
        sa.Column("result_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_alert_body_runs_created", "alert_body_investigation_runs", ["created_at"])
    op.create_index("idx_alert_body_runs_status", "alert_body_investigation_runs", ["status"])


def downgrade() -> None:
    op.drop_index("idx_alert_body_runs_status", table_name="alert_body_investigation_runs")
    op.drop_index("idx_alert_body_runs_created", table_name="alert_body_investigation_runs")
    op.drop_table("alert_body_investigation_runs")
