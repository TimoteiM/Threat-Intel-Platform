"""add alert ingest fields (body hash for dedupe, callback url)

Revision ID: 015
Revises: 014
Create Date: 2026-08-05
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("alert_body_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("callback_url", sa.String(length=1024), nullable=True),
    )
    # Dedupe looks up recent runs by hash, newest first.
    op.create_index(
        "idx_alert_body_runs_hash_created",
        "alert_body_investigation_runs",
        ["alert_body_hash", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_alert_body_runs_hash_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "callback_url")
    op.drop_column("alert_body_investigation_runs", "alert_body_hash")
