"""promote the sender's alert id to a column so ingest can dedupe on it

Revision ID: 016
Revises: 015
Create Date: 2026-08-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("external_ref", sa.String(length=255), nullable=True),
    )
    # Runs created before this migration carry the id inside result_json only;
    # lift it out so an alert delivered again is recognised against them too.
    op.execute(
        """
        UPDATE alert_body_investigation_runs
           SET external_ref = LEFT(result_json->>'external_ref', 255)
         WHERE result_json->>'external_ref' IS NOT NULL
        """
    )
    # Dedupe looks up runs by the sender's id, newest first.
    op.create_index(
        "idx_alert_body_runs_extref_created",
        "alert_body_investigation_runs",
        ["external_ref", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_alert_body_runs_extref_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "external_ref")
