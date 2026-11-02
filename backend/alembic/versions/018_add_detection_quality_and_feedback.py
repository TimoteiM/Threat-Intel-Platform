"""record which detection produced an alert, and capture analyst feedback

Revision ID: 018
Revises: 017
Create Date: 2026-08-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # external_ref identifies one alert; these identify the rule that keeps
    # producing them, which is what detection-quality reporting groups by.
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("detection_rule_id", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("detection_rule_name", sa.String(length=512), nullable=True),
    )
    op.create_index(
        "idx_alert_body_runs_rule_created",
        "alert_body_investigation_runs",
        ["detection_rule_id", "created_at"],
    )

    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("subject_type", sa.String(length=30), nullable=False),
        sa.Column("subject_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("platform_classification", sa.String(length=20), nullable=True),
        sa.Column("platform_risk_score", sa.Integer(), nullable=True),
        sa.Column("detection_rule_id", sa.String(length=120), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("analyst", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("subject_type", "subject_id", name="uq_feedback_subject"),
    )
    op.create_index("idx_feedback_rule", "analyst_feedback", ["detection_rule_id"])
    op.create_index("idx_feedback_created", "analyst_feedback", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_feedback_created", table_name="analyst_feedback")
    op.drop_index("idx_feedback_rule", table_name="analyst_feedback")
    op.drop_table("analyst_feedback")
    op.drop_index("idx_alert_body_runs_rule_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "detection_rule_name")
    op.drop_column("alert_body_investigation_runs", "detection_rule_id")
