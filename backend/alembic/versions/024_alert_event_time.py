"""
When the alert happened on the host, as distinct from when we were told.

Correlation ordered members by created_at, which is ingest order. This
deployment receives alerts replayed days after the fact, so ingest order is the
order a sender chose to send in — a replayed alert sorts after events that
happened long before it. Measured on stored runs, event time and ingest time
differ by more than twelve hours on ordinary traffic.

Every sequence question asked of a case — which tactic followed which, how
quickly, in what direction — is wrong if asked of that order. This is the column
those questions read.

Revision ID: 024
Revises: 023
"""

from alembic import op
import sqlalchemy as sa

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
    )
    # Sequencing reads (scope, entity, event_time) in that order, so the index
    # carries the sort rather than leaving it to a per-case sort in Python.
    op.create_index(
        "idx_alert_runs_scope_entity_event_time",
        "alert_body_investigation_runs",
        ["alert_source", "alert_client", "entity_host", "event_time"],
        postgresql_where=sa.text("entity_host IS NOT NULL AND event_time IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_alert_runs_scope_entity_event_time", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "event_time")
