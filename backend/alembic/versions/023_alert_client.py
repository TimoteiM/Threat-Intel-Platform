"""
Which organisation an alert is about.

Both feeds carry other people's alerts, so two customers can each own a host
called DC01. Correlating across them would build a chain spanning two companies
— wrong as analysis, and a confidentiality problem besides.

`alert_kind` separates a single alert from a payload that is already a session.
A TraceCat incident arrives with fifty events and their triggered rules: it is a
case, not a member of one, and grouping it with single alerts compares a case to
its own parts.

Revision ID: 023
Revises: 022
"""

from alembic import op
import sqlalchemy as sa

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_body_investigation_runs", sa.Column("alert_client", sa.String(120), nullable=True))
    op.add_column("alert_body_investigation_runs", sa.Column("alert_kind", sa.String(20), nullable=True))
    op.drop_index("idx_alert_runs_source_entity_created", table_name="alert_body_investigation_runs")
    # Correlation asks: from this sender, for this client, about this entity,
    # recently. The key is the index.
    op.create_index(
        "idx_alert_runs_scope_entity_created",
        "alert_body_investigation_runs",
        ["alert_source", "alert_client", "entity_host", "created_at"],
        postgresql_where=sa.text("entity_host IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_alert_runs_scope_entity_created", table_name="alert_body_investigation_runs")
    op.create_index(
        "idx_alert_runs_source_entity_created",
        "alert_body_investigation_runs",
        ["alert_source", "entity_host", "created_at"],
        postgresql_where=sa.text("entity_host IS NOT NULL"),
    )
    op.drop_column("alert_body_investigation_runs", "alert_kind")
    op.drop_column("alert_body_investigation_runs", "alert_client")
