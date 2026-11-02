"""
Which platform an alert came from.

Correlation groups alerts by entity, and two platforms watching the same estate
name hosts their own way. Joining across them would assemble a "chain" out of a
Siembiot endpoint alert and an unrelated session alert about a similarly named
host — a fabrication that looks exactly like the finding the feature exists to
produce, which makes it the most damaging kind.

Revision ID: 022
Revises: 021
"""

from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_body_investigation_runs", sa.Column("alert_source", sa.String(120), nullable=True))
    # Correlation always asks "what else came from this source, about this
    # entity, recently" — so the source leads the index.
    op.create_index(
        "idx_alert_runs_source_entity_created",
        "alert_body_investigation_runs",
        ["alert_source", "entity_host", "created_at"],
        postgresql_where=sa.text("entity_host IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_alert_runs_source_entity_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "alert_source")
