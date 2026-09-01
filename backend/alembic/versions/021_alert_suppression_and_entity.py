"""
Alert-level suppression, and the entity a chain is built from.

Two columns, one purpose each.

`exclusions.match_fields` lets an exclusion describe an alert rather than an
indicator. The existing row shape — one `normalized_value` with a unique
constraint on (type, value) — cannot express "rule 1002 from this agent at Low
priority", and that predicate is the difference between silencing one noisy
shape and silencing a whole rule that also produced 173 malicious results.

`alert_body_investigation_runs.entity_host` / `entity_user` are what correlation
groups on. An attack chain is (entity, time window, tactics), and nothing in
this schema previously identified the device or account an alert was about —
so no query could ask what else happened on that machine.

Revision ID: 021
Revises: 020
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "exclusions",
        sa.Column("match_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("alert_body_investigation_runs", sa.Column("entity_host", sa.String(255), nullable=True))
    op.add_column("alert_body_investigation_runs", sa.Column("entity_user", sa.String(255), nullable=True))

    # Correlation always asks "what else touched this entity recently", so the
    # window is part of the index rather than a filter applied after it.
    op.create_index(
        "idx_alert_runs_entity_host_created",
        "alert_body_investigation_runs",
        ["entity_host", "created_at"],
        postgresql_where=sa.text("entity_host IS NOT NULL"),
    )
    op.create_index(
        "idx_alert_runs_entity_user_created",
        "alert_body_investigation_runs",
        ["entity_user", "created_at"],
        postgresql_where=sa.text("entity_user IS NOT NULL"),
    )

    # The unique constraint on (indicator_type, normalized_value) would let one
    # alert exclusion exist per type, since every alert row shares a synthetic
    # value. Scoped to the indicator types it was written for.
    op.drop_constraint("uq_exclusion_type_value", "exclusions", type_="unique")
    op.create_index(
        "uq_exclusion_type_value",
        "exclusions",
        ["indicator_type", "normalized_value"],
        unique=True,
        postgresql_where=sa.text("indicator_type <> 'alert'"),
    )


def downgrade() -> None:
    op.drop_index("uq_exclusion_type_value", table_name="exclusions")
    op.create_unique_constraint(
        "uq_exclusion_type_value", "exclusions", ["indicator_type", "normalized_value"]
    )
    op.drop_index("idx_alert_runs_entity_user_created", table_name="alert_body_investigation_runs")
    op.drop_index("idx_alert_runs_entity_host_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "entity_user")
    op.drop_column("alert_body_investigation_runs", "entity_host")
    op.drop_column("exclusions", "match_fields")
