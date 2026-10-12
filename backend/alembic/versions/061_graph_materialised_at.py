"""Record when a run's graph rows were written, so staleness is detectable.

`alert_graph_entity` and `alert_graph_edge` are a cache that nothing kept warm.
`materialise_run` had exactly one caller — the `graph_backfill` CLI — so every
figure drawn from those tables was as of whenever a person last ran it by hand,
and nothing in the schema said so.

Measured 2026-10-12: two alerts on `exp-4lwk334` carry a corroborated ATT&CK
technique in their assessment and have no graph rows at all, because they
arrived after the last backfill. A re-run the night before had grown registry
values from 2 rows to 74,649 and every other kind with them, which is the same
defect showing up as a one-off correction.

`graph_source_type IS NULL` already identified a run that had never been
materialised, but it could not distinguish "never done" from "done, and the
source genuinely has no type", and it carried no time. This column does both:
NULL means never, and a timestamp means when — so a sweep can be incremental
and a reader can be told how old the answer is.

Revision ID: 061
Revises: 060
"""

from alembic import op
import sqlalchemy as sa

revision = "061"
down_revision = "060"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("graph_materialised_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Partial index: the sweep only ever asks for the NULLs, and they are the
    # minority once the backfill has run.
    op.create_index(
        "ix_runs_graph_unmaterialised",
        "alert_body_investigation_runs",
        ["created_at"],
        postgresql_where=sa.text("graph_materialised_at is null"),
    )
    # Everything already materialised is backdated to the row's own creation
    # rather than to now: claiming these were materialised at migration time
    # would overstate their freshness by however long the backfill lagged.
    op.execute(
        "update alert_body_investigation_runs "
        "set graph_materialised_at = created_at "
        "where graph_source_type is not null"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_runs_graph_unmaterialised", table_name="alert_body_investigation_runs"
    )
    op.drop_column("alert_body_investigation_runs", "graph_materialised_at")
