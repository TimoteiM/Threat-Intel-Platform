"""Materialise the entities and relationships an alert witnesses.

The case graph drew the case record: a hub, one box per alert, and an account.
It could not draw an attack, because the thing worth seeing only appears when
two observations collapse onto one node — the same binary reached by
persistence and by credential access, the same address serving a stager and
later answering a beacon. On the case that prompted this, the legend read
Process 0 and ATT&CK 0 while the eight alerts underneath carried eleven
techniques, eleven processes, two hosts, three files, a registry value and a
service. An extraction failure, not an ingestion gap.

Measured over all 15,203 stored bodies before writing this, so the scope of
what the graph can draw is known rather than hoped for:

    shape of alert_body        bodies        node type         share of runs
    key/value text lines       14,430        host                     94.3%
    freeform (CEF, syslog)        712        technique                87.3%
    JSON                           61        process                  48.6%
                                             account                  27.1%
                                             file                      7.0%
                                             registry value            0.2%
                                             ip / domain               0.0%

So four node types carry the estate and the rest are present in a handful of
incidents. Nothing here invents the missing ones.

Two tables rather than one view, for two reasons. A case graph becomes a join
on `run_id` instead of re-parsing every body on every page load; and "where
else has this thing been seen" becomes an index hit on `merge_key`, which is
what makes cross-case pivots affordable at all.

One row per (alert, entity), not one row per merged node. The merge is the
assembler's job at read time, because it needs to see every alert at once: a
process named with a PID by one alert and only as somebody's parent by two
others cannot be keyed identically at write time. Storing the merged result
would also discard which alert saw what, and that is precisely what the side
panel has to show.

Revision ID: 049
Revises: 048
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "049"
down_revision = "048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_graph_entity",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id", UUID(as_uuid=True),
            sa.ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("merge_key", sa.String(512), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("attrs", JSONB, nullable=False, server_default="{}"),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rule_level", sa.Integer, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("run_id", "merge_key", name="uq_graph_entity_run_key"),
    )
    # The pivot index. Without it, "which other cases touched this binary" is a
    # sequential scan over every entity ever extracted.
    op.create_index("ix_graph_entity_merge_key", "alert_graph_entity", ["merge_key"])
    op.create_index("ix_graph_entity_run", "alert_graph_entity", ["run_id"])

    op.create_table(
        "alert_graph_edge",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id", UUID(as_uuid=True),
            sa.ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        # Merge keys, not row ids: an edge has to survive being written by an
        # alert that never saw both of its ends as the same object.
        sa.Column("source_key", sa.String(512), nullable=False),
        sa.Column("target_key", sa.String(512), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("attrs", JSONB, nullable=False, server_default="{}"),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "run_id", "kind", "source_key", "target_key",
            name="uq_graph_edge_run_triple",
        ),
    )
    op.create_index("ix_graph_edge_run", "alert_graph_edge", ["run_id"])
    op.create_index("ix_graph_edge_source", "alert_graph_edge", ["source_key"])
    op.create_index("ix_graph_edge_target", "alert_graph_edge", ["target_key"])


def downgrade() -> None:
    op.drop_index("ix_graph_edge_target", table_name="alert_graph_edge")
    op.drop_index("ix_graph_edge_source", table_name="alert_graph_edge")
    op.drop_index("ix_graph_edge_run", table_name="alert_graph_edge")
    op.drop_table("alert_graph_edge")
    op.drop_index("ix_graph_entity_run", table_name="alert_graph_entity")
    op.drop_index("ix_graph_entity_merge_key", table_name="alert_graph_entity")
    op.drop_table("alert_graph_entity")
