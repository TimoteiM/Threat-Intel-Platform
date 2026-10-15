"""investigation_records + investigation_steps, and converge indicator_lookups.actor

Two tables added, and one column split.

**Idempotent**, because `create_all` runs at startup and is a second schema
authority — see backlog 25 and the note in 064, where the api restarted first,
`create_all` won, and `alembic_version` sat at 063 with the table present.

The `indicator_lookups.actor` split is the part with a decision in it. That
column shipped hours earlier as `String(255)` with `"unidentified"` for absent,
which is exactly the four-way collapse `docs/design/submitter-attribution.md`
exists to prevent. The six existing rows all carry `'verification'` — a string
written by an in-process check, matching no account in `users`. So they become
`recorded_unresolvable` with the string preserved in `actor_recorded`: an actor
*was* recorded and cannot be resolved, which is a different claim from
`predates_attribution` (nobody wrote one down) and from `automated_ingest`
(there was no human). Discarding the string would turn the first into the
second.

Revision ID: 065
Revises: 064
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "065"
down_revision = "064"
branch_labels = None
depends_on = None


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _columns(bind, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    if table not in set(inspector.get_table_names()):
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    existing = _tables(bind)

    if "investigation_records" not in existing:
        op.create_table(
            "investigation_records",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("origin_surface", sa.String(length=32), nullable=False),
            sa.Column("origin_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=True),
            sa.Column("actor_kind", sa.String(length=32), nullable=False),
            sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("actor_recorded", sa.String(length=255), nullable=True),
            sa.Column("verdict", sa.String(length=32), nullable=True),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("summary_unverified_entities", postgresql.JSONB(),
                      nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("summary_unverified_numerals", postgresql.JSONB(),
                      nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("incomplete", sa.Boolean(), nullable=False,
                      server_default=sa.text("false")),
            sa.Column("incomplete_steps", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'[]'::jsonb")),
            sa.Column("steps_run", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("steps_escalated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("observables_stopped", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("model_calls", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.text("now()")),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("idx_inv_records_origin", "investigation_records",
                        ["origin_surface", "origin_id"])
        op.create_index("idx_inv_records_created", "investigation_records", ["created_at"])
        op.create_index("idx_inv_records_actor", "investigation_records", ["actor_kind"])
        op.create_index("ix_investigation_records_tenant_id",
                        "investigation_records", ["tenant_id"])

    if "investigation_steps" not in existing:
        op.create_table(
            "investigation_steps",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=64), nullable=False),
            sa.Column("question", sa.Text(), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=True),
            sa.Column("target", sa.String(length=512), nullable=True),
            sa.Column("query", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'{}'::jsonb")),
            sa.Column("response_excerpt", sa.Text(), nullable=True),
            sa.Column("response_truncated", sa.Boolean(), nullable=False,
                      server_default=sa.text("false")),
            sa.Column("response_bytes", sa.Integer(), nullable=True),
            sa.Column("verdict", sa.String(length=32), nullable=True),
            sa.Column("observables_found", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'[]'::jsonb")),
            sa.Column("observables_selected", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'[]'::jsonb")),
            sa.Column("warrant", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'{}'::jsonb")),
            sa.Column("absence_kind", sa.String(length=32), nullable=True),
            sa.Column("absence_reason", sa.Text(), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("cost", postgresql.JSONB(), nullable=False,
                      server_default=sa.text("'{}'::jsonb")),
            sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["record_id"], ["investigation_records.id"],
                                    ondelete="CASCADE"),
        )
        op.create_index("idx_inv_steps_record", "investigation_steps",
                        ["record_id", "ordinal"])

    # --- converge indicator_lookups.actor onto the attribution shape -------
    cols = _columns(bind, "indicator_lookups")
    if cols and "actor_kind" not in cols:
        op.add_column("indicator_lookups",
                      sa.Column("actor_kind", sa.String(length=32), nullable=True))
        op.add_column("indicator_lookups",
                      sa.Column("actor_user_id", postgresql.UUID(as_uuid=True),
                                nullable=True))
        op.add_column("indicator_lookups",
                      sa.Column("actor_recorded", sa.String(length=255), nullable=True))

        # Backfill before NOT NULL, so the constraint lands on a column that
        # is already fully populated — the sequence the attribution spec sets
        # out, and the one that avoids a migration failing on live rows.
        #
        # An actor WAS recorded on every existing row and none of them resolves
        # to an account, so every one is `recorded_unresolvable` and the string
        # is preserved. `predates_attribution` would be the wrong claim: the
        # field existed and was written.
        op.execute(sa.text("""
            UPDATE indicator_lookups
               SET actor_recorded = actor,
                   actor_kind = 'recorded_unresolvable'
             WHERE actor_kind IS NULL
        """))
        op.alter_column("indicator_lookups", "actor_kind", nullable=False)

        try:
            op.drop_index("idx_indicator_lookups_actor", table_name="indicator_lookups")
        except Exception:  # noqa: BLE001 — absent if create_all made the table
            pass
        op.drop_column("indicator_lookups", "actor")
        op.create_index("idx_indicator_lookups_actor", "indicator_lookups",
                        ["actor_kind"])


def downgrade() -> None:
    bind = op.get_bind()
    cols = _columns(bind, "indicator_lookups")
    if cols and "actor" not in cols:
        op.add_column("indicator_lookups",
                      sa.Column("actor", sa.String(length=255), nullable=True))
        op.execute(sa.text("""
            UPDATE indicator_lookups
               SET actor = coalesce(actor_recorded, 'unidentified')
        """))
        op.alter_column("indicator_lookups", "actor", nullable=False)
        try:
            op.drop_index("idx_indicator_lookups_actor", table_name="indicator_lookups")
        except Exception:  # noqa: BLE001
            pass
        op.drop_column("indicator_lookups", "actor_recorded")
        op.drop_column("indicator_lookups", "actor_user_id")
        op.drop_column("indicator_lookups", "actor_kind")
        op.create_index("idx_indicator_lookups_actor", "indicator_lookups", ["actor"])

    for table in ("investigation_steps", "investigation_records"):
        if table in _tables(bind):
            op.drop_table(table)
