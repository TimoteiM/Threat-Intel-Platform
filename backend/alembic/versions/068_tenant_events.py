"""An append-only record of what happened to a tenant

A tenant row created by an incoming alert says `provisional` and nothing else:
not who confirmed it, not when, not what it was called before, not why anyone
decided it was a real client. The status column answers "what is it now" and
cannot answer "who decided that" — a current-state column is not an audit log
(see docs/problems/history-table-read-as-current-state.md).

That gap is backlog 29's, scoped to tenants: **no administrative action on
this platform is recorded anywhere.** `integration_audit` is for integration
configuration and giving it a second subject would make that table mean two
things, so this is its own table rather than an overload.

Append-only by construction: every row is one event, nothing is updated, and
`tenants.status` stays the fast path for "what is it now" while this answers
"how did it get there".

Idempotent, because `Base.metadata.create_all` runs at startup and is a second
schema authority — backlog 25. A migration that assumes it is the only writer
is a migration that fails the first time the app has already made the table.

Revision ID: 068
Revises: 067
"""

from alembic import op
import sqlalchemy as sa

revision = "068"
down_revision = "067"
branch_labels = None
depends_on = None

_TABLE = "tenant_events"


def _has_table(bind) -> bool:
    return sa.inspect(bind).has_table(_TABLE)


def _indexes(bind) -> set[str]:
    return {ix["name"] for ix in sa.inspect(bind).get_indexes(_TABLE)}


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind):
        op.create_table(
            _TABLE,
            sa.Column(
                "id", sa.dialects.postgresql.UUID(as_uuid=True),
                primary_key=True, server_default=sa.text("gen_random_uuid()"),
            ),
            # Not a foreign key to `tenants.id`. The event must survive the row
            # it describes: "this tenant was created by an alert and then
            # removed" is exactly the history worth keeping, and a cascade
            # would delete the only evidence of it.
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("action", sa.String(32), nullable=False),
            # Who, as recorded at the time. A username rather than a user id,
            # for the same reason the submitter work landed on: an account can
            # be renamed or removed and the event still has to say who acted.
            sa.Column("actor", sa.String(128), nullable=True),
            sa.Column("actor_role", sa.String(32), nullable=True),
            # Both sides of every change, so a reader never has to infer the
            # previous value from an earlier row that may not exist.
            sa.Column("from_status", sa.String(32), nullable=True),
            sa.Column("to_status", sa.String(32), nullable=True),
            sa.Column("from_name", sa.String(255), nullable=True),
            sa.Column("to_name", sa.String(255), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column(
                "at", sa.DateTime(timezone=True),
                nullable=False, server_default=sa.text("now()"),
            ),
        )

    existing = _indexes(bind)
    if "ix_tenant_events_tenant_id" not in existing:
        op.create_index("ix_tenant_events_tenant_id", _TABLE, ["tenant_id"])
    if "ix_tenant_events_at" not in existing:
        op.create_index("ix_tenant_events_at", _TABLE, ["at"])

    # The tenants that already exist have no history, and inventing one would
    # be worse than having none: `c00` was made active by hand on 2026-09-24
    # and the three provisional rows were minted by their first alert today.
    # Neither fact has an actor anyone recorded, so nothing is backfilled —
    # an absent event means "before this table existed", which is true, where
    # a fabricated one would assert somebody acted.


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind):
        op.drop_table(_TABLE)
