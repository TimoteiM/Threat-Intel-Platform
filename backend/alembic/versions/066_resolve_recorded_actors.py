"""Resolve recorded actors against `users` instead of assuming they are unresolvable

065 backfilled every `indicator_lookups` row to `recorded_unresolvable` on the
stated grounds that "the six existing rows all carry `'verification'`". By the
time it ran there were **26** rows: 14 from that in-process check and **12 from
a real person using the page**, whose username resolves to a `users` row with
role `owner`. Those twelve are `human` with a resolvable id, and 065 recorded
them as unattributable.

The error is not the classification, it is that the backfill **asserted a
population measured hours earlier**. A migration runs later than it is written,
by definition, and against whatever the table holds then. So the rule here is
to *resolve*, not to assume — which is what 065 should have done, and what this
does for any row, now or later.

Idempotent and re-runnable: it only promotes rows that still carry a resolvable
name, and never demotes.

Revision ID: 066
Revises: 065
"""

from alembic import op
import sqlalchemy as sa

revision = "066"
down_revision = "065"
branch_labels = None
depends_on = None

#: Both tables carry the same attribution pair, by design — one column, two
#: features. So the same resolution runs over both rather than being written
#: twice and diverging.
_TABLES = ("indicator_lookups", "investigation_records")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    present = set(inspector.get_table_names())

    for table in _TABLES:
        if table not in present:
            continue
        cols = {c["name"] for c in inspector.get_columns(table)}
        if not {"actor_kind", "actor_user_id", "actor_recorded"} <= cols:
            continue
        # Promote only. A row already resolved stays resolved, and a row whose
        # recorded name matches no account keeps `recorded_unresolvable` —
        # which is the honest kind for it: an actor WAS recorded and cannot be
        # matched, as distinct from none having been written down.
        op.execute(sa.text(f"""
            UPDATE {table} AS t
               SET actor_kind = 'human',
                   actor_user_id = u.id
              FROM users AS u
             WHERE u.username = t.actor_recorded
               AND t.actor_user_id IS NULL
        """))


def downgrade() -> None:
    # Deliberately not reversed. Demoting a resolved actor back to
    # `recorded_unresolvable` would assert that an actor cannot be matched when
    # this migration has just demonstrated it can — a false claim written by a
    # rollback.
    pass
