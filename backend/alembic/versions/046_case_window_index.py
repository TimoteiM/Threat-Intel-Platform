"""Index the column the closing queue now reads.

A case is answered ten minutes after it opened, not ten minutes after its last
alert. The closing job's work queue therefore filters and orders on
`opened_at`, where it used to use `last_activity_at` — and the two partial
indexes that backed the old predicate do not help the new one.

This matters more than an index usually does. The queue runs every minute and
takes two slices of it, so an unindexed predicate is a sequential scan of
every open case, twice, sixty times an hour.

On `LEAST(opened_at, created_at)` and not on `opened_at`, because that is the
expression the query uses: a case whose first alert is timestamped in the
future falls back to when we recorded it, and an index on the bare column
would not be used for the expression.

The old indexes are left in place: `last_activity_at` is still what the
expired-case check and the supersession window read.

Revision ID: 046
Revises: 045
"""

from alembic import op

revision = "046"
down_revision = "045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Partial, because the queue only ever asks about open cases, and on this
    # estate they are a few dozen rows out of eleven hundred.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_spine_open_opened
        ON alert_case_spine (LEAST(opened_at, created_at))
        WHERE status = 'open' AND closed_at IS NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_case_spine_open_opened")
