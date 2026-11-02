"""
Trigram indexes for assistant search.

Search was a LEFT JOIN from sessions to entries with an ILIKE on both sides and
a `count(DISTINCT id)` beside it. The page cost 61 ms and the count 6,153 ms,
because the count has to evaluate the predicate over all 201 MB of entry text.

These make the *selective* half of that fast. Measured on this data:

    page, rare term ("kerberoast")     61 ms  ->    5 ms
    count, rare term                 6,153 ms ->  174 ms
    page, common term ("process")                6,811 ms

The common term stays slow and no index fixes it: "process" appears in 83% of
the entry text, so the index returns most of the table and Postgres rechecks
each candidate against a TOASTed 14 kB average. That is real work, not a
missing index — which is why content search is now opt-in and the default
searches titles alone, in 39 ms.

55 MB for the entry index, 3.6 MB for titles. Built with CONCURRENTLY: a plain
CREATE INDEX on 201 MB holds a write lock for the ~48 s it takes, and alerts
are being ingested the whole time.
"""

from alembic import op
import sqlalchemy as sa

revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction.
    with op.get_context().autocommit_block():
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assistant_entries_raw_trgm "
            "ON assistant_entries USING gin (raw_text gin_trgm_ops)"
        )
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assistant_sessions_title_trgm "
            "ON assistant_sessions USING gin (title gin_trgm_ops)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_assistant_sessions_title_trgm")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_assistant_entries_raw_trgm")
