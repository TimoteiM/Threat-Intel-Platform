"""
An index for the daily-activity widget.

The widget asks one question — how many alert analyses completed in the last
two days — and answered it by reading every session ever stored:

    Seq Scan on assistant_sessions  (actual time=0.507..18.300 rows=1902)
      Rows Removed by Filter: 20708
      Buffers: shared hit=1299 read=4019

21.7 ms today at 22,610 sessions, and the discarded 20,708 is the part that
grows. Nothing about the answer gets harder over time; only the scan does. At
the current rate of roughly 950 completed analyses a day this crosses 100 ms
inside a year, which is the shape an analyst reports as the page getting
slower the longer it is in service.

Partial, because the widget only ever counts completed alert analyses, so the
predicate belongs in the index rather than in rows the scan has to reject. It
covers about 8% of the table.
"""

from alembic import op

revision = "035"
down_revision = "034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction, and alerts are ingested
    # continuously — a plain CREATE INDEX would hold a write lock throughout.
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
            "idx_assistant_sessions_alert_completed "
            "ON assistant_sessions (completed_at DESC) "
            "WHERE mode = 'alert_analysis' "
            "AND status = 'completed' "
            "AND completed_at IS NOT NULL"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS "
            "idx_assistant_sessions_alert_completed"
        )
