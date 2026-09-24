"""
The logs around an alert, and the record of how much of them has been read.

Why this is a table rather than a key in `alert_body_investigation_runs.result_json`:

A real-time alert's window ends in the future, so the read happens in two
parts — what exists now, and the remainder once the window has closed. The
second part is a Celery task that may run minutes later, may be retried, and
must not duplicate what the first part already returned. That needs three
durable facts the run's payload cannot safely hold:

    covered_until  — exactly where the next read starts
    attempts       — so a cluster that is down all afternoon stops being asked
    logs           — keyed by the document's own `index:id`, so a merge is a
                     union and a retry is a no-op

`result_json` is rewritten wholesale by the analysis pipeline every time a run
is re-analysed. That is not a theory: the same pattern silently dropped a CAPE
sandbox report that had been written into an investigation's evidence blob by a
late-arriving task. Follow-up state that another writer can replace is not
durable, so it lives in its own row with its own key.

One row per run, enforced by a unique constraint rather than by convention: two
workers racing on the same live alert must converge on one record, for the same
reason a sandbox submission does.

The index on (status, next_attempt_at) is what the sweep reads. It is a partial
index over the two non-terminal states, because the sweep asks "what is still
owed" every minute and the answer is almost always none — a full scan of every
alert ever ingested to find nothing is a cost paid per minute for ever.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_log_context",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # collected | partial | empty | unavailable | skipped | failed
        sa.Column("status", sa.String(20), nullable=False, server_default="partial"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        # The high-water mark. The next read starts here and never before it,
        # which is what makes the follow-up idempotent rather than merely
        # deduplicated after the fact.
        sa.Column("covered_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("logs", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("selectors", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("sources", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("run_id", name="uq_alert_log_context_run"),
    )
    op.create_index(
        "idx_alert_log_context_due",
        "alert_log_context",
        ["next_attempt_at"],
        postgresql_where=sa.text("status IN ('partial', 'unavailable')"),
    )


def downgrade() -> None:
    op.drop_index("idx_alert_log_context_due", table_name="alert_log_context")
    op.drop_table("alert_log_context")
