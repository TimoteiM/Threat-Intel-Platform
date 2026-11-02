"""
Whether the analysis an analyst is reading saw the logs the case now holds.

A live alert is analysed on the half of its window that had already happened.
The rest arrives minutes later. Without these two columns there is no way to
tell, at read time, whether the verdict on screen was formed with the full log
context or with a third of it — and an analysis presented as complete when it
was formed on partial context is worse than no log context at all, because it
reads as though the quiet half was checked.

    logs_at_analysis  how many log records existed when the analysis ran
    analysed_at       when that was

`len(logs) - logs_at_analysis` is then the number of events the verdict never
saw, which is the fact the UI shows and the fact that decides whether a re-run
is worth a model call.

Nullable rather than defaulted to 0: rows written before this migration did not
record it, and claiming they were analysed on zero logs would mark every one of
them stale.
"""

from alembic import op
import sqlalchemy as sa

revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_log_context", sa.Column("logs_at_analysis", sa.Integer(), nullable=True))
    op.add_column("alert_log_context", sa.Column("analysed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("alert_log_context", "analysed_at")
    op.drop_column("alert_log_context", "logs_at_analysis")
