"""Give a case a number, a closing time, and the case it continues from.

Cases are about to close themselves. An analyst who used to open one by hand,
merge what belonged, and write a resolution will instead read a case that has
already done all three — so the things that job produced have to exist as
data: when it closed, what it concluded, how long it took, and which earlier
case it carries on from.

`case_number` is the human handle. `case_key` is a sha256 and always will be,
because it has to be derivable from the events; nobody says "sha256 9f3c…" out
loud. The number comes from a sequence so it is assigned once, in order, and
never recomputed — the same reason the key is derived from event time and not
from a position in a query.

Measured on the existing data before building this: of 821 alerts arriving
after a ten-minute quiet period, 811 (99%) were another instance of a
detection the case already held, and only 10 brought a detection it had not
seen. That ratio is why `closed_at` is a real boundary and not a suggestion —
a straggler that adds nothing does not reopen anything.

Revision ID: 039
Revises: 038
"""

from alembic import op
import sqlalchemy as sa

revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE IF NOT EXISTS alert_case_number_seq AS BIGINT START 1")

    op.add_column("alert_case_spine", sa.Column("case_number", sa.BigInteger(), nullable=True))
    # The label an analyst reads, frozen when the case closes. Recomputing it
    # from members would make a closed case's title drift as the estate
    # changes around it, and a continuation that names the case it follows
    # would then name it differently from the case itself.
    op.add_column("alert_case_spine", sa.Column("title", sa.Text(), nullable=True))
    op.add_column("alert_case_spine", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    # auto | analyst | superseded — who ended it.
    op.add_column("alert_case_spine", sa.Column("closure_kind", sa.String(length=32), nullable=True))
    op.add_column("alert_case_spine", sa.Column("resolution", sa.String(length=32), nullable=True))
    op.add_column("alert_case_spine", sa.Column("alerts_at_close", sa.Integer(), nullable=True))
    # The earlier case this one carries on from, when a genuinely new detection
    # arrived after that one had closed. Not `superseded_by_case_key`, which
    # points the other way and means "this one was absorbed".
    op.add_column("alert_case_spine", sa.Column("continues_case_key", sa.String(length=64), nullable=True))
    # When the closing job last looked, so a case cannot be closed twice by two
    # overlapping runs of a job that fires every minute.
    op.add_column("alert_case_spine", sa.Column("closure_claimed_at", sa.DateTime(timezone=True), nullable=True))

    # Oldest case is #1. Numbering by opened_at rather than by insertion order
    # so the sequence matches the order things actually happened.
    op.execute(
        """
        WITH ordered AS (
            SELECT case_key, row_number() OVER (ORDER BY opened_at, case_key) AS n
            FROM alert_case_spine
        )
        UPDATE alert_case_spine s
        SET case_number = ordered.n
        FROM ordered
        WHERE s.case_key = ordered.case_key
        """
    )
    op.execute(
        "SELECT setval('alert_case_number_seq', "
        "GREATEST((SELECT COALESCE(MAX(case_number), 0) FROM alert_case_spine), 1))"
    )

    op.create_unique_constraint(
        "uq_alert_case_spine_case_number", "alert_case_spine", ["case_number"]
    )
    # `idx_case_spine_open_activity` (status, last_activity_at) already exists
    # from 025 and is exactly what the closing job scans on, so it is reused
    # rather than created again.
    op.create_index(
        "idx_case_spine_continues", "alert_case_spine", ["continues_case_key"]
    )


def downgrade() -> None:
    op.drop_index("idx_case_spine_continues", table_name="alert_case_spine")
    op.drop_constraint("uq_alert_case_spine_case_number", "alert_case_spine", type_="unique")
    for column in (
        "closure_claimed_at", "continues_case_key", "alerts_at_close",
        "resolution", "closure_kind", "closed_at", "title", "case_number",
    ):
        op.drop_column("alert_case_spine", column)
    op.execute("DROP SEQUENCE IF EXISTS alert_case_number_seq")
