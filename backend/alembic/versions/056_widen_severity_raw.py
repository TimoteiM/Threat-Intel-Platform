"""Give `source_severity_raw` room for what it actually says.

The column was sized at 32 characters for values like `rule.level=15/16`.
Then Fortigate gained two signals and the raw value became
`data.level=alert (also crlevel=low)` — 35 characters — and the backfill
failed on every Fortigate alert carrying both, which is exactly the alerts the
firewall itself graded as attacks.

Widened rather than truncated at the boundary: the point of this column is
that a normalised number can be traced back to what the source said, and a
value cut short mid-sentence cannot be traced to anything.

Revision ID: 056
Revises: 055
"""

from alembic import op
import sqlalchemy as sa

revision = "056"
down_revision = "055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "alert_body_investigation_runs",
        "source_severity_raw",
        type_=sa.String(96),
        existing_type=sa.String(32),
    )


def downgrade() -> None:
    op.alter_column(
        "alert_body_investigation_runs",
        "source_severity_raw",
        type_=sa.String(32),
        existing_type=sa.String(96),
    )
