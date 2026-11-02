"""Record who closed a case, on what, and why.

`CaseClosureKind.ANALYST` has always been documented as "a person closed it,
and closed_by says who" — describing a column that did not exist. The analyse
endpoint computed a `closed_by` from the caller's identity, returned it in the
response and threw it away, so every case closed by a person was
indistinguishable from every other.

Three columns, because a manual close is a decision and a decision needs its
circumstances:

  closed_by        who signed it off
  closure_note     why, in their words, when they chose to say
  closed_narrative_fingerprint
                   which analysis was in front of them

The fingerprint matters more than it looks. `narrative_markdown`,
`narrative_status` and `narrative_fingerprint` are rewritten unconditionally
whenever correlation dispatches a fresh narrative, and it does that whenever
the case's score, member count or tactics move — including for a closed case.
The resolution is protected from that rewrite; the evidence is not. Without
this column an analyst's sign-off silently re-attaches itself to an analysis
they never read.

Revision ID: 042
Revises: 041
"""

from alembic import op
import sqlalchemy as sa

revision = "042"
down_revision = "041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_case_spine", sa.Column("closed_by", sa.String(255), nullable=True))
    op.add_column("alert_case_spine", sa.Column("closure_note", sa.Text(), nullable=True))
    op.add_column(
        "alert_case_spine",
        sa.Column("closed_narrative_fingerprint", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("alert_case_spine", "closed_narrative_fingerprint")
    op.drop_column("alert_case_spine", "closure_note")
    op.drop_column("alert_case_spine", "closed_by")
