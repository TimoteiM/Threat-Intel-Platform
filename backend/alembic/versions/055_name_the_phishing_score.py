"""Give the phishing score a name that says what it scores.

`highest_risk_score` reads as universal — the highest risk, of anything. It is
the maximum, over an alert's extracted indicators, of a seven-component
weighted sum in risk_aggregator.py, and five of those seven components are
URL, email, attachment and sandbox signals, with a step-floor from OpenCTI.
So it is a phishing-and-reputation score with a threat-intel floor, and it
cannot rank endpoint severity at all: Windows alerts average 8.8 against
Fortigate's 62.0, which is a measure of how much of the formula each source
can reach rather than a severity difference between them.

Measured on `alert_body_investigation_runs`, which is the right table because
it is the one every consumer of this column reads — the case score, the alert
list and, until migration 054, the graph's risk arc.

The wire field keeps its name. `highest_risk_score` is in the outbound
callback payload at app/tasks/alert_callback_task.py, and breaking an external
contract to fix an internal naming problem is not a trade worth making. A
comment at that boundary says the external name is retained deliberately.

Revision ID: 055
Revises: 054
"""

from alembic import op
import sqlalchemy as sa

revision = "055"
down_revision = "054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "alert_body_investigation_runs",
        "highest_risk_score",
        new_column_name="indicator_risk_score",
    )


def downgrade() -> None:
    op.alter_column(
        "alert_body_investigation_runs",
        "indicator_risk_score",
        new_column_name="highest_risk_score",
    )
