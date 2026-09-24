"""
Keep the version of a report that is safe to show a model again.

A finished report is de-anonymised for the analyst: `[HOST_1]` becomes the real
hostname, `[ACCOUNT_1]` the real account, and a "Resolved Identifiers" table is
appended mapping every token back to its value. That is correct for the person
reading it and wrong for anything that reads it afterwards.

Correlated-case narratives read it afterwards. `_gather_resolutions` collects
each member's `report_markdown` and puts it in the evidence for a *new* model
call, so the de-anonymised prose and the token table both went back out. Tested
against the real sanitiser: hostname and IP are re-tokenised on the way (leaving
a useless `[HOST_1] | Hostname | [HOST_1]` row that costs tokens and says
nothing), but a bare account name in a table cell matches none of the keyed
account patterns and reached the provider in the clear.

So the pre-restoration text is kept. It is what the model produced, before
tokens were resolved, and it is the only version that should ever be model input
again.

Nullable, with no backfill: the resolved text for existing sessions cannot be
un-resolved, and inventing one would be worse than the caller falling back to
stripping the table from it.
"""

from alembic import op
import sqlalchemy as sa

revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assistant_sessions",
        sa.Column("report_markdown_model_safe", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assistant_sessions", "report_markdown_model_safe")
