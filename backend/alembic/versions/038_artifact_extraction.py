"""Store what an upload's content extraction found, so the password need not travel.

An encrypted archive can only be read with the analyst's password. The
extraction therefore has to happen in the request that carries it — the
alternative is handing the password to a Celery task, which means a plaintext
archive password sitting in the Redis broker and in whatever the result
backend keeps. It is used and discarded instead, and what it produced is
stored here for the analysis task to pick up.

The column holds the same shape the task would have produced itself, so a file
that needed no password still takes the old path and this stays null.

Revision ID: 038
Revises: 037
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "038"
down_revision = "037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "artifacts",
        sa.Column("extraction_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("artifacts", "extraction_json")
