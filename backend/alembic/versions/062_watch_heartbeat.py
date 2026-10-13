"""Record when each scheduled watch last finished.

Five watch tasks returned results that nothing read. When they began failing,
the only evidence was a log line carrying the exception type and not its
message, and it went unnoticed for about a month — including the pipeline
stall watchdog, whose own reason for existing is that a dying worker and an
idle worker produce the same queue.

Revision ID: 062
Revises: 061
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "062"
down_revision = "061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `app/main.py` runs `Base.metadata.create_all` at startup, so a new table
    # can appear from the model before its migration runs — which is what
    # happened here: the API was recreated first and this then failed with
    # DuplicateTable, leaving alembic on 061 with the table already present.
    # Guarded so the two orders converge instead of racing.
    inspector = sa.inspect(op.get_bind())
    if "watch_heartbeat" in inspector.get_table_names():
        return

    op.create_table(
        "watch_heartbeat",
        sa.Column("task", sa.String(length=120), primary_key=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "failures_since", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    # Deliberately no backfill. A row inserted at migration time would claim a
    # heartbeat nobody observed, and the absence of a row is the correct
    # reading for a watch that has not reported since this deployed — the same
    # reasoning as 061, which backdated to `created_at` because there the
    # earlier state was knowable and here it is not.


def downgrade() -> None:
    op.drop_table("watch_heartbeat")
