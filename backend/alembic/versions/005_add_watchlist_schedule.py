"""add schedule_interval and next_check_at to watchlist

Revision ID: 005
Revises: 004
Create Date: 2026-02-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "watchlist",
        sa.Column("schedule_interval", sa.String(20), nullable=True),
    )
    op.add_column(
        "watchlist",
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_watchlist_next_check", "watchlist", ["next_check_at"])


def downgrade() -> None:
    op.drop_index("idx_watchlist_next_check", table_name="watchlist")
    op.drop_column("watchlist", "next_check_at")
    op.drop_column("watchlist", "schedule_interval")
