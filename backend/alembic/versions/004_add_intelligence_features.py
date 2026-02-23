"""add watchlist, watchlist_alerts, and whois_history tables

Revision ID: 004
Revises: 003
Create Date: 2026-02-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Watchlist table
    op.create_table(
        "watchlist",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alert_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("idx_watchlist_domain", "watchlist", ["domain"])
    op.create_index("idx_watchlist_status", "watchlist", ["status"])

    # Watchlist alerts table
    op.create_table(
        "watchlist_alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "watchlist_id",
            UUID(as_uuid=True),
            sa.ForeignKey("watchlist.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("details_json", JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("acknowledged", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index("idx_watchlist_alerts_wl", "watchlist_alerts", ["watchlist_id"])

    # WHOIS history table
    op.create_table(
        "whois_history",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("whois_json", JSONB, nullable=False),
        sa.Column(
            "captured_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "investigation_id",
            UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("changes_from_previous", JSONB, nullable=True),
    )
    op.create_index("idx_whois_history_domain", "whois_history", ["domain"])
    op.create_index("idx_whois_history_captured", "whois_history", ["captured_at"])


def downgrade() -> None:
    op.drop_index("idx_whois_history_captured", table_name="whois_history")
    op.drop_index("idx_whois_history_domain", table_name="whois_history")
    op.drop_table("whois_history")

    op.drop_index("idx_watchlist_alerts_wl", table_name="watchlist_alerts")
    op.drop_table("watchlist_alerts")

    op.drop_index("idx_watchlist_status", table_name="watchlist")
    op.drop_index("idx_watchlist_domain", table_name="watchlist")
    op.drop_table("watchlist")
