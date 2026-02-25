"""Add ip_lookups table for IP reputation lookup history

Revision ID: 006
Revises: 005
Create Date: 2026-02-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_lookups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("abuse_score", sa.Integer, nullable=True),
        sa.Column("isp", sa.String(255), nullable=True),
        sa.Column("country_code", sa.String(10), nullable=True),
        sa.Column("threatfox_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("result_json", JSONB, nullable=False),
        sa.Column(
            "queried_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("idx_ip_lookups_ip", "ip_lookups", ["ip"])
    op.create_index("idx_ip_lookups_queried", "ip_lookups", ["queried_at"])


def downgrade() -> None:
    op.drop_index("idx_ip_lookups_queried", table_name="ip_lookups")
    op.drop_index("idx_ip_lookups_ip", table_name="ip_lookups")
    op.drop_table("ip_lookups")
