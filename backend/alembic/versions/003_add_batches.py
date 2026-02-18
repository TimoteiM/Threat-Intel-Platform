"""add batches table and batch_id FK on investigations

Revision ID: 003
Revises: 002
Create Date: 2026-02-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create batches table
    op.create_table(
        "batches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("total_domains", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completed_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(50), nullable=False, server_default="created"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_batches_created", "batches", ["created_at"])
    op.create_index("idx_batches_status", "batches", ["status"])

    # Add batch_id FK to investigations
    op.add_column(
        "investigations",
        sa.Column(
            "batch_id",
            UUID(as_uuid=True),
            sa.ForeignKey("batches.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("idx_investigations_batch", "investigations", ["batch_id"])


def downgrade() -> None:
    op.drop_index("idx_investigations_batch", table_name="investigations")
    op.drop_column("investigations", "batch_id")
    op.drop_index("idx_batches_status", table_name="batches")
    op.drop_index("idx_batches_created", table_name="batches")
    op.drop_table("batches")
