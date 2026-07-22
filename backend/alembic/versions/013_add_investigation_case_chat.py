"""add durable investigation case chat

Revision ID: 013
Revises: 012
Create Date: 2026-07-20
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_case_chat_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=True),
        sa.Column("evidence_refs_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("limitations_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("suggested_followups_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_case_chat_investigation", "investigation_case_chat_messages", ["investigation_id"])
    op.create_index(
        "idx_case_chat_investigation_created",
        "investigation_case_chat_messages",
        ["investigation_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_case_chat_investigation_created", table_name="investigation_case_chat_messages")
    op.drop_index("idx_case_chat_investigation", table_name="investigation_case_chat_messages")
    op.drop_table("investigation_case_chat_messages")
