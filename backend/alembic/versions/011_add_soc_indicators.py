"""add soc indicators

Revision ID: 011
Revises: 010
Create Date: 2026-05-12
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soc_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("indicator_type", sa.String(length=30), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column("normalized_value", sa.String(length=1024), nullable=False),
        sa.Column("token", sa.String(length=80), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False, server_default="assistant"),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("confidence", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("assistant_session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("assistant_entry_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["assistant_entry_id"], ["assistant_entries.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assistant_session_id"], ["assistant_sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_soc_indicators_indicator_type", "soc_indicators", ["indicator_type"])
    op.create_index("ix_soc_indicators_value", "soc_indicators", ["value"])
    op.create_index("ix_soc_indicators_normalized_value", "soc_indicators", ["normalized_value"])
    op.create_index("idx_soc_indicators_normalized", "soc_indicators", ["indicator_type", "normalized_value"])
    op.create_index("idx_soc_indicators_session", "soc_indicators", ["assistant_session_id"])
    op.create_index("idx_soc_indicators_entry", "soc_indicators", ["assistant_entry_id"])
    op.create_index("idx_soc_indicators_investigation", "soc_indicators", ["investigation_id"])
    op.create_index("idx_soc_indicators_seen", "soc_indicators", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("idx_soc_indicators_seen", table_name="soc_indicators")
    op.drop_index("idx_soc_indicators_investigation", table_name="soc_indicators")
    op.drop_index("idx_soc_indicators_entry", table_name="soc_indicators")
    op.drop_index("idx_soc_indicators_session", table_name="soc_indicators")
    op.drop_index("idx_soc_indicators_normalized", table_name="soc_indicators")
    op.drop_index("ix_soc_indicators_normalized_value", table_name="soc_indicators")
    op.drop_index("ix_soc_indicators_value", table_name="soc_indicators")
    op.drop_index("ix_soc_indicators_indicator_type", table_name="soc_indicators")
    op.drop_table("soc_indicators")
