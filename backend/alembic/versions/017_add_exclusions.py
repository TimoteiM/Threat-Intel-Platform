"""add the exclusion list (indicators treated as benign without collection)

Revision ID: 017
Revises: 016
Create Date: 2026-08-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exclusions",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("indicator_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("normalized_value", sa.String(length=512), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("added_by", sa.String(length=255), nullable=True),
        sa.Column("match_subdomains", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("indicator_type", "normalized_value", name="uq_exclusion_type_value"),
    )
    # Every alert run loads the active set once; this is the query it makes.
    op.create_index("idx_exclusions_active", "exclusions", ["active", "indicator_type"])


def downgrade() -> None:
    op.drop_index("idx_exclusions_active", table_name="exclusions")
    op.drop_table("exclusions")
