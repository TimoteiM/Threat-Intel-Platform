"""add anyrun proxy request fields

Revision ID: 012
Revises: 011
Create Date: 2026-07-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column(
            "anyrun_use_residential_proxy",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "investigations",
        sa.Column("anyrun_proxy_country", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigations", "anyrun_proxy_country")
    op.drop_column("investigations", "anyrun_use_residential_proxy")
