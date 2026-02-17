"""add client_domain to investigations

Revision ID: 002
Revises: 001
Create Date: 2026-02-16
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("client_domain", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigations", "client_domain")
