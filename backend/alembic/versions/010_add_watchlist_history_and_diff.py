"""add risk_score_history and evidence_diff_json to watchlist

Revision ID: 010
Revises: 009
Create Date: 2026-04-21
"""

from typing import Sequence, Union

from alembic import op

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE watchlist
            ADD COLUMN IF NOT EXISTS risk_score_history JSONB,
            ADD COLUMN IF NOT EXISTS evidence_diff_json  JSONB;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE watchlist
            DROP COLUMN IF EXISTS risk_score_history,
            DROP COLUMN IF EXISTS evidence_diff_json;
        """
    )
