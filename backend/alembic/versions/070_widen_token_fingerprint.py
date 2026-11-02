"""Widen the scope fingerprint from 6 hex characters to 12

The fingerprint is what makes a token belong to one tenant and one
investigation, and a collision makes the cross-tenant check pass — the one
check whose failure is a confident answer about another customer's estate.

So the bound that matters is the **birthday** bound, not the preimage one. At
24 bits a 50% chance of some pair of scopes colliding arrives at roughly 4,800
scopes, which an estate reaches in about a month of investigations. At 48 bits
it is roughly 20 million.

Existing rows are **deleted rather than migrated**. A row's stored fingerprint
was computed at the old width, so every token it issued is six characters wide
and no longer parses; re-deriving the fingerprint would leave the map holding
tokens that cannot be matched to it. These maps are ephemeral by design — they
carry a TTL and are purged — so dropping them costs a re-tokenisation and
keeping them would cost a map whose tokens silently resolve to nothing.

Idempotent, because `create_all` is a second schema authority — backlog 25.

Revision ID: 070
Revises: 069
"""

from alembic import op
import sqlalchemy as sa

revision = "070"
down_revision = "069"
branch_labels = None
depends_on = None

_TABLE = "investigation_token_maps"
_COLUMN = "fingerprint"
_WIDTH = 16


def _width(bind) -> int | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(_TABLE):
        return None
    for column in inspector.get_columns(_TABLE):
        if column["name"] == _COLUMN:
            return getattr(column["type"], "length", None)
    return None


def upgrade() -> None:
    bind = op.get_bind()
    current = _width(bind)
    if current is None:
        return
    if current >= _WIDTH:
        return

    # Before widening, not after: a row whose tokens are six characters wide
    # cannot resolve any of them once the grammar expects twelve.
    op.execute(sa.text(f"DELETE FROM {_TABLE}"))
    op.alter_column(
        _TABLE, _COLUMN,
        existing_type=sa.String(current),
        type_=sa.String(_WIDTH),
        existing_nullable=False,
    )


def downgrade() -> None:
    bind = op.get_bind()
    current = _width(bind)
    if current is None or current <= 8:
        return
    op.execute(sa.text(f"DELETE FROM {_TABLE}"))
    op.alter_column(
        _TABLE, _COLUMN,
        existing_type=sa.String(current),
        type_=sa.String(8),
        existing_nullable=False,
    )
