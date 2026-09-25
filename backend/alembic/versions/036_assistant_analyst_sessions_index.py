"""
An index for the assistant's own session list.

The list now shows only sessions an analyst started — `manual` and
`from_investigation`, 627 rows — and hides the 22,048 that other features
created while using the assistant as an engine. Without an index that filter
is a full scan that reads 22,675 rows to return five, and its cost grows with
alert volume rather than with anything the analyst did.

Partial and covering: `source_type` is in the predicate rather than the key,
because the set of analyst source types is fixed, and `created_at DESC` is the
sort every page applies. 2.7% of the table.

`get_session` is deliberately untouched. Opening a session by id never
filtered, so the `/assistant?session=<id>` links from an alert investigation
and a case narrative keep working.
"""

from alembic import op

revision = "036"
down_revision = "035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction, and alerts are ingested
    # continuously — a plain CREATE INDEX would hold a write lock throughout.
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
            "idx_assistant_sessions_analyst "
            "ON assistant_sessions (created_at DESC) "
            "WHERE source_type IN ('manual', 'from_investigation')"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS idx_assistant_sessions_analyst"
        )
