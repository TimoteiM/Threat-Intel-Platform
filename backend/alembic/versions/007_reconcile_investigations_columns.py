"""reconcile missing investigations columns on partially migrated databases

Revision ID: 007
Revises: 006
Create Date: 2026-03-03
"""

from typing import Sequence, Union

from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Some environments have tables from later revisions but an out-of-date
    # alembic_version row. Make this migration idempotent with IF NOT EXISTS.
    op.execute(
        """
        ALTER TABLE investigations
        ADD COLUMN IF NOT EXISTS client_domain VARCHAR(255)
        """
    )
    op.execute(
        """
        ALTER TABLE investigations
        ADD COLUMN IF NOT EXISTS batch_id UUID
        """
    )
    op.execute(
        """
        ALTER TABLE investigations
        ADD COLUMN IF NOT EXISTS observable_type VARCHAR(20) NOT NULL DEFAULT 'domain'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_investigations_batch
        ON investigations (batch_id)
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'batches'
            ) AND NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'investigations_batch_id_fkey'
            ) THEN
                ALTER TABLE investigations
                ADD CONSTRAINT investigations_batch_id_fkey
                FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE SET NULL;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'investigations_batch_id_fkey'
            ) THEN
                ALTER TABLE investigations
                DROP CONSTRAINT investigations_batch_id_fkey;
            END IF;
        END
        $$;
        """
    )
    op.execute("DROP INDEX IF EXISTS idx_investigations_batch")
    op.execute("ALTER TABLE investigations DROP COLUMN IF EXISTS batch_id")
    op.execute("ALTER TABLE investigations DROP COLUMN IF EXISTS client_domain")
