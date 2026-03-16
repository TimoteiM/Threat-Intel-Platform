"""add ai assistant sessions and entries

Revision ID: 009
Revises: 008
Create Date: 2026-03-16
"""

from typing import Sequence, Union

from alembic import op

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS assistant_sessions (
            id UUID PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            mode VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'draft',
            source_type VARCHAR(30) NOT NULL DEFAULT 'manual',
            linked_investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
            sanitization_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            report_markdown TEXT,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS assistant_entries (
            id UUID PRIMARY KEY,
            session_id UUID NOT NULL REFERENCES assistant_sessions(id) ON DELETE CASCADE,
            entry_index INTEGER NOT NULL DEFAULT 0,
            entry_label VARCHAR(255),
            raw_text TEXT NOT NULL,
            sanitized_text TEXT NOT NULL,
            token_map_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'draft'
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS source_type VARCHAR(30) NOT NULL DEFAULT 'manual'
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS linked_investigation_id UUID
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS sanitization_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS result_json JSONB NOT NULL DEFAULT '{}'::jsonb
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS report_markdown TEXT
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS error TEXT
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_sessions
        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ
        """
    )

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'assistant_sessions_linked_investigation_id_fkey'
            ) THEN
                ALTER TABLE assistant_sessions
                ADD CONSTRAINT assistant_sessions_linked_investigation_id_fkey
                FOREIGN KEY (linked_investigation_id) REFERENCES investigations(id) ON DELETE SET NULL;
            END IF;
        END
        $$;
        """
    )

    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS entry_index INTEGER NOT NULL DEFAULT 0
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS entry_label VARCHAR(255)
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS raw_text TEXT NOT NULL DEFAULT ''
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS sanitized_text TEXT NOT NULL DEFAULT ''
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS token_map_json JSONB NOT NULL DEFAULT '{}'::jsonb
        """
    )
    op.execute(
        """
        ALTER TABLE assistant_entries
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_sessions_created
        ON assistant_sessions (created_at)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_sessions_mode
        ON assistant_sessions (mode)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_sessions_status
        ON assistant_sessions (status)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_sessions_investigation
        ON assistant_sessions (linked_investigation_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_entries_session
        ON assistant_entries (session_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_assistant_entries_session_order
        ON assistant_entries (session_id, entry_index)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_assistant_entries_session_order")
    op.execute("DROP INDEX IF EXISTS idx_assistant_entries_session")
    op.execute("DROP INDEX IF EXISTS idx_assistant_sessions_investigation")
    op.execute("DROP INDEX IF EXISTS idx_assistant_sessions_status")
    op.execute("DROP INDEX IF EXISTS idx_assistant_sessions_mode")
    op.execute("DROP INDEX IF EXISTS idx_assistant_sessions_created")
    op.execute("DROP TABLE IF EXISTS assistant_entries")
    op.execute("DROP TABLE IF EXISTS assistant_sessions")
