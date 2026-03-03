"""add email investigation runs table and async status fields

Revision ID: 008
Revises: 007
Create Date: 2026-03-03
"""

from typing import Sequence, Union

from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS email_investigation_runs (
            id UUID PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            email_subject VARCHAR(512),
            sender_email VARCHAR(255),
            sender_domain VARCHAR(255),
            sender_ip VARCHAR(64),
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            task_id VARCHAR(64),
            error TEXT,
            resolution_source VARCHAR(50) NOT NULL DEFAULT 'queued',
            result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
        """
    )

    op.execute("ALTER TABLE email_investigation_runs ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'queued'")
    op.execute("ALTER TABLE email_investigation_runs ADD COLUMN IF NOT EXISTS task_id VARCHAR(64)")
    op.execute("ALTER TABLE email_investigation_runs ADD COLUMN IF NOT EXISTS error TEXT")
    op.execute("ALTER TABLE email_investigation_runs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ")
    op.execute("ALTER TABLE email_investigation_runs ADD COLUMN IF NOT EXISTS resolution_source VARCHAR(50) NOT NULL DEFAULT 'queued'")

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_email_runs_created
        ON email_investigation_runs (created_at)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_email_runs_status
        ON email_investigation_runs (status)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_email_runs_status")
    op.execute("DROP INDEX IF EXISTS idx_email_runs_created")
    op.execute("DROP TABLE IF EXISTS email_investigation_runs")
