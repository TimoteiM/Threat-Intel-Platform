"""indicator_lookups: who asked what, before the attribution schema exists

A pure addition, which is the safe shape: no rename, no column change, no
backfill. Code that predates this table simply does not use it, so the
split-brain described in `docs/deploy/schema-changes.md` — where a migration
changes every container at once and a rebuild changes one — cannot apply.

Revision ID: 064
Revises: 063
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "064"
down_revision = "063"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "indicator_lookups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=True),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("sources_asked", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("idx_indicator_lookups_created", "indicator_lookups", ["created_at"])
    op.create_index("idx_indicator_lookups_actor", "indicator_lookups", ["actor"])
    op.create_index("ix_indicator_lookups_tenant_id", "indicator_lookups", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_indicator_lookups_tenant_id", table_name="indicator_lookups")
    op.drop_index("idx_indicator_lookups_actor", table_name="indicator_lookups")
    op.drop_index("idx_indicator_lookups_created", table_name="indicator_lookups")
    op.drop_table("indicator_lookups")
