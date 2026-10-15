"""indicator_lookups: who asked what, before the attribution schema exists

A pure addition, which is the safe shape: no rename, no column change, no
backfill. Code that predates this table simply does not use it, so the
split-brain described in `docs/deploy/schema-changes.md` — where a migration
changes every container at once and a rebuild changes one — cannot apply.

**Idempotent, because `create_all` also creates tables.** `app/main.py` runs
`Base.metadata.create_all` at startup, so whichever of the two gets there
first wins and the other must not fail. On 2026-10-15 the api restarted before
this migration ran, `create_all` made the table, and `alembic upgrade head`
then died on `DuplicateTable` and left the version at 063 — the table present
and unrecorded. Migrations 062 and 063 already guard this way; this one did
not, which is the whole reason it is written down here.

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
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    if "indicator_lookups" in existing:
        # Created by `create_all` already. Nothing to do, and failing here
        # would leave the version behind the schema.
        return

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
    inspector = sa.inspect(op.get_bind())
    if "indicator_lookups" not in set(inspector.get_table_names()):
        return
    op.drop_index("ix_indicator_lookups_tenant_id", table_name="indicator_lookups")
    op.drop_index("idx_indicator_lookups_actor", table_name="indicator_lookups")
    op.drop_index("idx_indicator_lookups_created", table_name="indicator_lookups")
    op.drop_table("indicator_lookups")
