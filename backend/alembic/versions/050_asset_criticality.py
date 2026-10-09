"""Record which machines matter, as a person said so.

The graph needs to badge a crown jewel, and the obvious shortcut is a name
pattern. It is not available: `EXP-DC-01` matches `-DC-` and so does
`EXP-DCOM-02`, while a domain controller named `EXP-SRV-09` matches nothing.
That is the delimiter-boundary failure this codebase has hit six times, and
here it fails silently in both directions — a badge appearing on the wrong
machine and missing from the right one, on the most persuasive mark the graph
draws.

So: an explicit table, three states, and absence of a row means *unknown*
rather than *not important*. A seeding helper may propose candidates, from
name patterns and from observed behaviour such as being the target of
`nltest /dclist`, but every proposal lands `proposed` and a person promotes
it.

Revision ID: 050
Revises: 049
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "050"
down_revision = "049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_criticality",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        # The short lowercased label, which is what the graph merges hosts on.
        sa.Column("host", sa.String(255), nullable=False, unique=True),
        sa.Column("tier", sa.String(32), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="proposed"),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("set_by", sa.String(255), nullable=True),
        sa.Column(
            "set_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_asset_criticality_host", "asset_criticality", ["host"])
    op.create_index("ix_asset_criticality_state", "asset_criticality", ["state"])


def downgrade() -> None:
    op.drop_index("ix_asset_criticality_state", table_name="asset_criticality")
    op.drop_index("ix_asset_criticality_host", table_name="asset_criticality")
    op.drop_table("asset_criticality")
