"""Tenants have a kind, and c00 is not a customer.

CrowdStrike confirmed on 2026-10-21 that `c00` is Expertware's own estate:
one CID across 176 of 176 devices, every `machine_domain` an
`expertware.net` domain, every OU path ending in `ExpertWare`. It carries
16,552 of 17,640 alert runs. Six documents had called it a customer's, one
of them addressed outward.

Correcting the documents fixes the documents. This column is what stops the
next one: a tenant's kind is a property of the row, so a caller that wants to
describe a population has something to ask instead of something to assume.

`customer` is the default, because that is what a tenant created by an
arriving alert is presumed to be until someone establishes otherwise — and
presuming the safer thing here means presuming "someone else's data".

Revision ID: 074
Revises: 073
"""

from alembic import op
import sqlalchemy as sa

revision = "074"
down_revision = "073"
branch_labels = None
depends_on = None

#: Deliberately a small, closed set. A free-text column would be a third
#: place for "internal" to be spelled differently.
KINDS = ("customer", "internal_estate", "unknown")


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("kind", sa.String(32), nullable=False,
                  server_default=sa.text("'customer'")),
    )
    op.create_check_constraint(
        "ck_tenants_kind",
        "tenants",
        sa.text("kind IN ('customer', 'internal_estate', 'unknown')"),
    )
    # The one row we have evidence for. Everything else keeps the default,
    # because "we have not checked" is not the same as "it is a customer" —
    # and the two Exabeam tenants genuinely cannot be attributed to anyone
    # yet (backlog 47), so they are marked `unknown` rather than assumed.
    op.execute("""
        UPDATE tenants
           SET kind = 'internal_estate',
               notes = COALESCE(notes, '') ||
                 ' Confirmed 2026-10-21 against CrowdStrike: CID '
                 'eed7e41845d04c26b4198f4c85f6216e, 176 of 176 devices on an '
                 'expertware.net domain. This is our own estate, not a customer.'
         WHERE tenant_id = 'c00'
    """)
    op.execute("""
        UPDATE tenants SET kind = 'unknown'
         WHERE tenant_id IN ('lin', 'pov')
    """)


def downgrade() -> None:
    op.drop_constraint("ck_tenants_kind", "tenants", type_="check")
    op.drop_column("tenants", "kind")
