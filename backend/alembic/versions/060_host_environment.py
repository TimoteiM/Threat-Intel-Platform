"""Record which machines are production and which are test, as a person said so.

Measured 2026-10-12 on `alert_body_investigation_runs`, the week before the
ingestion collapse (2026-09-18..09-24): the estate took 5,477 alerts from 100
hosts, and **2,579 of them — 47% — came from one machine called
`Windows-Test-Device`**. The top two hosts carried 77%.

So every estate-wide figure this platform has produced is substantially a
figure about one test machine: the ATT&CK mapping counts, the backfill's
entity and edge totals, the `ioc_values` prevalence that the pivot work rests
on, the risk-score distribution every band discussion used, and
`windows_eventchannel`'s median day. That is the same defect as a
discriminator true of every row — a statistic whose dominant term is an
artefact rather than the thing being measured — and it is the fifth instance
in this codebase and the largest.

Classified rather than excluded. Alerts from a test host still render and
still investigate, because the answer to misleading data is to label it, not
to hide it. What changes is that anything *claiming to describe the estate*
leaves test hosts out and says so.

Three values, and the third is load-bearing: `unknown` stays visible as
unknown rather than being silently counted as production. A host with no row
has not been judged, which is a different statement from "this is production".

`tier` becomes nullable in the same change. The table's one row per host now
carries two independent judgements, and requiring a criticality tier in order
to record an environment would mean inventing the first to record the second —
the sort of fabricated claim the explicit table exists to prevent.

Revision ID: 060
Revises: 059
"""

from alembic import op
import sqlalchemy as sa

revision = "060"
down_revision = "059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "asset_criticality", "tier",
        existing_type=sa.String(32), nullable=True,
    )
    op.add_column(
        "asset_criticality",
        sa.Column("environment", sa.String(16), nullable=True),
    )
    op.add_column(
        "asset_criticality",
        sa.Column("environment_state", sa.String(16), nullable=True),
    )
    op.add_column(
        "asset_criticality",
        sa.Column("environment_reason", sa.Text, nullable=True),
    )
    op.create_index(
        "ix_asset_criticality_environment", "asset_criticality", ["environment"]
    )
    # A row must say something. Without this, a row carrying neither judgement
    # is indistinguishable from no row at all, and "we looked and recorded
    # nothing" would read the same as "nobody looked".
    op.create_check_constraint(
        "ck_asset_criticality_says_something",
        "asset_criticality",
        "tier is not null or environment is not null",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_asset_criticality_says_something", "asset_criticality", type_="check"
    )
    op.drop_index("ix_asset_criticality_environment", table_name="asset_criticality")
    op.drop_column("asset_criticality", "environment_reason")
    op.drop_column("asset_criticality", "environment_state")
    op.drop_column("asset_criticality", "environment")
    op.execute("update asset_criticality set tier = 'normal' where tier is null")
    op.alter_column(
        "asset_criticality", "tier",
        existing_type=sa.String(32), nullable=False,
    )
