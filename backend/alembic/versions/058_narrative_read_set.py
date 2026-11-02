"""Record which alerts a narrative was written over.

Not a freeze. A freeze happens on judgement — resolution, close, supersession,
an analyst's own conclusion. An AI narrative commissioned early does not
freeze a case, because turning "ask for an early read" into "stop accepting
alerts" would make `analyse_case_now` cost something invisible at the point of
use.

What this records is what was on screen: the membership the narrative was
actually written over, with the derivation version that produced it. A
narrative can then be checked against the alerts it described, and if the case
later accretes, the divergence is visible instead of silent.

This is the cheapest point to start closing a gap the E2 measurement exposed.
Of 1,698 narratives in this estate, **zero** name a single alert — not a run
id, not a Wazuh alert id — and the five analyst-closed cases name no more than
the 1,674 automatic ones. This platform has never recorded what anyone was
looking at when they formed a judgement. A backfill cannot fix that; only
recording it from now on can.

Why it matters more than it sounds: measured by simulating today's freeze rule
against the real alert stream, 236 of 1,014 cases (23.3%) accrete after the
freeze, and those late arrivals account for 3,197 of 5,523 alert memberships
(57.9%). On larger cases it is the norm — 95.5% of cases holding 21+ alerts
grow after the freeze. So a narrative describing "the alerts in this case" is
describing a set that changes underneath it most of the time, and until now
there was no way to tell.

Revision ID: 058
Revises: 057
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "058"
down_revision = "057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_read_set",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("case_key", sa.String(64), nullable=False),
        # What was read, and when. Non-binding: this is a record of what was on
        # screen, not a claim about what the case contains now.
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(32), nullable=False),
        # Who or what asked. `analyse_case_now` is an analyst asking for an
        # early read, and that is worth distinguishing from the quiet-period
        # job, because the early read is the one whose set is most likely to
        # diverge later.
        sa.Column("requested_by", sa.String(255), nullable=True),
        # The derivation that produced it, so a later version can be compared
        # rather than silently replacing it.
        sa.Column("derivation_version", sa.String(64), nullable=False),
        # The alerts themselves. The whole point: a count is what every
        # existing artefact already gives, and a count cannot be checked.
        sa.Column("run_ids", JSONB, nullable=False),
        sa.Column("alert_count", sa.Integer, nullable=False),
        # The narrative this set belongs to, where there is one.
        sa.Column("narrative_fingerprint", sa.String(64), nullable=True),
    )
    op.create_index("ix_case_read_set_case", "case_read_set", ["case_key"])
    op.create_index("ix_case_read_set_read_at", "case_read_set", ["read_at"])


def downgrade() -> None:
    op.drop_index("ix_case_read_set_read_at", table_name="case_read_set")
    op.drop_index("ix_case_read_set_case", table_name="case_read_set")
    op.drop_table("case_read_set")
