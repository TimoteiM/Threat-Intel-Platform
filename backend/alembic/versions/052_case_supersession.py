"""Say what happened to a case key that no longer re-derives.

A case key is a hash of (source, client, host, first event time,
discriminator). The formula changed on 2026-10-07 and no migration followed,
so every row keyed under the old one stopped resolving. Measured over 1,887
spine rows: 880 dead, of which 855 still have their alerts and 811 carry a
written AI analysis. 811 investigations nothing could open.

Three columns, so a dead row can state its own situation instead of
disappearing:

    supersession_state       mapped | ambiguous | target_unknown | expired
    supersession_note        the reason, in words
    supersession_candidates  every live case it might be, when it is ambiguous

`ambiguous` exists because a wrong pointer is worse than no pointer: it
silently attributes one incident's analysis to another. 164 rows have several
live candidates on host and opening time, and those keep all of them.

`case_key_version` is the recurrence guard. The formula's inputs are pinned by
a test; changing them without bumping this column and writing a migration
fails that test rather than orphaning another 880 rows.

Revision ID: 052
Revises: 051
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "052"
down_revision = "051"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_case_spine", sa.Column("supersession_state", sa.String(32), nullable=True))
    op.add_column("alert_case_spine", sa.Column("supersession_note", sa.Text, nullable=True))
    op.add_column(
        "alert_case_spine",
        sa.Column("supersession_candidates", JSONB, nullable=True),
    )
    op.add_column(
        "alert_case_spine",
        sa.Column("case_key_version", sa.Integer, nullable=False, server_default="2"),
    )
    op.create_index(
        "ix_case_spine_supersession_state", "alert_case_spine", ["supersession_state"]
    )
    # Rows written before this migration were keyed under version 1 — the
    # formula in use up to 2026-10-07. Dating it rather than guessing: the
    # measured cutover is the first row written on 2026-10-08, after which the
    # dead rate falls from 74.6% to 9.6%.
    op.execute(
        """
        update alert_case_spine
           set case_key_version = 1
         where created_at < timestamptz '2026-10-08 00:00:00+00'
        """
    )


def downgrade() -> None:
    op.drop_index("ix_case_spine_supersession_state", table_name="alert_case_spine")
    op.drop_column("alert_case_spine", "case_key_version")
    op.drop_column("alert_case_spine", "supersession_candidates")
    op.drop_column("alert_case_spine", "supersession_note")
    op.drop_column("alert_case_spine", "supersession_state")
