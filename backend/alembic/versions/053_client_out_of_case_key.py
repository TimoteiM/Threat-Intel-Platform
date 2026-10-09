"""Stop a field that is constant for 99.9% of rows from shaping case identity.

`alert_client` reads 'unknown' on 15,234 of 15,255 alerts and on 1,851 of
1,889 case rows; the rest are 'LIN' (36), 'Codex Desktop' (2) and two others.
A value true of almost every row cannot distinguish one case from another, so
its presence in the key contributed nothing — and for the 38 rows that do
carry a value it produced a different key for a reason that is not about the
incident.

Pinned rather than removed, which is the whole point of this migration being
cheap. Removing the component changes the joined string for every row and
re-keys all 1,889, renumbering the entire case list. Pinning it to the value
1,851 rows already carry leaves those keys byte-identical and re-keys only the
38 that were being separated for the wrong reason. Those are then re-pointed
by `python -m app.cli.case_supersession --apply`, the same path that recovered
the 881 orphaned on 2026-10-07.

Measured while writing this: the dead-key rate is uniform across clients —
47% for 'unknown', 50% for 'LIN', 50% for 'Codex Desktop' — so `alert_client`
was not a second cause of that incident. The formula change remains the only
one.

This is the first use of CASE_KEY_VERSION, which exists because the last
formula change shipped without a migration.

Revision ID: 053
Revises: 052
"""

from alembic import op
import sqlalchemy as sa

revision = "053"
down_revision = "052"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A row whose client already read 'unknown' has a key that version 3
    # reproduces byte for byte, so it is already a version 3 key.
    op.execute(
        """
        update alert_case_spine
           set case_key_version = 3
         where coalesce(lower(alert_client), '') in ('unknown', '')
        """
    )
    # The rest keep version 2, which is how a reader can see which rows still
    # hold a key no current formula produces.
    op.execute(
        """
        update alert_case_spine
           set case_key_version = 2
         where coalesce(lower(alert_client), '') not in ('unknown', '')
        """
    )


def downgrade() -> None:
    op.execute("update alert_case_spine set case_key_version = 2")
