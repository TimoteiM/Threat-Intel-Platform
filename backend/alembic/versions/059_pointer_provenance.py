"""Every supersession pointer says who wrote it.

Of 866 rows carrying `superseded_by_case_key` on 2026-10-09, two had no
`supersession_state`: #1866 and #1973. Both were written by the live
correlation pass, `alert_case_store.absorb_superseded`, which set the pointer
and nothing else — the state was only ever written by the one-off migration in
`app.cli.case_supersession`, so every pointer the platform wrote after that ran
was unprovenanced.

How the writer is known, rather than assumed: every other path that writes a
pointer also writes a state (the CLI) or a note (`collapse_chains`), and
migration 044 only clears them. Both rows have the shape absorption selects —
same host, a session starting inside the target's (by 0.04 s and 0.7 s) — and
#1973 was closed `merged` 25 ms before its target row was created, which is
one transaction. Neither write fell in the hourly job's slot, so both came
from a page load.

So these rows are given `merged`, the state that means "the platform recorded
where this case went, at the time" — which is what happened — with a note
saying the state was backfilled and why. The selection is the condition, not
the two keys: any row in this shape at upgrade time was written by the same
code for the same reason.

Then the gap is closed where it cannot be forgotten: a CHECK constraint makes
a pointer without a state a write the database refuses.

Revision ID: 059
Revises: 058
"""

from alembic import op

revision = "059"
down_revision = "058"
branch_labels = None
depends_on = None

_NOTE = (
    "State backfilled on 2026-10-09 by migration 059. The pointer was written "
    "by the live correlation pass (absorb_superseded), which until then set "
    "the pointer without a state; it is the only writer that could have "
    "produced a pointer with neither a state nor a note."
)


def upgrade() -> None:
    op.execute(
        f"""
        UPDATE alert_case_spine
           SET supersession_state = 'merged',
               supersession_note = concat_ws(' ', supersession_note, '{_NOTE}')
         WHERE superseded_by_case_key IS NOT NULL
           AND supersession_state IS NULL
        """
    )
    op.create_check_constraint(
        "ck_case_spine_pointer_has_provenance",
        "alert_case_spine",
        "superseded_by_case_key IS NULL OR supersession_state IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint("ck_case_spine_pointer_has_provenance", "alert_case_spine", type_="check")
