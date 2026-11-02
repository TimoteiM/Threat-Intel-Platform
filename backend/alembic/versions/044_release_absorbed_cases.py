"""Give back the cases that were absorbed into other cases.

Reported as: closing case #132 answered *"This case was merged into case #133.
Close that one instead — its alerts include these."* It did not. #132 held two
`Kerberoasting: RC4 service ticket requested` alerts; #133 held four
`Computer account added/changed/deleted`. They share **not one alert**.

Supersession was written when one session meant one case. A late alert can
close a gap between two sessions, the merged session starts earlier, so it
hashes to a new key and the row for the old key becomes unreachable — along
with its assignee and its history. Following that forward is right.

Then membership changed. A session's alerts are now grouped by shared
evidence, so one session yields several cases, and every one of them carries
the same `session_started_at`. "Another key inside this session's span"
stopped meaning "an older version of this case" and started meaning "a
sibling case about something else" — and absorption could not tell the
difference.

Measured over all 320 pointers before this ran: 171 had absorbed a case that
still holds its own alerts, and in **none** of them had those alerts moved
into the absorbing case. 149 pointed at keys that no longer form a case,
which is the only thing absorption was ever for. A Cobalt Strike Malleable C2
case was filed inside "Repeated injection"; #892 and #895 absorbed each
other; five distinct detections on one domain controller — a Sysmon WMI event
subscription, HTML smuggling, an account lockout — were all filed inside
"User account changed".

By shape, 311 of 321 pointers join two rows with the *same*
`session_started_at`, which the code now forbids outright; 4 point at a case
that started *later* than the absorbed one, which is backwards.

**Every pointer is released, not just the provably wrong ones.** The rule the
code now enforces is membership — a key this correlation pass is producing is
never absorbed — and that cannot be evaluated in SQL. Releasing all of them
and letting correlation re-absorb the genuinely dead keys on its next pass is
the direction that cannot destroy a case. A released case with no alerts left
is closed as `expired` by the closing job, which is honest and already built.

The 242 rows carrying `status='superseded'` with `closed_at` NULL are the
other half of the report — "case #132 remained opened". The Cases table reads
`closed_at`, so they showed as Open for ever; the closing job skipped them
because their status is not 'open'; and a manual close failed on the closure
claim for the same reason. There was no exit from that state. Status now
follows `closed_at`, which is the invariant everything else reads.

Revision ID: 044
Revises: 043
"""

from alembic import op
import sqlalchemy as sa

revision = "044"
down_revision = "043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A case closed *because* it was absorbed has no closure of its own to
    # keep, so it goes back to being open and is answered normally. ('merged'
    # is new with this change, so this is for re-runs rather than for history.)
    op.execute(
        """
        UPDATE alert_case_spine
           SET superseded_by_case_key = NULL,
               status = 'open',
               closed_at = NULL,
               closure_kind = NULL,
               resolution = NULL
         WHERE superseded_by_case_key IS NOT NULL
           AND closure_kind = 'merged'
        """
    )
    # Everything else keeps whatever closure it reached on its own merits and
    # loses only the pointer. `status` is derived from `closed_at` rather than
    # assumed, so 'superseded' — the state with no exit — cannot survive.
    op.execute(
        """
        UPDATE alert_case_spine
           SET superseded_by_case_key = NULL,
               status = CASE WHEN closed_at IS NULL THEN 'open' ELSE 'closed' END
         WHERE superseded_by_case_key IS NOT NULL
        """
    )
    # Any row left in the dead state without a pointer to explain it.
    op.execute(
        """
        UPDATE alert_case_spine
           SET status = CASE WHEN closed_at IS NULL THEN 'open' ELSE 'closed' END
         WHERE status = 'superseded'
        """
    )


def downgrade() -> None:
    # Not reversible. The pointers released here recorded a relationship that
    # was measurably false for 171 of them, and nothing recorded which.
    pass
