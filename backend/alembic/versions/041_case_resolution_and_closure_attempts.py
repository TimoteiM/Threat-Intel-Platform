"""Make a case's resolution mean what its analysis says, and stop unreadable cases blocking the queue.

Three corrections, all of them to data this platform already reports on.

**The resolution was never an assessment.** It was a band of the correlation
score: `true_positive` was exactly 76-100, `inconclusive` 30-73,
`false_positive` 0-35, with no overlap anywhere. The score measures how much
independent agreement there is between detection rules and how far the
behaviour travelled — four distinct rules and nothing else scores 90 — and the
narrative prompt says so in those words. Reading it as severity filed 24 cases
as confirmed detections, of which the written analysis called exactly one
malicious. 490 of 794 cases were closed before their analysis existed at all,
so the resolution could not have read it even in principle.

History is rewritten from the analysis that was already paid for: 842 stored
narratives, re-read with the same function the live path now uses. 68 cases
closed `expired` have a benign analysis sitting unused; those get their answer.

**Titles repeated the host.** Migration 037 stripped the "<agent> - " prefix
from `detection_name` with `^[^-]{1,80}? - ` — a negated character class that
excludes the hyphen — so every host whose name contains one was skipped:
7,448 of 7,668 runs on hyphenated hosts kept the prefix, against 0 of 3,795 on
hosts without. `case_label` then prepended the host again, producing
"EXP-6FSKJR3 — EXP-6FSKJR3 - A .NET application crashed". The label now comes
from the first linked alert's own title, so live cases are correct on the next
read; this repairs the titles frozen at close, which no recompute will reach.

The `detection_name` column itself is deliberately NOT repaired here. It feeds
the distinct-rule count that decides which clusters become cases at all, so
stripping the prefix merges detection identities and moves historical case
membership and scores. That is its own change, measured on its own.

**Unreadable cases blocked the work queue.** A case the closing job cannot
re-derive stayed open and kept its place at the head of an oldest-first queue,
so every pass selected it again in the same position. Six of them were enough
to take throughput to zero. Two columns let the job back off instead of
re-running a full correlation on the same dead row every minute for ever.

Revision ID: 041
Revises: 040
"""

import re

from alembic import op
import sqlalchemy as sa

revision = "041"
down_revision = "040"
branch_labels = None
depends_on = None


# Deliberately self-contained, not imported from `app.services`.
#
# A migration has to produce the same result in five years, against whatever
# the service layer has become by then. Importing the live mapping would make
# this file's output drift silently with it.
_VERDICT_WORDS: tuple[tuple[str, str], ...] = (
    ("true positive", "true_positive"),
    ("true_positive", "true_positive"),
    ("false positive", "false_positive"),
    ("false_positive", "false_positive"),
    ("not malicious", "false_positive"),
    ("not_malicious", "false_positive"),
    ("inconclusive", "inconclusive"),
    ("indeterminate", "inconclusive"),
    ("unknown", "inconclusive"),
    ("malicious", "true_positive"),
    ("confirmed", "true_positive"),
    ("compromised", "true_positive"),
    ("suspicious", "needs_review"),
    ("needs review", "needs_review"),
    ("benign", "false_positive"),
    ("clean", "false_positive"),
)

_HEDGE = re.compile(
    r"^(likely|probably|possibly|assessed(?:\s+as)?|appears(?:\s+to\s+be)?"
    r"|most\s+likely|highly\s+likely|verdict)\b[\s:,-]*"
)
_VERDICT_LINE = re.compile(r"\*\*\s*Verdict\s*:\s*([^*\n]+)\*\*", re.IGNORECASE)


def _resolution_from(markdown: str | None) -> str:
    """What the written analysis concluded, as the word a case closes under."""
    match = _VERDICT_LINE.search(markdown or "")
    text = (match.group(1) if match else "").strip().casefold().lstrip("*#: ").strip()
    for _ in range(3):
        stripped = _HEDGE.sub("", text).strip()
        if stripped == text:
            break
        text = stripped
    for word, resolution in _VERDICT_WORDS:
        if text.startswith(word):
            return resolution
    # Never a positive. A verdict nobody could read is a case nobody answered,
    # and scanning the rest of the line for frightening words read "No
    # malicious activity confirmed" as a confirmed intrusion.
    return "inconclusive"


def upgrade() -> None:
    # --- the queue ----------------------------------------------------------
    op.add_column(
        "alert_case_spine",
        sa.Column("closure_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "alert_case_spine",
        sa.Column("closure_attempted_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Backs the newest-due slice of the two-slice work queue.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_spine_due_desc
        ON alert_case_spine (last_activity_at DESC)
        WHERE status = 'open' AND closed_at IS NULL
        """
    )

    # --- status and closed_at must agree ------------------------------------
    #
    # Two rows are status='open' with closed_at, closure_kind, resolution and
    # closure_claimed_at all set by the same pass. `close_case` always writes
    # both, and no path was found that reverts status, so the mechanism is
    # unidentified and this reconciles the rows without asserting a cause.
    #
    # They matter: the work queue requires `closed_at IS NULL`, so neither can
    # ever be selected again, and nothing would have answered them.
    op.execute(
        """
        UPDATE alert_case_spine
           SET status = 'closed'
         WHERE status = 'open' AND closed_at IS NOT NULL
        """
    )
    # No CHECK constraint yet, on purpose. One would turn the unidentified
    # writer into a failed transaction on a live ingest path, and a guard
    # whose trigger nobody has found is a guard that fires at the worst
    # moment. The reconciliation above plus the count in the closing job's
    # return value make a recurrence visible first.

    # --- a closed case's closure is no longer overwritten by supersession ---
    #
    # `mark_superseded` set status unconditionally, so four closed cases were
    # moved to 'superseded' while keeping closure_kind and resolution — lost
    # to the open queue and to every closed-case report at once.
    op.execute(
        """
        UPDATE alert_case_spine
           SET status = 'closed'
         WHERE status = 'superseded' AND closed_at IS NOT NULL
        """
    )

    # --- titles that repeat the host ---------------------------------------
    op.execute(
        """
        UPDATE alert_case_spine
           SET title = btrim(substring(title from position(' - ' in title) + 3))
         WHERE title IS NOT NULL
           AND entity_host IS NOT NULL
           AND entity_host <> ''
           AND title LIKE entity_host || ' ' || chr(8212) || ' ' || entity_host || ' - %'
        """
    )
    # Pre-correlated incidents are keyed `{host}\\x1fincident:{id}`, and the
    # label was built from the composite rather than the host half.
    op.execute(
        """
        UPDATE alert_case_spine
           SET title = regexp_replace(title, chr(31) || '[^ ]*', '', 'g')
         WHERE title LIKE '%' || chr(31) || '%'
        """
    )

    # --- the resolutions ----------------------------------------------------
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT case_key, narrative_markdown
            FROM alert_case_spine
            WHERE closed_at IS NOT NULL AND narrative_markdown IS NOT NULL
            """
        )
    ).fetchall()
    for case_key, markdown in rows:
        bind.execute(
            sa.text(
                "UPDATE alert_case_spine SET resolution = :resolution "
                "WHERE case_key = :case_key"
            ),
            {"resolution": _resolution_from(markdown), "case_key": case_key},
        )

    # Closed, and nothing was ever written about it. Not a false positive,
    # which is a finding somebody reached.
    bind.execute(
        sa.text(
            """
            UPDATE alert_case_spine
               SET resolution = 'inconclusive'
             WHERE closed_at IS NOT NULL
               AND (narrative_markdown IS NULL OR btrim(narrative_markdown) = '')
            """
        )
    )


def downgrade() -> None:
    # The resolution and title corrections are not reversible: the values they
    # replaced were derived from a score and from a broken prefix strip, and
    # nothing recorded them. Only the schema comes back.
    op.execute("DROP INDEX IF EXISTS idx_case_spine_due_desc")
    op.drop_column("alert_case_spine", "closure_attempted_at")
    op.drop_column("alert_case_spine", "closure_attempts")
