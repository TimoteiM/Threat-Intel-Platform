"""Correct the alerts a fast host clock put in the future.

Reported as "how is the displayed activity in the future?" — the Cases table
showed case #1127 opened at 16:07 and last active at 19:41 while the clock on
the wall read 12:26.

Nothing was mis-parsed. The alert states both times and both are explicitly
UTC:

    Time: 2026-10-08T09:15:26.531+0000            <- the manager wrote the alert
    data.win.system.systemTime: 2026-10-08T13:07:39.294706900Z   <- the host

The host's own clock is the more precise source and is preferred for exactly
that reason, so a Windows machine 3h52m fast was believed. The only guard was
an absolute one — nothing more than two days ahead — which a ten-hour skew
sails through.

It is small and it was load-bearing. A case opens at its first alert's event
time, and a case is now answered ten minutes after it opens, so a case opened
in the future has a window that cannot elapse: #1127 would have stayed open
until real time caught up with its host.

Three hosts, eight alerts: SERVER01, LABORATORVM001 and WIN10-MSSQL02, two of
them exactly ten hours out, which looks like a lab VM rather than drift.

The extractor now refuses a host stamp later than the alert that reports it,
and counts the substitution. This repairs what is already stored, using the
same rule and the alert's own words — the earliest stamp on its `Time:` line,
which is where the manager records when it wrote the alert.

Revision ID: 047
Revises: 046
"""

import re
from datetime import datetime, timedelta, timezone

from alembic import op
import sqlalchemy as sa

revision = "047"
down_revision = "046"
branch_labels = None
depends_on = None

# Self-contained: a migration has to produce the same result in five years
# against whatever the extractor has become.
_TIME_LINE = re.compile(r"(?:^|\n)[ \t]*Time:[ \t]*([^\n]{19,90})", re.IGNORECASE)
_STAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
)


def _parse(raw: str) -> datetime | None:
    text = raw.strip().replace("Z", "+00:00")
    # `+0000` without the colon, which is what Wazuh writes.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _reported_at(body: str) -> datetime | None:
    """The earliest stamp on the alert's own `Time:` line.

    Two appear there separated by a pipe, and the earliest is the one the
    extractor already takes — so the repair and the live path agree.
    """
    match = _TIME_LINE.search(body or "")
    if not match:
        return None
    found = [s for s in (_parse(x) for x in _STAMP.findall(match.group(1))) if s]
    return min(found) if found else None


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT id, alert_body, event_time, created_at
            FROM alert_body_investigation_runs
            WHERE event_time IS NOT NULL
              AND alert_body IS NOT NULL
              AND event_time > created_at + interval '2 minutes'
            """
        )
    ).fetchall()

    for run_id, body, event_time, created_at in rows:
        corrected = _reported_at(body)
        # Only when the alert gives a better answer than the one stored, and
        # never a worse one: without a manager stamp there is nothing to
        # prefer, and the row is left as it is rather than guessed at.
        if corrected is None or corrected >= event_time:
            continue
        bind.execute(
            sa.text(
                "UPDATE alert_body_investigation_runs SET event_time = :t WHERE id = :id"
            ),
            {"t": corrected, "id": run_id},
        )

    # The spine carries copies of these instants. Re-derived from the runs
    # rather than recomputed by correlation, which would re-cluster the whole
    # estate to fix eight rows.
    op.execute(
        """
        UPDATE alert_case_spine s
           SET last_activity_at = LEAST(s.last_activity_at, s.created_at),
               opened_at        = LEAST(s.opened_at, s.created_at)
         WHERE s.opened_at > s.created_at
            OR s.last_activity_at > s.created_at
        """
    )


def downgrade() -> None:
    # Not reversible: the values replaced were a fast host's own reading, and
    # nothing recorded them.
    pass
