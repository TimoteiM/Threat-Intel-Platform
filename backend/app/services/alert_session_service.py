"""
Where one session of activity on a host ends and the next begins.

There are no analyst actions to close a case with, so the boundary has to come
from the alerts themselves: a quiet stretch means the activity stopped, and a
session that has run long enough gets cut regardless. Both numbers are here
rather than inline, because they are the only two knobs that change what a case
*is*, and they should be readable in one place.

The constraint that shaped this module is that session assignment must be a
pure function of event time, evaluated at read. Nothing here may depend on when
recompute last ran, how often it runs, or whether anyone opened the page —
otherwise the case boundary becomes a function of analyst attention, and two
analysts looking at the same host at different times see different cases.

That rules out the obvious identity. Measured over stored runs (27 hosts, 1,080
arbitrary window boundaries, 53,262 key comparisons against the full-history
answer), an incrementing session ordinal disagreed with itself 95.3% of the
time, because it counts from wherever the query happened to start. Deriving
identity from the session's first event time instead, and extending the read
back past the window boundary to the previous gap, disagreed 0.0% of the time.

So: SESSION_START is the identity, the ordinal is decoration, and the lookback
is mandatory rather than an optimisation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

# A quiet stretch this long ends the session. Short enough that yesterday's
# noise does not join today's intrusion; long enough to hold an attack that
# pauses while an operator reads what they just collected.
SESSION_GAP_HOURS = 6
SESSION_GAP = timedelta(hours=SESSION_GAP_HOURS)

# A session is cut here no matter how continuous the activity is. Without it a
# host that never falls quiet for six hours — a busy proxy, a chatty catch-all
# rule — accumulates one unbounded case that no one can ever finish working.
SESSION_MAX_HOURS = 72
SESSION_MAX = timedelta(hours=SESSION_MAX_HOURS)

# How much history a backwards walk pulls per round trip. This is a chunk size,
# NOT a bound — an earlier draft claimed the walk was bounded by SESSION_MAX on
# the reasoning that no session outlives the cap, and that is wrong. It holds for
# gap-splits, which depend only on the two events either side of them. It fails
# for cap-splits: where a session is cut *because* it hit 72h, the cut's position
# depends on where its chain started, and a chain with no gap wider than
# SESSION_GAP can run arbitrarily far back. Stopping the walk at a fixed 72h
# would silently misplace exactly those boundaries.
#
# So the walk runs until it finds a gap wider than SESSION_GAP or history runs
# out, fetching this much at a time. Measured over stored runs across 1,080
# arbitrary cut points: median walk 0.2h, p95 4.5h, max 26.1h — but 46.8% ended
# by exhausting history rather than by finding a gap, and one traversed 1,836
# alerts. Cheap in the common case, unbounded in the tail, which is why it pages.
SESSION_LOOKBACK_CHUNK = SESSION_MAX

# Names which scoring function a persisted peak_score is the peak of. Bump this
# whenever the score changes shape — the Stealth fix moved a real case from 75
# to 100 with no change in its alerts, and a peak compared across that boundary
# is a comparison between two different questions.
SCORE_VERSION = "2026.09.1-shape-surprise"

# The fields case_key is derived from, in order. session_started_at is here and
# session_seq deliberately is not: the ordinal is what a human reads, not what
# the case is.
CASE_KEY_FIELDS: tuple[str, ...] = (
    "alert_source",
    "alert_client",
    "entity_host",
    "session_started_at",
)


@dataclass(frozen=True)
class SessionAssignment:
    """One alert's place in its host's timeline."""

    run_id: Any
    event_time: datetime
    session_started_at: datetime
    session_seq: int
    case_key: str


def case_key_for(
    source: str, client: str, host: str, session_started_at: datetime
) -> str:
    """The stable identity of one session.

    Derived from the session's first event time, never from the ordinal. The
    separator is a unit separator rather than a character a hostname or client
    name could contain, so ("a|b", "c") and ("a", "b|c") cannot collide.
    """
    started = _as_utc(session_started_at)
    parts = (
        str(source or ""),
        str(client or ""),
        str(host or ""),
        started.isoformat(),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    """Naive stamps are read as UTC, matching how event_time is stored."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def session_starts(times: Sequence[datetime]) -> list[datetime]:
    """Walk event times in order and mark where each session begins.

    `times` must be ascending and must start at a session boundary — see
    anchor_index for why that precondition is the whole ballgame. Equal stamps
    stay in one session: a zero gap is not a quiet stretch.
    """
    starts: list[datetime] = []
    start: datetime | None = None
    prev: datetime | None = None
    for raw in times:
        when = _as_utc(raw)
        if start is None or prev is None:
            start = when
        elif (when - prev) > SESSION_GAP or (when - start) > SESSION_MAX:
            start = when
        starts.append(start)
        prev = when
    return starts


def anchor_index(times: Sequence[datetime], from_index: int) -> int:
    """Index of the earliest event that must be read to place `from_index`.

    Walks backwards until it finds a gap wider than SESSION_GAP — the point
    before which nothing can influence this session's start, because a gap that
    wide always splits regardless of what precedes it. Returns 0 when history
    runs out first, which is honest rather than correct: with no gap found, the
    computed start is the earliest event we hold, and if older alerts arrive
    later the boundary genuinely moves.

    Without this walk, a window boundary landing mid-session invents a start
    that never happened — 66.5% of keys disagreed with the full-history answer.
    With it, 0.0%.
    """
    i = max(0, min(int(from_index), len(times) - 1))
    while i > 0 and (_as_utc(times[i]) - _as_utc(times[i - 1])) <= SESSION_GAP:
        i -= 1
    return i


def assign_sessions(
    events: Sequence[tuple[Any, datetime]],
    *,
    source: str,
    client: str,
    host: str,
) -> list[SessionAssignment]:
    """Place every alert on this host into a session.

    `events` is (run_id, event_time) ascending, and must begin at a session
    boundary — pass what anchor_index selected, not what the query window held.

    session_seq counts from the first session in `events`, so it is a label for
    the reader and nothing more. It is deliberately NOT an input to case_key:
    measured across 1,080 window boundaries, an ordinal key disagreed with the
    full-history answer 95.3% of the time, because counting from the start of a
    window makes the identity a function of where you looked rather than of what
    happened. session_started_at is a property of the events themselves.
    """
    if not events:
        return []
    starts = session_starts([when for _run_id, when in events])
    out: list[SessionAssignment] = []
    seq = -1
    last_start: datetime | None = None
    for (run_id, when), start in zip(events, starts):
        if start != last_start:
            seq += 1
            last_start = start
        out.append(
            SessionAssignment(
                run_id=run_id,
                event_time=_as_utc(when),
                session_started_at=start,
                session_seq=seq,
                case_key=case_key_for(source, client, host, start),
            )
        )
    return out
