"""Has a source stopped sending, or is it merely quiet?

Written because two of the four largest sources in the estate had sent nothing
for weeks and nothing in the platform could tell. Measured 2026-10-09 on
`alert_body_investigation_runs`:

    windows_eventchannel    9,102 runs   last 2026-10-09   762 in 7 days
    appsec-agent            2,685 runs   last 2026-09-22     0 in 7 days
    fortigate-firewall-v5   2,533 runs   last 2026-09-17     0 in 7 days
    palo_alto_panos           224 runs   last 2026-10-09     20 in 7 days

appsec-agent was 17.7% of alert volume and Fortigate 16.6%. Silent for 17 and
22 days. A source going quiet is either a customer change we should know about
or a broken feed we are blind to, and both need this same detector.

Why the stall watchdog could not see it
---------------------------------------
`pipeline_health_service` watches the queue, and the queue is *downstream of
ingest*. An alert that never arrives is never queued, so a dead feed produces
exactly the same queue as a healthy quiet one — the same shape as the stall it
was written for, one layer up, and the same shape as a threat feed that failed
6,259 consecutive times at debug level and surfaced as a count of zero.

Two measurements, deliberately from different columns
-----------------------------------------------------
This is the trap that made the finding hard to establish, so it is encoded
here rather than left to be rediscovered:

    the historical cadence   from `graph_source_type`
    the recent arrivals      from the alert bodies

`graph_source_type` is written when a run is *materialised*, not when it
arrives. So a source that is delivering right now has recent runs with no
source type at all, and reading that column alone reports a live source as
stopped — it did exactly that for PAN-OS, giving 0 runs in 7 days where the
bodies gave 20. Old runs are all materialised, so the column is correct for
the baseline and wrong for the present. Each half therefore reads the source
that is right for it, and the recent half costs one classification pass over a
few hundred bodies.

What this refuses to do
-----------------------
**It does not hold a list of sources to watch.** Seven hand-maintained lists
in this codebase have swallowed a feature with no error, and a watchdog whose
coverage is a literal would silently not watch the next source onboarded. The
population is derived from what has actually delivered.

**It does not judge a source with no cadence.** A source seen twice has no
normal rhythm to be late against, so it reports as unknown rather than fresh.
A blank treated as healthy is the bug this whole module exists to undo.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import TOO_LITTLE_HISTORY, Absent, absent

logger = logging.getLogger(__name__)

#: How many runs a source needs before it has a rhythm worth measuring. Below
#: this its gaps are noise, and declaring it stale would alarm on a source that
#: was never regular. Set against the estate: the four sources that matter hold
#: 224 to 9,102 runs, and the next ones down hold 18, 10, 5 and 2.
MIN_RUNS_FOR_CADENCE = 40

#: How many of its own typical gaps a source may be silent for before this is
#: not quiet. Three rather than two because a weekly-cadence source legitimately
#: skips a holiday week, and the cost of a late alarm here is days, not minutes.
STALE_AT_GAPS = 3.0

#: And a floor, so a chatty source cannot be declared stale over an hour of
#: calm. Nothing in this estate has a legitimate daily rhythm finer than this.
MIN_SILENCE = timedelta(hours=12)

#: The widest recent window read from the bodies. Wide enough to carry the
#: slowest cadence in the estate, narrow enough that classifying every body in
#: it is cheap: 857 runs over the seven days measured.
#:
#: Each source is then counted inside **its own** allowed silence rather than
#: inside this whole window. That distinction is the difference between a
#: useful alarm and a decorative one: counting every source over seven days
#: would mean a source can only be called stale after seven days of total
#: silence, so for `windows_eventchannel` — 9,217 runs, a median gap of about a
#: minute — the cadence logic would never bind and the detector would be seven
#: days slow on the source it most matters for. Per-source, that becomes the
#: 12-hour floor.
RECENT = timedelta(days=7)

_BASELINE_SQL = """
select coalesce(graph_source_type, '') as source,
       count(*) as runs,
       min(coalesce(event_time, created_at)) as first_seen,
       max(coalesce(event_time, created_at)) as last_seen
from alert_body_investigation_runs
where graph_source_type is not null and graph_source_type <> ''
group by 1
"""

_GAPS_SQL = """
select extract(epoch from (
         coalesce(event_time, created_at)
         - lag(coalesce(event_time, created_at)) over (
             partition by graph_source_type order by coalesce(event_time, created_at)
           )
       )) as gap
from alert_body_investigation_runs
where graph_source_type = :source
"""

_RECENT_SQL = """
select id, alert_body, coalesce(event_time, created_at) as at
from alert_body_investigation_runs
where coalesce(event_time, created_at) >= :since
"""


@dataclass
class SourceFreshness:
    source: str
    runs: int
    last_seen: datetime | None
    recent_runs: int
    typical_gap: timedelta | None
    now: datetime
    #: The window `recent_runs` was counted over. Reported, because "0 recent
    #: runs" means nothing without it.
    recent_window: timedelta | None = None
    #: Why this source cannot be judged, when it cannot be.
    unjudgeable: Absent | None = None

    @property
    def silent_for(self) -> timedelta | None:
        if self.last_seen is None:
            return None
        stamp = (
            self.last_seen
            if self.last_seen.tzinfo
            else self.last_seen.replace(tzinfo=timezone.utc)
        )
        return self.now - stamp

    @property
    def allowed_silence(self) -> timedelta | None:
        """How long this source may legitimately be quiet, by its own rhythm."""
        if self.typical_gap is None:
            return None
        return max(MIN_SILENCE, self.typical_gap * STALE_AT_GAPS)

    @property
    def stale(self) -> bool:
        """This source has stopped, judged against its own cadence.

        Both halves are required, as in `pipeline_health_service`. A source
        with no measurable cadence is never stale — it is unjudgeable, which is
        a different statement and is reported as one. And a source still
        delivering inside the recent window is not stale however old its last
        materialised run looks, which is the column trap above.
        """
        if self.unjudgeable is not None or self.recent_runs > 0:
            return False
        allowed = self.allowed_silence
        silence = self.silent_for
        if allowed is None or silence is None:
            return False
        return silence > allowed

    def as_json(self) -> dict[str, Any]:
        silence = self.silent_for
        allowed = self.allowed_silence
        return {
            "source": self.source,
            "runs": self.runs,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "recent_runs": self.recent_runs,
            "recent_window_hours": (
                round(self.recent_window.total_seconds() / 3600.0, 1)
                if self.recent_window
                else None
            ),
            "silent_for_hours": (
                round(silence.total_seconds() / 3600.0, 1) if silence else None
            ),
            "typical_gap_hours": (
                round(self.typical_gap.total_seconds() / 3600.0, 2)
                if self.typical_gap
                else None
            ),
            "allowed_silence_hours": (
                round(allowed.total_seconds() / 3600.0, 1) if allowed else None
            ),
            "stale": self.stale,
            "unjudgeable": (
                self.unjudgeable.as_json() if self.unjudgeable is not None else None
            ),
        }


@dataclass
class IngestFreshness:
    sources: list[SourceFreshness] = dc_field(default_factory=list)

    @property
    def stale(self) -> list[SourceFreshness]:
        return [s for s in self.sources if s.stale]

    def as_json(self) -> dict[str, Any]:
        return {
            "sources": [s.as_json() for s in self.sources],
            "stale": [s.source for s in self.stale],
            "watched": len(self.sources),
            "unjudgeable": [
                s.source for s in self.sources if s.unjudgeable is not None
            ],
            "min_runs_for_cadence": MIN_RUNS_FOR_CADENCE,
            "stale_at_gaps": STALE_AT_GAPS,
        }


def _typical_gap(gaps: list[float]) -> timedelta | None:
    """The median gap between arrivals, which is the source's own rhythm.

    Median rather than mean: one three-week outage in the history would drag a
    mean far enough that the source could never be late again, so the outage
    would raise the threshold that is meant to catch it.
    """
    usable = [g for g in gaps if g is not None and g > 0]
    if not usable:
        return None
    return timedelta(seconds=median(usable))


async def recent_arrivals_by_source(
    db: AsyncSession, *, since: datetime
) -> dict[str, list[datetime]]:
    """When each source delivered recently, read from the bodies.

    The bodies rather than `graph_source_type`, because that column is written
    at materialise time and a run that arrived since the last backfill has
    none. Classifying is the same code the extractor uses, so a source counted
    here is a source the graph would also name.

    Timestamps rather than a count, so each source can be counted inside its
    own allowed silence instead of inside one window shared by all of them.
    """
    from app.services import panos_field_map
    from app.services.alert_graph_extraction_service import read_fields, source_type_of

    rows = (await db.execute(text(_RECENT_SQL), {"since": since})).all()
    seen: dict[str, list[datetime]] = {}
    for _run_id, body, at in rows:
        text_body = body if isinstance(body, str) else ("" if body is None else str(body))
        if panos_field_map.records_of(text_body):
            name = "palo_alto_panos"
        else:
            name = source_type_of(read_fields(text_body))
        if at is not None:
            seen.setdefault(name, []).append(
                at if at.tzinfo else at.replace(tzinfo=timezone.utc)
            )
    return seen


def arrivals_within(
    arrivals: list[datetime], *, now: datetime, window: timedelta
) -> int:
    """How many of these arrivals fall inside the window ending now."""
    cutoff = now - window
    return sum(1 for at in arrivals if at >= cutoff)


async def check(db: AsyncSession, *, now: datetime | None = None) -> IngestFreshness:
    now = now or datetime.now(timezone.utc)
    baseline = (await db.execute(text(_BASELINE_SQL))).all()
    arrivals = await recent_arrivals_by_source(db, since=now - RECENT)

    found: list[SourceFreshness] = []
    for row in baseline:
        source = str(row.source)
        runs = int(row.runs or 0)
        unjudgeable: Absent | None = None
        gap: timedelta | None = None
        if runs < MIN_RUNS_FOR_CADENCE:
            unjudgeable = absent(
                TOO_LITTLE_HISTORY,
                (
                    f"{source} has delivered {runs} runs, below the "
                    f"{MIN_RUNS_FOR_CADENCE} needed to measure a cadence, so it "
                    "has no normal rhythm to be late against. This is not a "
                    "statement that it is healthy."
                ),
                raw=str(runs),
            )
        else:
            gaps = (await db.execute(text(_GAPS_SQL), {"source": source})).scalars().all()
            gap = _typical_gap([float(g) for g in gaps if g is not None])
            if gap is None:
                unjudgeable = absent(
                    TOO_LITTLE_HISTORY,
                    (
                        f"{source} has runs but no measurable interval between "
                        "them, so no cadence could be derived."
                    ),
                    raw=str(runs),
                )
        # Counted inside this source's own allowed silence, capped at the
        # window actually read. A source with no cadence gets the whole window,
        # since there is nothing narrower to justify.
        candidate = SourceFreshness(
            source=source, runs=runs, last_seen=row.last_seen, recent_runs=0,
            typical_gap=gap, now=now, unjudgeable=unjudgeable,
        )
        window = min(candidate.allowed_silence or RECENT, RECENT)
        found.append(
            SourceFreshness(
                source=source,
                runs=runs,
                last_seen=row.last_seen,
                recent_runs=arrivals_within(
                    arrivals.get(source, []), now=now, window=window
                ),
                recent_window=window,
                typical_gap=gap,
                now=now,
                unjudgeable=unjudgeable,
            )
        )

    health = IngestFreshness(sources=sorted(found, key=lambda s: -s.runs))
    stale = health.stale
    if stale:
        # Error, not warning. The two sources this was written for were silent
        # for 17 and 22 days among warnings nobody was reading.
        logger.error(
            "ingest_source_stale sources=%s — %s. A source that stops looks "
            "exactly like a source that is quiet, and the queue watchdog "
            "cannot see it because the queue is downstream of ingest. Either a "
            "customer changed something we should know about, or the feed is "
            "broken and we are blind to it. Ask whoever owns the integration.",
            ",".join(s.source for s in stale),
            "; ".join(
                f"{s.source} silent {(s.silent_for or timedelta()).days}d "
                f"against a typical gap of "
                f"{(s.typical_gap or timedelta()).total_seconds() / 3600:.1f}h "
                f"over {s.runs} runs"
                for s in stale
            ),
        )
    else:
        logger.info(
            "ingest_sources_fresh watched=%d unjudgeable=%d",
            len(health.sources),
            sum(1 for s in health.sources if s.unjudgeable is not None),
        )
    return health
