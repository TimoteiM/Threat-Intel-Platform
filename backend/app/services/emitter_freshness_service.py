"""Has an emitter's volume collapsed against its own history?

One implementation, two groupings. A *source* and a *host* are both emitters,
and two implementations of the same question would drift — the host one is
where the value is, and it is the one that would have caught `expdc002`
running at 4.1% of normal for three weeks.

Why rate against a baseline, and not time since the last alert
--------------------------------------------------------------
Any metric anchored on the most recent event can be cleared by one event.
`fortigate-firewall-v5` delivered a single alert at 01:59 after 26.3 days of
silence and the first version of the ingest alarm went from STALE to fresh on
it. A ratio against the emitter's own past volume cannot be reset that way, and
it catches degradation as well as silence — which matters, because the six
worst hosts in this estate are not silent. They are at 1-21% of normal and
still sending just enough to look alive.

The baseline cannot be the raw history
--------------------------------------
Three things in the last 60 days are not evidence about any emitter's health,
and each one would drag a baseline downward until nothing could ever look
broken:

    7 days   the platform ingested nothing at all, estate-wide
             (2026-08-18..08-23 and 2026-10-04)
    11 days  the collapse, when the estate ran at 1-39 alerts a day against a
             prior 700-1,000 (2026-09-25..10-05)
    one host `windows-test-device`, which was 47% of all alerts in the week
             before the collapse

So the baseline is computed over *eligible* days only, and what was excluded is
reported with the figure rather than applied silently.

Shadow first
------------
This computes and logs; it does not alarm. The threshold is a provisional 25%
of baseline, chosen to generate evidence rather than to be right: on the
figures to hand it fires on Fortigate at roughly 1.4% of normal and leaves
`unstructured syslog`'s ordinary variance alone at about 24%. A week of shadow
output is what sets the real number — which is the monitor rule applied before
shipping rather than after.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from statistics import median
from typing import Any, Iterable, Sequence

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

SOURCE = "source"
HOST = "host"
GROUPINGS = (SOURCE, HOST)

#: Days in a comparison window — **eligible** days, not calendar days.
#:
#: Seven, because these emitters are bursty enough that a single day is noise:
#: `windows_eventchannel` ranges 7 to 1,272 on days it is active.
#:
#: The distinction matters and the first version of this file got it wrong in
#: its labelling. 17 of the last 60 calendar days are excluded — 8 where the
#: platform ingested nothing and 11 of the collapse — so a "window" of 7
#: eligible days can span a fortnight of wall-clock time. The newest window is
#: contiguous and really is about a week; older ones are not. Every figure
#: derived from this is therefore named `per_window` or `per_eligible_day`, and
#: never `7d`.
WINDOW_DAYS = 7

#: How many trailing windows form the baseline. Eight weeks of eligible days,
#: so a baseline survives one bad fortnight without being defined by it.
BASELINE_WINDOWS = 8

#: Provisional, for the shadow run only. Not a setting.
SHADOW_RATIO = 0.25

#: An emitter needs to have DEMONSTRATED this much volume in some past window
#: before this can judge it. A floor on history, not on recent activity.
#:
#: The version this replaces counted recent active days, and it got blinder the
#: worse the problem was: a host dark for 38 days has few active days *because*
#: it is dark, so the metric disqualified itself from judging exactly the
#: emitters worth judging. 179 of 192 hosts were unjudgeable, the two worst
#: among them. History is a property of the past and cannot be eroded by the
#: failure being detected.
MIN_BASELINE_VOLUME = 20

#: Days the platform itself took nothing. A per-emitter baseline must not
#: inherit a floor from a platform outage.
#: Derived, not listed: any day with zero runs estate-wide.
_ZERO_DAYS_SQL = """
select d::date as day, coalesce(c.n, 0) as n
from generate_series(
       (now() - make_interval(days => :days))::timestamp,
       now()::timestamp, interval '1 day') d
left join (
  select created_at::date dd, count(*) n
  from alert_body_investigation_runs
  where created_at >= now() - make_interval(days => :days)
  group by 1
) c on c.dd = d::date
order by d
"""

#: Per-emitter daily counts. `graph_source_type` is safe to group on now that
#: the materialisation sweep keeps it current — before the sweep it was written
#: only by a manual backfill, so recent runs carried none and a live source
#: read as stopped. `created_at` is the receipt clock, which is the one that
#: answers "have we heard from this emitter".
_DAILY_SQL = {
    SOURCE: """
        select coalesce(graph_source_type, '(unclassified)') as emitter,
               created_at::date as day, count(*) as n
        from alert_body_investigation_runs
        where created_at >= now() - make_interval(days => :days)
        group by 1, 2
    """,
    HOST: """
        select lower(split_part(entity_host, '.', 1)) as emitter,
               created_at::date as day, count(*) as n
        from alert_body_investigation_runs
        where created_at >= now() - make_interval(days => :days)
          and entity_host is not null
        group by 1, 2
    """,
}


@dataclass(frozen=True)
class EmitterVolume:
    grouping: str
    emitter: str
    recent: int
    baseline: float | None
    active_days: int
    #: None when there is no baseline to divide by.
    ratio: float | None
    windows_used: int

    @property
    def judgeable(self) -> bool:
        return self.baseline is not None and self.baseline > 0

    def would_alarm(self, ratio: float = SHADOW_RATIO) -> bool:
        """Shadow only. Never consulted by anything that pages a human."""
        return self.judgeable and self.ratio is not None and self.ratio < ratio

    def as_json(self) -> dict[str, Any]:
        return {
            "grouping": self.grouping,
            "emitter": self.emitter,
            "recent_window": self.recent,
            "baseline_window_peak": (
                round(self.baseline, 1) if self.baseline is not None else None
            ),
            # The honest per-day form, which does not depend on how many
            # calendar days a window of eligible days happened to span.
            "recent_per_eligible_day": round(self.recent / WINDOW_DAYS, 2),
            "ratio": round(self.ratio, 4) if self.ratio is not None else None,
            "active_days": self.active_days,
            "windows_used": self.windows_used,
            "judgeable": self.judgeable,
            "would_alarm_at_25pct": self.would_alarm(),
            "window_is_eligible_days_not_calendar_days": True,
        }


@dataclass
class FreshnessReport:
    eligible_days: int
    excluded_zero_days: tuple[str, ...]
    excluded_ranges: tuple[str, ...]
    excluded_emitters: tuple[str, ...]
    volumes: list[EmitterVolume] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        firing = [v for v in self.volumes if v.would_alarm()]
        return {
            "shadow": True,
            "eligible_days": self.eligible_days,
            "excluded_zero_ingest_days": list(self.excluded_zero_days),
            "excluded_ranges": list(self.excluded_ranges),
            "excluded_emitters": list(self.excluded_emitters),
            "emitters": len(self.volumes),
            "would_alarm": [v.as_json() for v in firing],
            "unjudgeable": [
                v.emitter for v in self.volumes if not v.judgeable
            ],
        }


def _windows(days: Sequence[date], counts: dict[date, int]) -> list[int]:
    """Volume per consecutive window of eligible days, newest first."""
    out: list[int] = []
    for start in range(0, len(days), WINDOW_DAYS):
        chunk = days[start:start + WINDOW_DAYS]
        if len(chunk) < WINDOW_DAYS:
            break
        out.append(sum(counts.get(d, 0) for d in chunk))
    return out


def summarise(
    *,
    grouping: str,
    per_emitter: dict[str, dict[date, int]],
    eligible: Sequence[date],
) -> list[EmitterVolume]:
    """Trailing window against the median of the windows before it."""
    newest_first = list(reversed(eligible))
    out: list[EmitterVolume] = []
    for emitter, counts in per_emitter.items():
        windows = _windows(newest_first, counts)
        active = sum(1 for d in eligible if counts.get(d, 0) > 0)
        if not windows:
            out.append(EmitterVolume(grouping, emitter, 0, None, active, None, 0))
            continue
        recent = windows[0]
        prior = [w for w in windows[1:BASELINE_WINDOWS + 1]]

        # The most this emitter has been seen to produce in a comparable
        # window, not the median of them.
        #
        # The median was wrong for a reason the first run made visible.
        # `expdc001`'s windows run [36, 97, 54, 27, 16, 1] newest-first: it
        # ramped up through September from an almost-silent August, so the
        # median of its prior windows is 27 and a recent 36 reads as 1.333 —
        # healthy — while it is in fact at 37% of the week before. A median
        # over a history containing a ramp-up measures the ramp, not the
        # health. `expsql003` is worse: [1, 428, 0, 1, 0, 0] has a median of
        # 0, so a host that produced 428 alerts in a week was unjudgeable.
        #
        # Demonstrated capacity cannot be dragged down by quiet history, which
        # is the same principle as the volume floor below: what an emitter has
        # done is a fact about the past.
        baseline = float(max(prior)) if prior else None
        if baseline is None or baseline < MIN_BASELINE_VOLUME:
            # Never produced enough in any past window to be measured against.
            # Genuinely sparse, and "cannot say" is the honest answer — which
            # is a different statement from "healthy" and is listed by name.
            out.append(
                EmitterVolume(grouping, emitter, recent, None, active, None, len(prior))
            )
            continue
        out.append(
            EmitterVolume(
                grouping, emitter, recent, baseline, active,
                recent / baseline, len(prior),
            )
        )
    return out


async def eligible_days(
    db: AsyncSession, *, days: int, excluded_ranges: Iterable[tuple[date, date]] = ()
) -> tuple[list[date], list[date]]:
    """(days usable for a baseline, days the platform itself took nothing)."""
    rows = (await db.execute(text(_ZERO_DAYS_SQL), {"days": days})).all()
    zero = [r.day for r in rows if int(r.n or 0) == 0]
    ranges = list(excluded_ranges)
    usable = [
        r.day
        for r in rows
        if int(r.n or 0) > 0
        and not any(lo <= r.day <= hi for lo, hi in ranges)
    ]
    return usable, zero


async def check(
    db: AsyncSession,
    *,
    days: int = 60,
    excluded_ranges: Iterable[tuple[date, date]] = (),
    exclude_test_hosts: bool = True,
) -> dict[str, FreshnessReport]:
    """Both groupings, in shadow."""
    from app.services.asset_criticality_service import test_hosts

    rigs = await test_hosts(db) if exclude_test_hosts else set()
    ranges = list(excluded_ranges)
    usable, zero = await eligible_days(db, days=days, excluded_ranges=ranges)
    usable_set = set(usable)

    reports: dict[str, FreshnessReport] = {}
    for grouping in GROUPINGS:
        rows = (await db.execute(text(_DAILY_SQL[grouping]), {"days": days})).all()
        per: dict[str, dict[date, int]] = {}
        for r in rows:
            emitter = str(r.emitter or "")
            if not emitter or (grouping == HOST and emitter in rigs):
                continue
            if r.day not in usable_set:
                continue
            per.setdefault(emitter, {})[r.day] = int(r.n or 0)
        volumes = summarise(grouping=grouping, per_emitter=per, eligible=usable)
        reports[grouping] = FreshnessReport(
            eligible_days=len(usable),
            excluded_zero_days=tuple(d.isoformat() for d in zero),
            excluded_ranges=tuple(f"{lo}..{hi}" for lo, hi in ranges),
            excluded_emitters=tuple(sorted(rigs)) if grouping == HOST else (),
            volumes=volumes,
        )
        firing = [v for v in volumes if v.would_alarm()]
        # Shadow: logged at info, never error, and labelled so nobody wires it
        # to a pager before the week of evidence exists.
        logger.info(
            "emitter_freshness_shadow grouping=%s emitters=%d eligible_days=%d "
            "would_alarm_at_25pct=%d [%s]",
            grouping, len(volumes), len(usable), len(firing),
            ", ".join(f"{v.emitter}={v.ratio:.3f}" for v in firing[:12]),
        )
    return reports


# --- what the first shadow run showed, and what it changed -----------------
#
# Run 2026-10-12 over 60 days, 43 eligible, the collapse and 8 zero-ingest days
# excluded, test hosts excluded. The source grouping named exactly the two
# known-silent sources. The host grouping — where the value was supposed to be
# — caught one of the six degraded hosts, and the reason was the statistic
# rather than the threshold.
#
# The window series made it visible, newest-first:
#
#     expdc001     [36,  97,  54, 27, 16, 1]   median 27 -> ratio 1.333
#     expdc002     [ 6,  70,  45, 28,  2, 0]   median 28 -> ratio 0.214
#     expsql003    [ 1, 428,   0,  1,  0, 0]   median  0 -> unjudgeable
#     exp-8brrpb4  [ 8,  35,  30,209,  0, 0]   median 30 -> ratio 0.267
#     exp-fin-034  [ 0,   0,   0,  0,  8, 0]   median  0 -> unjudgeable
#
# Zero-activity days were already counted as zeros — `eligible` is a calendar
# list and `_windows` sums `counts.get(d, 0)` — so the denominator was never
# the problem. The median was. These series contain a ramp-up through
# September from an almost-silent August, and a median over that measures the
# ramp rather than the health.
#
# Against demonstrated capacity instead, the same series give:
#
#     expdc001     36/97  = 0.371    does not fire, and should not: it is at
#                                    37% of the week before, a real decline
#                                    but not a collapse
#     expdc002      6/70  = 0.086    fires
#     expsql003     1/428 = 0.002    fires
#     exp-8brrpb4   8/209 = 0.038    fires
#     exp-fin-034   0/8            baseline 8 is under the volume floor, so it
#                                    stays unjudgeable — it is a genuinely
#                                    sparse emitter, and its 38 days of silence
#                                    is better answered by a last-seen list
#                                    than by a rate
#
# The direction of failure is the thing to check before shipping any monitor
# here, because this is the third one that broke toward reassurance: "one
# alert clears any outage", "zero means never scored", and "a dark host has
# too little history to judge".
