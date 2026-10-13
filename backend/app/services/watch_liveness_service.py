"""Whether each scheduled watch is still running — not whether it alarmed.

The distinction is the whole point. An alarm that does not fire produces
nothing to notice, so "the estate is quiet" and "the alarm is dead" look
identical. A heartbeat that stops produces a *stale timestamp*, which
something else can read. On 2026-09/10 the stall watchdog failed for about a
month at a rate of 21 per 89 minutes, and the only trace was a log line
recording `type(exc).__name__`.

Read in the API process, because a worker cannot report its own death.

Lateness is measured against each task's **own** crontab period, taken from
the beat schedule rather than configured here — and the reason is sharper
than "one threshold would be deaf or noisy".

**Frequency and detectability move together; importance does not.** This
fault needed two tasks to overlap, so exposure scaled with how often a task
ran: the two-minute graph sweep failed 36 times in 89 minutes, the six-hourly
emitter shadow once in 48 hours. That looks like the shadow got off lightly,
and it is the wrong way round. A frequent task failing builds a *visible
backlog* — unmaterialised runs pile up and someone notices. An infrequent one
silently drops a sample, and a time series with holes is not recoverable by
catching up, because the sample was of a moment that has passed.

So the tasks least damaged by a fault are the ones whose damage is hardest to
see, and a shared threshold would be calibrated by the noisy frequent tasks
and deaf to exactly the quiet ones that cannot self-heal. Each task is judged
against its own cadence for that reason, not for tidiness. The multiple is deliberately loose — this
reports, it does not alarm, and this platform's rule is that a monitor runs
in shadow until its own output has set a threshold.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import NEVER_OBSERVED, absent

#: A watch is late past this many of its own periods. Loose on purpose: a
#: two-minute task that misses one tick is ordinary, and the condition worth
#: seeing is a task that has stopped, not one that slipped.
LATE_AFTER_PERIODS = 4

_SQL = "select task, last_ok_at, failures_since from watch_heartbeat"


def _period_seconds(entry: Any) -> float | None:
    """How often beat runs this task, from its own schedule entry."""
    schedule = getattr(entry, "schedule", None) or entry.get("schedule")
    seconds = getattr(schedule, "seconds", None)
    if seconds:
        return float(seconds)
    # A crontab. `remaining_estimate(x)` takes x as the task's *last run*,
    # not as "now", and returns the time from now until the next firing after
    # x. So two estimates one firing apart differ by exactly one period.
    #
    # Two earlier attempts read it as "time from x to the next firing" and
    # produced 181s and 61s for a schedule that fires every 120. The fix was
    # to look at what the function returns rather than at what its name
    # suggests — which is this week's recurring lesson in miniature.
    try:
        now = datetime.now(timezone.utc)
        first = schedule.remaining_estimate(now)
        # One second past the boundary: passing the firing instant itself
        # returns that same firing, and the difference is zero. The epsilon
        # cancels out of the subtraction, so it does not bias the period.
        second = schedule.remaining_estimate(now + first + timedelta(seconds=1))
        period = (second - first).total_seconds()
        return float(period) if period > 0 else None
    except Exception:  # noqa: BLE001 - an unreadable schedule is not an outage
        return None


def scheduled_watches() -> dict[str, float | None]:
    """`{task name: period in seconds}` for everything beat runs.

    Derived from the beat schedule, so a watch added there is covered here
    without anyone remembering — the hand-maintained-list failure that has
    bitten this codebase seven times.
    """
    from app.tasks.celery_app import celery_app

    out: dict[str, float | None] = {}
    for entry in (celery_app.conf.beat_schedule or {}).values():
        task = entry.get("task") if isinstance(entry, dict) else getattr(entry, "task", None)
        if not task:
            continue
        out[str(task).rsplit(".", 1)[-1]] = _period_seconds(entry)
    return out


async def liveness(db: AsyncSession, *, now: datetime | None = None) -> dict[str, Any]:
    """Each scheduled watch, and how long since it last finished."""
    now = now or datetime.now(timezone.utc)
    rows = (await db.execute(text(_SQL))).all()
    beats = {
        str(r.task): (r.last_ok_at, int(r.failures_since or 0)) for r in rows
    }

    watches: dict[str, Any] = {}
    late: list[str] = []
    for name, period in scheduled_watches().items():
        # The heartbeat is keyed by the short name the task reports itself as,
        # which is not always the beat entry's function name.
        reports_as = _ALIASES.get(name, name)
        if reports_as not in INSTRUMENTED:
            # Scheduled, but it does not record a heartbeat. Saying so beats
            # saying "never observed", which would assert a missed run.
            watches[name] = {
                "instrumented": False,
                "period_seconds": period,
                "note": "scheduled, but records no heartbeat — liveness unknown",
            }
            continue
        found = beats.get(reports_as)
        if found is None:
            watches[name] = {
                "instrumented": True,
                "last_ok_at": absent(
                    NEVER_OBSERVED,
                    "This watch has not reported a completed run since the "
                    "heartbeat was deployed. That is either a watch that has "
                    "never succeeded, or one that has not been due yet — the "
                    "period beside it says which is plausible.",
                ).as_json(),
                "period_seconds": period,
            }
            continue
        last_ok, failures = found
        if last_ok.tzinfo is None:
            last_ok = last_ok.replace(tzinfo=timezone.utc)
        age = (now - last_ok).total_seconds()
        is_late = period is not None and age > period * LATE_AFTER_PERIODS
        watches[name] = {
            "instrumented": True,
            "last_ok_at": last_ok.isoformat(),
            "age_seconds": round(age, 1),
            "period_seconds": period,
            "late": is_late,
            # A fresh last_ok_at beside a non-zero count is a flapping task,
            # which neither field reports on its own.
            "failures_since_last_success": failures,
        }
        if is_late:
            late.append(name)

    return {
        "watches": watches,
        "instrumented": sorted(
            k for k, v in watches.items() if v.get("instrumented")
        ),
        "not_instrumented": sorted(
            k for k, v in watches.items() if not v.get("instrumented")
        ),
        "late": sorted(late),
        "note": (
            "This reports whether each watch RAN, which is a different "
            "question from whether it alarmed. A silent alarm and a quiet "
            "estate are indistinguishable; a stale heartbeat is not."
        ),
    }


#: The tasks that record a heartbeat, by the name they record under.
#:
#: Declared rather than inferred, because the beat schedule holds 14 entries
#: and only these five report. Reporting the other nine as `never_observed`
#: would say they *should* have reported and have not — a claim this module
#: cannot support, and nine permanently-red rows is how a signal teaches
#: people to ignore it. They are reported as not instrumented, which is the
#: true statement.
INSTRUMENTED = frozenset({
    "pipeline_watch",
    "schema_watch",
    "ingest_watch",
    "graph_materialise_sweep",
    "emitter_freshness_shadow",
})

#: Scheduled tasks that record no heartbeat, named rather than counted.
#:
#: `not instrumented: 9` beside `late: []` reads as benign, and in six months
#: someone adds a task, the number becomes 10, and nothing happens. That is
#: how "the same 14 baseline failures" became a constant of this project
#: before being enumerated into docs/testing/tolerated-failures.md on the same
#: day as this. So the check is "these nine, and no others" — a diff, not a
#: number that can drift upward unnoticed. `test_watch_liveness` fails when
#: the set changes, in either direction.
#:
#: Instrumenting them is not obviously right: these do work rather than watch
#: for conditions, so their failure is visible in what they did not do —
#: cases left open, videos not purged, pending VT scans unclaimed. The five
#: that are instrumented are the ones whose only output is an observation,
#: where silence and health are indistinguishable.
NOT_INSTRUMENTED = frozenset({
    "close_quiet_cases",          # every 60s
    "correlate_and_notify",       # every 3600s
    "purge_anyrun_videos",        # every 3600s
    "recover_stuck_alert_runs",   # every 180s
    "refresh_stale_ip_lookups",   # every 86400s
    "resume_sandbox_analyses",    # every 300s
    "sweep_alert_log_context",    # every 60s
    "vt_collect_pending",         # every 900s
    "watchlist_check",            # every 3600s
})

#: Where the beat entry's function name and the task's own reporting name
#: differ. Small and explicit rather than inferred.
_ALIASES = {
    "watch_pipeline": "pipeline_watch",
    "watch_schema": "schema_watch",
    "watch_ingest": "ingest_watch",
    "materialise_graphs": "graph_materialise_sweep",
}
