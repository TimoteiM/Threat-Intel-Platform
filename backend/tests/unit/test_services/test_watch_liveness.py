"""Does each scheduled watch still run — asked separately from did it alarm.

A silent alarm and a quiet estate are indistinguishable, which is the
condition `watch_pipeline` exists to detect and the one it reproduced for a
month. A stale heartbeat is distinguishable, which is why the signal is "it
finished" rather than "it alarmed".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services import watch_liveness_service as mod


class _Row:
    def __init__(self, task, last_ok_at, failures_since=0):
        self.task, self.last_ok_at, self.failures_since = task, last_ok_at, failures_since


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _DB:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, *_a, **_k):
        return _Result(self._rows)


NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


async def _liveness(rows, schedule):
    import app.services.watch_liveness_service as m

    original = m.scheduled_watches
    m.scheduled_watches = lambda: schedule
    try:
        return await m.liveness(_DB(rows), now=NOW)
    finally:
        m.scheduled_watches = original


@pytest.mark.asyncio
async def test_a_watch_that_finished_recently_is_not_late():
    out = await _liveness(
        [_Row("pipeline_watch", NOW - timedelta(seconds=30))],
        {"watch_pipeline": 120.0},
    )
    assert out["watches"]["watch_pipeline"]["late"] is False
    assert out["late"] == []


@pytest.mark.asyncio
async def test_a_watch_silent_for_many_periods_is_late():
    out = await _liveness(
        [_Row("pipeline_watch", NOW - timedelta(minutes=30))],
        {"watch_pipeline": 120.0},
    )
    assert out["watches"]["watch_pipeline"]["late"] is True
    assert out["late"] == ["watch_pipeline"]


@pytest.mark.asyncio
async def test_lateness_is_measured_against_each_tasks_own_period():
    """The sweep runs every two minutes and the shadow four times a day. One
    threshold for both is either deaf or noisy."""
    silent_for = timedelta(hours=3)
    out = await _liveness(
        [
            _Row("pipeline_watch", NOW - silent_for),
            _Row("emitter_freshness_shadow", NOW - silent_for),
        ],
        {"watch_pipeline": 120.0, "emitter_freshness_shadow": 21600.0},
    )
    assert out["watches"]["watch_pipeline"]["late"] is True
    assert out["watches"]["emitter_freshness_shadow"]["late"] is False


@pytest.mark.asyncio
async def test_a_task_that_records_no_heartbeat_is_not_reported_as_missing():
    """Nine of the fourteen scheduled tasks record nothing. Calling those
    `never_observed` would assert a missed run this module cannot support —
    and nine permanently-red rows teach people to ignore the signal."""
    out = await _liveness([], {"close_quiet_cases": 60.0})
    entry = out["watches"]["close_quiet_cases"]
    assert entry["instrumented"] is False
    assert "last_ok_at" not in entry
    assert out["not_instrumented"] == ["close_quiet_cases"]


@pytest.mark.asyncio
async def test_an_instrumented_watch_with_no_row_says_never_observed():
    out = await _liveness([], {"watch_pipeline": 120.0})
    entry = out["watches"]["watch_pipeline"]
    assert entry["instrumented"] is True
    assert entry["last_ok_at"]["kind"] == "never_observed"
    # Absent, not late: nothing is known, and "late" would be a claim.
    assert "late" not in entry


@pytest.mark.asyncio
async def test_a_fresh_heartbeat_beside_failures_reports_both():
    """Neither field says "flapping" alone."""
    out = await _liveness(
        [_Row("pipeline_watch", NOW - timedelta(seconds=10), failures_since=7)],
        {"watch_pipeline": 120.0},
    )
    entry = out["watches"]["watch_pipeline"]
    assert entry["late"] is False
    assert entry["failures_since_last_success"] == 7


@pytest.mark.asyncio
async def test_a_naive_timestamp_is_read_as_utc():
    out = await _liveness(
        [_Row("pipeline_watch", datetime(2026, 10, 13, 11, 59, 30))],
        {"watch_pipeline": 120.0},
    )
    assert out["watches"]["watch_pipeline"]["age_seconds"] == 30.0


def test_the_periods_come_from_the_beat_schedule_not_a_second_list():
    """A hand-maintained copy of the schedule is the failure this codebase
    has had seven times."""
    found = mod.scheduled_watches()
    assert found["materialise_graphs"] == pytest.approx(120, abs=2)
    assert found["watch_schema"] == pytest.approx(3600, abs=2)
    assert found["emitter_freshness_shadow"] == pytest.approx(21600, abs=2)
    assert found["refresh_stale_ip_lookups"] == pytest.approx(86400, abs=2)


def test_every_instrumented_name_is_actually_on_the_schedule():
    """A name in INSTRUMENTED that beat does not run would silently never
    report, which is the condition this module exists to surface."""
    scheduled = set(mod.scheduled_watches())
    reporting = {mod._ALIASES.get(n, n) for n in scheduled}
    assert mod.INSTRUMENTED <= reporting


def test_the_uninstrumented_tasks_are_named_not_counted():
    """"not instrumented: 9" beside "late: []" reads as benign, and the
    number drifts upward silently when someone adds a task. Enumerated, the
    check is a diff — and this fails in either direction, so a task that
    gains a heartbeat has to be removed from the list deliberately.
    """
    scheduled = set(mod.scheduled_watches())
    reporting = {mod._ALIASES.get(n, n) for n in scheduled}
    uninstrumented = reporting - mod.INSTRUMENTED
    assert uninstrumented == set(mod.NOT_INSTRUMENTED), (
        "the set of scheduled tasks without a heartbeat has changed; update "
        "NOT_INSTRUMENTED deliberately rather than letting the count drift"
    )


def test_every_scheduled_task_is_accounted_for():
    """No task may be in neither set: that is how one goes unwatched without
    anyone choosing it."""
    scheduled = set(mod.scheduled_watches())
    reporting = {mod._ALIASES.get(n, n) for n in scheduled}
    assert reporting == mod.INSTRUMENTED | set(mod.NOT_INSTRUMENTED)
