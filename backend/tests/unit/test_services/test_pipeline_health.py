"""A stalled queue must not look like a quiet one.

Written after an outage that ran 2h38m with no signal but a person looking at
a screen: migration 055 renamed a column, `api` was rebuilt, `worker` and
`beat` were not, and the worker died with UndefinedColumnError on every
analysis task while alerts piled up in `queued`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.pipeline_health_service import (
    DEPTH_WARNING,
    STALL_AFTER,
    PipelineHealth,
)

NOW = datetime(2026, 10, 9, 13, 0, tzinfo=timezone.utc)


def _health(**kw) -> PipelineHealth:
    base = dict(queued=0, processing=0, last_verdict_at=NOW, oldest_queued_at=None, now=NOW)
    base.update(kw)
    return PipelineHealth(**base)


def test_alerts_waiting_with_nothing_completing_is_a_stall():
    """The outage. 23 alerts queued, last verdict 38 minutes earlier, every
    page looking normal."""
    health = _health(
        queued=23,
        oldest_queued_at=NOW - timedelta(minutes=38),
        last_verdict_at=NOW - timedelta(minutes=38),
    )
    assert health.stalled is True
    assert health.as_json()["stalled"] is True


def test_an_empty_queue_is_never_a_stall_however_old_the_last_verdict():
    """A genuinely idle estate has no recent verdict and nothing wrong. This
    half is why time-since-last alone cannot be the alarm."""
    health = _health(queued=0, last_verdict_at=NOW - timedelta(days=3))
    assert health.stalled is False


def test_a_deep_queue_that_is_completing_work_is_not_a_stall():
    """And this half is why depth alone cannot be the alarm: a busy pipeline
    looks deep and is fine."""
    health = _health(
        queued=400, processing=8,
        oldest_queued_at=NOW - timedelta(hours=2),
        last_verdict_at=NOW - timedelta(seconds=5),
    )
    assert health.stalled is False
    assert health.as_json()["deep"] is True


def test_a_brief_backlog_is_not_a_stall():
    """An analysis takes seconds, so a few minutes of queue is normal traffic.
    Alarming on it would train everyone to ignore the alarm."""
    health = _health(
        queued=12,
        oldest_queued_at=NOW - timedelta(minutes=2),
        last_verdict_at=NOW - timedelta(minutes=2),
    )
    assert health.stalled is False


def test_never_having_produced_a_verdict_counts_as_stalled_when_work_waits():
    """A pipeline that has never completed anything and has alerts waiting is
    broken, not new."""
    health = _health(
        queued=5, last_verdict_at=None,
        oldest_queued_at=NOW - timedelta(hours=1),
    )
    assert health.stalled is True
    assert health.as_json()["seconds_since_last_verdict"] is None


def test_the_threshold_is_far_below_the_outage_it_was_written_for():
    assert STALL_AFTER <= timedelta(minutes=15), (
        "the outage ran 2h38m before a person noticed; a threshold near that "
        "duration would not have caught it meaningfully sooner"
    )
    assert DEPTH_WARNING >= 1


def test_the_watchdog_tasks_are_registered_with_the_worker():
    """This list has caused the identical symptom five times — the comments in
    `celery_app.py` count them — and the symptom is alerts sitting in `queued`
    for ever. An unregistered watchdog would mean the alarm for that failure is
    itself subject to that failure.
    """
    from app.tasks.celery_app import celery_app
    import app.tasks.pipeline_watch_task  # noqa: F401

    for name in (
        "app.tasks.pipeline_watch_task.watch_pipeline",
        "app.tasks.pipeline_watch_task.watch_schema",
    ):
        assert name in celery_app.tasks, (
            f"{name} is not registered. Add its module to the "
            "autodiscover_tasks list in app/tasks/celery_app.py — an "
            "unregistered task is accepted by the API and rejected by the "
            "worker, which is how this list became the bug five times."
        )


def test_both_watchdogs_are_scheduled():
    from app.tasks.celery_app import celery_app

    scheduled = {
        entry["task"] for entry in celery_app.conf.beat_schedule.values()
    }
    assert "app.tasks.pipeline_watch_task.watch_pipeline" in scheduled
    assert "app.tasks.pipeline_watch_task.watch_schema" in scheduled
