"""A watch task must not report failure in a shape that reads as success.

On 2026-10-13 a drain loop read `{"ran": False, "error": ...}` as "the sweep
finished with nothing to do", because `.get("materialised", 0)` gave 0 and
`.get("remaining")` gave None. 36 sweeps an hour were failing at the time and
had been for about a month. The same shape was returned by the pipeline stall
watchdog — the alarm whose whole purpose is that a worker dying on every task
and a worker with nothing to do produce the same queue.

`app/services/absence.py` has said how to do this since the first
honest-absence work: a thing that is not there carries the reason it is not
there, in a shape nothing can mistake for a value. This is that, one layer out.
"""

from __future__ import annotations

import logging

import pytest

from app.tasks import pipeline_watch_task as mod

TASKS = [
    ("watch_pipeline", "_pipeline"),
    ("watch_schema", "_schema"),
    ("watch_ingest", "_ingest"),
    ("materialise_graphs", "_materialise"),
    ("emitter_freshness_shadow", "_freshness_shadow"),
]


@pytest.mark.parametrize("task_name,inner", TASKS)
def test_a_failure_is_structurally_distinguishable(monkeypatch, task_name, inner):
    """The property that was missing: a caller can tell without knowing which
    fields a success would have carried."""
    assert hasattr(mod, inner), f"{inner} missing — the task was renamed"

    async def boom():
        raise RuntimeError("got Future attached to a different loop")

    monkeypatch.setattr(mod, inner, boom)
    result = getattr(mod, task_name)()
    assert result[mod.FAILED] is True
    assert mod.succeeded(result) is False
    assert "different loop" in result["error"]
    assert result["task"]


@pytest.mark.parametrize("task_name,inner", TASKS)
def test_the_failure_carries_no_field_a_success_would_carry(
    monkeypatch, task_name, inner
):
    """`materialised`, `remaining` and `ok` must be absent, not zero or None.

    A zero reads as "nothing to do" and a None reads as "finished" — the two
    readings that hid this."""
    assert hasattr(mod, inner), f"{inner} missing — the task was renamed"

    async def boom():
        raise RuntimeError("x")

    monkeypatch.setattr(mod, inner, boom)
    result = getattr(mod, task_name)()
    for field in ("materialised", "remaining", "considered", "entities"):
        assert field not in result


def test_the_log_carries_the_message_not_just_the_type(monkeypatch, caplog):
    """A month of bare `RuntimeError` is half the reason this took a month.

    The exception text said which loop conflict it was, and only the discarded
    return value ever carried it."""

    async def boom():
        raise RuntimeError("got Future attached to a different loop")

    monkeypatch.setattr(mod, "_materialise", boom)
    with caplog.at_level(logging.ERROR):
        mod.materialise_graphs()
    assert "different loop" in caplog.text
    assert "RuntimeError" in caplog.text


def test_succeeded_rejects_everything_that_is_not_a_result():
    assert mod.succeeded({"materialised": 3, "remaining": 0}) is True
    assert mod.succeeded({mod.FAILED: True}) is False
    assert mod.succeeded(None) is False
    assert mod.succeeded("ok") is False
    assert mod.succeeded([]) is False


def test_the_old_shape_would_have_failed_this_test():
    """Pinning the regression itself: the shape that caused the incident."""
    old = {"ran": False, "error": "RuntimeError: ..."}
    assert mod.succeeded(old) is False, (
        "a bare {'ran': False} has no FAILED marker — if this passes, the "
        "failure shape has regressed to one a .get() caller reads as success"
    )
