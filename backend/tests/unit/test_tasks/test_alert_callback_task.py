"""
Callback delivery: the run must always end with a terminal callback status.

Regression cover for a delivery to a receiver that never answered — Celery's own
retry limit ran out before ours, the task died with an unhandled exception, and
the run was left recorded as "retrying" for ever.
"""

import os
from types import SimpleNamespace

import pytest
import requests
from celery.exceptions import MaxRetriesExceededError

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.config import get_settings
from app.tasks import alert_callback_task as task_mod


@pytest.fixture
def recorded(monkeypatch):
    """Capture what the task writes onto the run instead of touching the DB."""
    states: list[dict] = []
    monkeypatch.setattr(
        task_mod,
        "_record",
        lambda run_uuid, **fields: states.append(dict(fields)),
    )
    return states


def _task(retries_raise: bool = False):
    """A stand-in for the bound task: records retry() calls, or blows the budget."""
    calls: list[dict] = []

    def retry(**kwargs):
        calls.append(kwargs)
        if retries_raise:
            raise MaxRetriesExceededError()
        raise AssertionError("retry() should propagate in real Celery; test stops here")

    return SimpleNamespace(retry=retry, calls=calls)


def test_backoff_doubles_and_is_capped():
    assert [task_mod._backoff_seconds(n) for n in (1, 2, 3, 4)] == [10, 20, 40, 80]
    assert task_mod._backoff_seconds(20) == 600


def test_a_retryable_failure_schedules_the_next_attempt(recorded, monkeypatch):
    task = _task()
    monkeypatch.setattr(get_settings(), "alert_callback_max_retries", 5)

    with pytest.raises(AssertionError):          # our stub's stand-in for Retry
        task_mod._retry_or_give_up(task, "run-1", "uuid-1", error="boom", attempt=1)

    assert recorded[-1]["status"] == "retrying"
    assert task.calls[0]["countdown"] == 10
    assert task.calls[0]["max_retries"] == 5


def test_the_last_attempt_records_a_final_failure(recorded, monkeypatch):
    """Past the budget: no further retry, and the run stops saying 'retrying'."""
    task = _task()
    monkeypatch.setattr(get_settings(), "alert_callback_max_retries", 3)

    result = task_mod._retry_or_give_up(task, "run-1", "uuid-1", error="refused", attempt=4)

    assert result == "run-1"
    assert task.calls == []                       # no retry was scheduled
    assert recorded[-1]["status"] == "failed"
    assert recorded[-1]["error"] == "refused"


def test_an_exhausted_celery_budget_still_ends_as_failed(recorded, monkeypatch):
    """Even if Celery refuses the retry, the record must be terminal."""
    task = _task(retries_raise=True)
    monkeypatch.setattr(get_settings(), "alert_callback_max_retries", 5)

    result = task_mod._retry_or_give_up(task, "run-1", "uuid-1", error="refused", attempt=2)

    assert result == "run-1"
    assert [state["status"] for state in recorded] == ["retrying", "failed"]


def test_the_task_no_longer_autoretries_behind_our_back():
    options = task_mod.deliver_alert_callback.__dict__
    autoretry = getattr(task_mod.deliver_alert_callback, "autoretry_for", ())
    assert not autoretry, "autoretry_for would exhaust Celery's budget before ours"
    assert requests.RequestException not in tuple(autoretry or ())
    assert options is not None
