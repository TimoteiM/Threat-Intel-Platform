"""The second half of a live alert's window, and why running it twice is safe.

No database: the row is a stub with the same attributes, because what is worth
pinning is the arithmetic of the high-water mark and the merge, not SQLAlchemy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services import alert_log_context_store as store
from app.services.alert_log_context_service import LogContext

EVENT = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
START, END = EVENT - timedelta(minutes=10), EVENT + timedelta(minutes=10)


class Settings:
    alert_log_followup_delay_seconds = 120
    alert_log_followup_max_attempts = 5
    alert_log_case_max_hits = 2000
    alert_log_context_enabled = True


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(store, "get_settings", lambda: Settings())


class Row:
    """The columns `record_attempt` touches."""

    def __init__(self, **kw):
        self.run_id = "11111111-1111-1111-1111-111111111111"
        self.status = "partial"
        self.reason = None
        self.window_start = START
        self.window_end = END
        self.covered_until = EVENT + timedelta(minutes=2)
        self.attempts = 0
        self.next_attempt_at = None
        self.last_error = None
        self.truncated = False
        self.logs: list = []
        self.selectors: dict = {}
        self.sources: dict = {}
        self.updated_at = None
        for k, v in kw.items():
            setattr(self, k, v)


class FakeDB:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1

    def refresh(self, _row):
        pass


def _log(doc_id, ts="2026-09-23T12:05:00+0000"):
    return {"key": f"wazuh-alerts-4.x-2026.09.23:{doc_id}", "index": "wazuh-alerts-4.x-2026.09.23",
            "id": doc_id, "timestamp": ts}


def _context(status, logs, covered):
    return LogContext(
        status=status, logs=logs,
        window={"start": START.isoformat(), "end": END.isoformat(),
                "covered_until": covered.isoformat(), "complete": covered >= END},
        sources={"pages": 1},
    )


# --- the flow that completes -------------------------------------------------

def test_a_completed_window_becomes_collected():
    row, db = Row(logs=[_log("a")]), FakeDB()
    store.record_attempt(db, row, _context("collected", [_log("b")], END))
    assert row.status == "collected"
    assert [r["id"] for r in row.logs] == ["a", "b"]
    assert row.covered_until == END
    assert row.next_attempt_at is None


def test_a_window_that_was_genuinely_empty_ends_empty_not_collected():
    row, db = Row(logs=[]), FakeDB()
    store.record_attempt(db, row, _context("collected", [], END))
    assert row.status == "empty"
    assert "No logs matched" in row.reason


# --- the property the whole design rests on ----------------------------------

def test_running_the_follow_up_twice_changes_nothing():
    """The scheduled task and the sweep can both fire for the same row. That is
    the point of having both, and it is only safe because this holds."""
    row, db = Row(logs=[_log("a")]), FakeDB()
    context = _context("collected", [_log("a"), _log("b")], END)

    store.record_attempt(db, row, context)
    first = list(row.logs)
    store.record_attempt(db, row, context)

    assert row.logs == first
    assert len(row.logs) == 2
    assert row.attempts == 2   # counted honestly; the data is unchanged


def test_the_high_water_mark_never_moves_backwards():
    """A later read that covered less must not re-open ground already read —
    otherwise a retry would re-fetch, and the merge would be doing all the work."""
    row, db = Row(covered_until=EVENT + timedelta(minutes=8)), FakeDB()
    store.record_attempt(db, row, _context("partial", [], EVENT + timedelta(minutes=4)))
    assert row.covered_until == EVENT + timedelta(minutes=8)


def test_an_incomplete_window_stays_pending_and_is_rescheduled():
    row, db = Row(), FakeDB()
    store.record_attempt(db, row, _context("partial", [_log("a")], EVENT + timedelta(minutes=5)))
    assert row.status == "partial"
    assert row.next_attempt_at is not None


# --- giving up ---------------------------------------------------------------

def test_a_cluster_that_is_down_is_retried_with_a_growing_gap():
    row, db = Row(), FakeDB()
    context = LogContext(status="unavailable", reason="no node answered",
                         window={"start": START.isoformat(), "end": END.isoformat(),
                                 "covered_until": row.covered_until.isoformat()})
    store.record_attempt(db, row, context)
    first_gap = row.next_attempt_at
    store.record_attempt(db, row, context)
    assert row.status == "unavailable"
    assert row.next_attempt_at > first_gap
    assert row.last_error == "no node answered"


def test_it_stops_after_the_attempt_limit():
    """A cluster unreachable all afternoon is not going to answer on the sixth
    try within this alert's useful life."""
    row, db = Row(), FakeDB()
    context = LogContext(status="unavailable", reason="no node answered",
                         window={"start": START.isoformat(), "end": END.isoformat(),
                                 "covered_until": row.covered_until.isoformat()})
    for _ in range(Settings.alert_log_followup_max_attempts):
        store.record_attempt(db, row, context)
    assert row.status == "failed"
    assert row.next_attempt_at is None
    assert "Gave up after 5 attempts" in row.reason


# --- correlated cases --------------------------------------------------------

def test_a_case_combines_its_members_and_removes_duplicates():
    """Alerts minutes apart on one host produce windows that share most of their
    logs; concatenating would show the same line five times."""
    a = Row(logs=[_log("x"), _log("y")], status="collected")
    b = Row(logs=[_log("y"), _log("z")], status="collected")
    combined = store.combine_for_case([a, b])
    assert [r["id"] for r in combined["logs"]] == ["x", "y", "z"]
    assert combined["status"] == "collected"
    assert combined["sources"]["member_count"] == 2


def test_a_case_is_only_as_complete_as_its_least_complete_member():
    a = Row(logs=[_log("x")], status="collected")
    b = Row(logs=[], status="partial")
    assert store.combine_for_case([a, b])["status"] == "partial"


def test_a_case_log_set_is_capped():
    row = Row(logs=[_log(f"d{i}", ts=f"2026-09-23T12:0{i % 10}:00+0000") for i in range(50)],
              status="collected")
    combined = store.combine_for_case([row], max_logs=10)
    assert combined["log_count"] == 10
    assert combined["unique_before_cap"] == 50
    assert combined["truncated"] is True


# --- registration ------------------------------------------------------------

def test_the_follow_up_task_is_registered_with_the_worker():
    """This list has swallowed four features. An unregistered follow-up means
    every real-time alert silently keeps only the logs it grabbed in the first
    second."""
    from app.tasks.celery_app import celery_app
    import app.tasks.alert_log_followup_task  # noqa: F401  (registers on import)

    assert "app.tasks.alert_log_followup_task.complete_alert_log_context" in celery_app.tasks
    assert "app.tasks.alert_log_followup_task.sweep_alert_log_context" in celery_app.tasks
    assert "alert-log-context-sweep" in celery_app.conf.beat_schedule
