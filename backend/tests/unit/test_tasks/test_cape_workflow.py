"""The CAPE workflow: adopting, submitting, polling, resuming.

No database and no network. The module's own persistence helpers are replaced
so the decisions are visible — which is the part worth testing, because every
one of them can lose a sample or detonate it twice.
"""

from __future__ import annotations

import pytest

from app.services import cape_analysis_service as svc
from app.services import cape_client as cape
from app.tasks import cape_task

ANALYSIS_ID = "22222222-2222-2222-2222-222222222222"
SHA = "a" * 64


class Settings:
    cape_configured = True
    cape_enabled = True
    cape_reuse_existing_analysis = True
    cape_poll_interval_seconds = 0
    cape_max_poll_duration_seconds = 60
    cape_report_format_list = ["json"]
    cape_route = "internet"
    cape_analysis_timeout_seconds = 180


class FakeClient:
    """A CAPE that does exactly what a test tells it to."""

    def __init__(self, *, search=None, views=None, submit=None, report=None):
        self._search = search or []
        self._views = list(views or [])
        self._submit = submit
        self._report = report
        self.submissions = 0
        self.searches = 0

    def search_by_sha256(self, sha256):
        self.searches += 1
        if isinstance(self._search, Exception):
            raise self._search
        return list(self._search)

    def submit_file(self, **kwargs):
        self.submissions += 1
        if isinstance(self._submit, Exception):
            raise self._submit
        return self._submit

    def view_task(self, task_id):
        return self._views.pop(0)

    def fetch_report(self, task_id, formats=None):
        return self._report


def task(task_id, status):
    return cape.CapeTask(task_id=task_id, status=status)


@pytest.fixture
def recorder(monkeypatch):
    """Capture the persistence calls instead of writing to Postgres."""
    events: list[tuple] = []
    monkeypatch.setattr(cape_task, "_set_status", lambda aid, s, note=None: events.append(("status", s)))
    monkeypatch.setattr(cape_task, "_record_task",
                        lambda aid, tid, reused, note: events.append(("task", str(tid), reused)))
    monkeypatch.setattr(cape_task, "_bump_poll", lambda aid: None)
    monkeypatch.setattr(cape_task, "_terminal",
                        lambda aid, s, error, note: events.append(("terminal", s, error)))
    monkeypatch.setattr(cape_task, "time", type("T", (), {"monotonic": staticmethod(lambda: 0.0),
                                                          "sleep": staticmethod(lambda s: None)}))
    return events


# ── Adopting an existing analysis ────────────────────────────────────────────


def test_an_existing_reported_analysis_is_adopted_instead_of_detonating_again(recorder, monkeypatch):
    client = FakeClient(search=[task(10, "reported"), task(11, "reported")])
    got = cape_task._obtain_task(client, ANALYSIS_ID, SHA, None, "x.exe", Settings())

    assert got == "11", "the most recent reported analysis should win"
    assert client.submissions == 0, "adopting must not submit"
    assert ("task", "11", True) in recorder


def test_a_running_analysis_is_not_adopted():
    """Somebody else's in-flight task is not our result."""
    client = FakeClient(search=[task(10, "running"), task(11, "pending")])
    assert cape_task._find_reusable(client, SHA) is None


def test_a_failed_analysis_is_not_adopted():
    client = FakeClient(search=[task(10, "failed_analysis")])
    assert cape_task._find_reusable(client, SHA) is None


def test_reuse_disabled_goes_straight_to_submission(recorder, monkeypatch):
    class NoReuse(Settings):
        cape_reuse_existing_analysis = False

    monkeypatch.setattr(cape_task, "_resolve_sample", lambda *a: (_FakePath(), "x.exe"))
    client = FakeClient(search=[task(10, "reported")],
                        submit=cape.CapeSubmission(task_ids=(99,)))
    got = cape_task._obtain_task(client, ANALYSIS_ID, SHA, None, "x.exe", NoReuse())
    assert got == "99"
    assert client.searches == 0 and client.submissions == 1


def test_a_failing_search_falls_back_to_submitting(monkeypatch):
    client = FakeClient(search=cape.CapeError("search unavailable"))
    assert cape_task._find_reusable(client, SHA) is None


# ── Submission safety ────────────────────────────────────────────────────────


class _FakePath:
    def open(self, _mode):
        import io

        return io.BytesIO(b"harmless fixture")

    def exists(self):
        return True

    def is_file(self):
        return True


def test_a_hash_with_no_file_and_no_prior_analysis_fails_cleanly(recorder):
    """An alert carrying a hash we have no sample for. Expected, not a fault."""
    client = FakeClient(search=[])
    got = cape_task._obtain_task(client, ANALYSIS_ID, SHA, None, None, Settings())
    assert got is None
    assert client.submissions == 0
    terminal = [e for e in recorder if e[0] == "terminal"]
    assert terminal and terminal[0][1] == svc.STATUS_FAILED
    assert "No file is available" in terminal[0][2]


def test_an_ambiguous_submission_is_reconciled_by_hash_not_resent(recorder, monkeypatch):
    """The rule this whole module is arranged around."""
    monkeypatch.setattr(cape_task, "_resolve_sample", lambda *a: (_FakePath(), "x.exe"))
    client = FakeClient(
        search=[task(77, "pending")],
        submit=cape.CapeAmbiguousSubmission("timed out"),
    )
    got = cape_task._obtain_task(client, ANALYSIS_ID, SHA, None, "x.exe", Settings())

    assert got == "77", "the task that the timed-out POST actually created"
    assert client.submissions == 1, "it must never be resubmitted"
    assert ("task", "77", False) in recorder


def test_an_ambiguous_submission_with_nothing_found_fails_without_resending(recorder, monkeypatch):
    monkeypatch.setattr(cape_task, "_resolve_sample", lambda *a: (_FakePath(), "x.exe"))
    calls = {"search": 0}

    class Client(FakeClient):
        def search_by_sha256(self, sha256):
            calls["search"] += 1
            return [] if calls["search"] > 1 else []

    client = Client(submit=cape.CapeAmbiguousSubmission("timed out"))
    got = cape_task._obtain_task(client, ANALYSIS_ID, SHA, None, "x.exe", Settings())

    assert got is None
    assert client.submissions == 1
    terminal = [e for e in recorder if e[0] == "terminal"]
    assert "NOT resubmitted automatically" in terminal[0][2]


# ── Polling ──────────────────────────────────────────────────────────────────


def test_polling_walks_the_states_and_stores_the_report(recorder, monkeypatch):
    stored = {}
    monkeypatch.setattr(cape_task, "_store_report",
                        lambda c, a, t, s: stored.setdefault("task", t) or {"status": svc.STATUS_REPORTED})
    client = FakeClient(views=[task(5, "pending"), task(5, "running"),
                               task(5, "completed"), task(5, "reported")])

    cape_task._poll_and_store(client, ANALYSIS_ID, "5", Settings())

    seen = [e[1] for e in recorder if e[0] == "status"]
    assert seen == [svc.STATUS_PENDING, svc.STATUS_RUNNING, svc.STATUS_PROCESSING]
    assert stored["task"] == "5"


def test_an_unchanged_state_is_not_recorded_twice(recorder, monkeypatch):
    monkeypatch.setattr(cape_task, "_store_report", lambda *a: {"status": svc.STATUS_REPORTED})
    client = FakeClient(views=[task(5, "running"), task(5, "running"),
                               task(5, "running"), task(5, "reported")])
    cape_task._poll_and_store(client, ANALYSIS_ID, "5", Settings())
    assert [e[1] for e in recorder if e[0] == "status"] == [svc.STATUS_RUNNING]


def test_a_failed_cape_task_ends_the_workflow(recorder):
    client = FakeClient(views=[task(5, "failed_analysis")])
    result = cape_task._poll_and_store(client, ANALYSIS_ID, "5", Settings())
    assert result["status"] == svc.STATUS_FAILED
    assert [e for e in recorder if e[0] == "terminal"][0][1] == svc.STATUS_FAILED


def test_polling_stops_at_the_deadline_and_says_the_task_may_still_run(monkeypatch, recorder):
    clock = {"t": 0.0}

    def monotonic():
        clock["t"] += 100.0
        return clock["t"]

    monkeypatch.setattr(cape_task, "time",
                        type("T", (), {"monotonic": staticmethod(monotonic),
                                       "sleep": staticmethod(lambda s: None)}))
    client = FakeClient(views=[task(5, "running")] * 10)
    result = cape_task._poll_and_store(client, ANALYSIS_ID, "5", Settings())

    assert result["status"] == svc.STATUS_TIMED_OUT
    terminal = [e for e in recorder if e[0] == "terminal"][0]
    assert "may still be running on CAPE" in terminal[2]


# ── Mapping CAPE's states onto ours ──────────────────────────────────────────


@pytest.mark.parametrize(
    "cape_state,expected",
    [("pending", svc.STATUS_PENDING), ("running", svc.STATUS_RUNNING),
     ("completed", svc.STATUS_PROCESSING), ("processing", svc.STATUS_PROCESSING),
     ("reported", svc.STATUS_REPORTED), ("failed_analysis", svc.STATUS_FAILED),
     ("failed_processing", svc.STATUS_FAILED)],
)
def test_cape_states_map_onto_platform_states(cape_state, expected):
    assert svc.CAPE_STATE_MAP[cape_state] == expected


def test_an_unknown_cape_state_does_not_crash_the_poller():
    assert svc.CAPE_STATE_MAP.get("something_new", svc.STATUS_RUNNING) == svc.STATUS_RUNNING


# ── Restart and resume ───────────────────────────────────────────────────────


def test_an_unconfigured_deployment_resumes_nothing(monkeypatch):
    class Off:
        cape_configured = False

    monkeypatch.setattr(cape_task, "get_settings", lambda: Off())
    assert cape_task.resume_sandbox_analyses()["resumed"] == 0


def test_only_unfinished_analyses_are_resumable():
    assert svc.STATUS_REPORTED not in svc.ACTIVE_STATUSES
    assert svc.STATUS_FAILED not in svc.ACTIVE_STATUSES
    for state in (svc.STATUS_QUEUED, svc.STATUS_SUBMITTED, svc.STATUS_RUNNING, svc.STATUS_PROCESSING):
        assert state in svc.ACTIVE_STATUSES


def test_a_resumed_analysis_that_already_has_a_task_id_is_polled_not_resubmitted(recorder, monkeypatch):
    """Worker-restart safety: the expensive step is never repeated."""
    monkeypatch.setattr(cape_task, "_store_report", lambda *a: {"status": svc.STATUS_REPORTED})
    client = FakeClient(views=[task(42, "reported")])
    cape_task._poll_and_store(client, ANALYSIS_ID, "42", Settings())
    assert client.submissions == 0 and client.searches == 0
