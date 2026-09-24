"""A domain or URL investigation detonates without anyone pressing a button.

No database and no network: the collector's persistence and its hand-off to the
workflow are replaced, because what is worth pinning is the decisions — when it
detonates, when it declines to, and what it says when it runs out of patience.

The waiting itself is bounded and then given up on, deliberately. Measured over
the URL analyses in this platform's own record, a fresh CAPE detonation takes
271-321 seconds, of which 180 is the enforced in-VM analysis timeout. No inline
budget an analyst would tolerate can wait that out, so the collector defers and
the workflow merges the report when it lands.
"""

from __future__ import annotations

import pytest

from app.collectors import cape_collector as mod
from app.collectors.cape_collector import CapeCollector
from app.services import cape_analysis_service as svc

INVESTIGATION = "11111111-1111-1111-1111-111111111111"
ANALYSIS = "22222222-2222-2222-2222-222222222222"


class Settings:
    cape_configured = True
    cape_auto_detonate_urls = True
    cape_inline_wait_seconds = 10
    cape_inline_poll_seconds = 5


def _collector(observable_type="domain", context=None, **kwargs):
    return CapeCollector(
        domain=kwargs.pop("domain", "suspicious-example.com"),
        investigation_id=INVESTIGATION,
        timeout=30,
        observable_type=observable_type,
        file_artifact_id=None,
        external_context=context if context is not None else {"cape_detonate": True},
    )


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(mod, "get_settings", lambda: Settings())
    # Nothing in this module may sleep for real: the budget is the thing under
    # test, and a test that honours it takes as long as the budget.
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)


def _fake_clock(monkeypatch, steps):
    """A monotonic clock that advances by `steps` on each successive call."""
    ticks = iter(list(steps) + [10**6])
    state = {"now": 0.0}

    def _monotonic():
        state["now"] += next(ticks, 10**6)
        return state["now"]

    monkeypatch.setattr(mod.time, "monotonic", _monotonic)


# --- when it declines to detonate -------------------------------------------

def test_no_detonation_without_the_callers_say_so():
    """The gate is evaluated once, in the investigation task, with the fast
    collectors' evidence in hand. A collector deciding for itself would detonate
    every URL in every pasted alert body."""
    assert _collector(context={})._detonate_and_wait() is None


def test_no_detonation_when_the_setting_is_off(monkeypatch):
    class Off(Settings):
        cape_auto_detonate_urls = False

    monkeypatch.setattr(mod, "get_settings", lambda: Off())
    assert _collector()._detonate_and_wait() is None


def test_no_detonation_for_an_ip():
    """CAPE fetches and detonates a URL. An IP is not something it can fetch, so
    the lookup is the whole of what this collector can say about one."""
    assert _collector(observable_type="ip", domain="185.220.101.44")._detonate_and_wait() is None


# --- when it does ------------------------------------------------------------

def test_a_report_that_lands_within_the_budget_is_returned(monkeypatch):
    report = object()
    monkeypatch.setattr(CapeCollector, "_start", lambda self, t, c: (ANALYSIS, "21", svc.STATUS_RUNNING))
    seen = iter([
        (None, svc.STATUS_RUNNING, "21"),
        (report, svc.STATUS_REPORTED, "21"),
    ])
    monkeypatch.setattr(CapeCollector, "_read_analysis", lambda self, a: next(seen))

    evidence = _collector()._detonate_and_wait()
    assert evidence.available is True
    assert evidence.report is report
    assert evidence.pending is False


def test_an_unfinished_detonation_is_deferred_not_failed(monkeypatch):
    """The analyst is told a detonation is in flight and that nothing is
    required of them. Reporting this as "no sandbox analysis" reads as an answer
    when it is a wait — which is how the panel looked before."""
    monkeypatch.setattr(CapeCollector, "_start", lambda self, t, c: (ANALYSIS, "21", svc.STATUS_PENDING))
    monkeypatch.setattr(CapeCollector, "_read_analysis",
                        lambda self, a: (None, svc.STATUS_RUNNING, "21"))
    _fake_clock(monkeypatch, [0, 0, 60, 120])

    evidence = _collector()._detonate_and_wait()
    assert evidence.available is False
    assert evidence.pending is True
    assert evidence.pending_analysis_id == ANALYSIS
    assert evidence.pending_task_id == "21"
    assert evidence.pending_since
    assert "task 21" in evidence.reason
    assert "No action needed." in evidence.reason


def test_a_detonation_that_fails_stops_the_wait(monkeypatch):
    monkeypatch.setattr(CapeCollector, "_start", lambda self, t, c: (ANALYSIS, "21", svc.STATUS_RUNNING))
    monkeypatch.setattr(CapeCollector, "_read_analysis",
                        lambda self, a: (None, svc.STATUS_FAILED, "21"))

    evidence = _collector()._detonate_and_wait()
    assert evidence.available is False
    assert evidence.pending is False
    assert "failed" in evidence.reason


def test_a_submission_that_cannot_start_is_a_gap_not_a_crash(monkeypatch):
    def _boom(self, target, context):
        raise RuntimeError("CAPE refused the submission")

    monkeypatch.setattr(CapeCollector, "_start", _boom)
    evidence = _collector()._detonate_and_wait()
    assert evidence.available is False
    assert evidence.pending is False
    assert "Could not start" in evidence.reason


# --- the hand-off to the durable workflow ------------------------------------

def test_a_new_analysis_is_handed_to_the_workflow(monkeypatch):
    """Creating the row is not enough — nothing polls CAPE until the task runs."""
    dispatched: list[str] = []
    _install_fake_db(monkeypatch, created=True, dispatched=dispatched)

    analysis_id, task_id, status = _collector()._start("http://suspicious-example.com", {})
    assert str(analysis_id) == ANALYSIS
    assert dispatched == [ANALYSIS]


def test_an_existing_analysis_is_adopted_not_restarted(monkeypatch):
    """A detonation occupies one of six VMs for minutes. Two investigations of
    the same URL watch one analysis rather than starting a second."""
    dispatched: list[str] = []
    _install_fake_db(monkeypatch, created=False, dispatched=dispatched)

    _collector()._start("http://suspicious-example.com", {})
    assert dispatched == []


def _install_fake_db(monkeypatch, *, created: bool, dispatched: list[str]):
    class _Row:
        id = ANALYSIS
        provider_task_id = None
        status = svc.STATUS_QUEUED

    class _Session:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def commit(self): pass

    monkeypatch.setattr(mod, "Session", _Session)
    monkeypatch.setattr(mod.svc, "get_or_create", lambda db, **kw: (_Row(), created))

    import app.tasks.cape_task as cape_task

    class _Task:
        @staticmethod
        def delay(analysis_id): dispatched.append(analysis_id)

    monkeypatch.setattr(cape_task, "run_cape_analysis", _Task)


# --- the orchestrator: both sandboxes start at the same moment ---------------

def test_cape_is_held_out_of_the_fast_phase_with_anyrun():
    """It used to run as a fast collector, which is why a domain nobody had
    detonated came back empty: the collector could only report what CAPE
    already happened to know, and the analyst then had to press "Detonate URL in
    sandbox" and wait out the whole five minutes again."""
    from app.tasks import investigation_task as it

    assert it.SANDBOX_COLLECTOR_NAMES == frozenset({"hybrid_analysis", "cape"})

    collectors = ["dns", "http", "vt", "cape", "hybrid_analysis"]
    fast = [c for c in collectors if c not in it.SANDBOX_COLLECTOR_NAMES]
    assert fast == ["dns", "http", "vt"]


def test_the_gate_decides_for_both_sandboxes():
    """A manual investigation detonates whatever the reputation looks like, and
    that has to reach CAPE too or the button is still required."""
    from app.services.anyrun_gate import should_detonate

    decision = should_detonate({}, observable_type="domain", manual=True)
    assert decision.run is True
    assert decision.reason == "requested_by_analyst"


def test_a_skipped_gate_is_recorded_against_each_sandbox():
    """A skip recorded only under AnyRun's name leaves the CAPE panel looking
    like a gap rather than a decision."""
    from app.tasks.investigation_task import _build_sandbox_skipped_result

    result = _build_sandbox_skipped_result("already_condemned", collector="cape")
    assert result["collector"] == "cape"
    assert result["meta"]["collector"] == "cape"
    assert result["evidence"]["meta"]["collector"] == "cape"
    assert result["status"] == "skipped"
    assert result["evidence"]["sandbox_skipped"]["reason"] == "already_condemned"
