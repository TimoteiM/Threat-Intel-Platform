"""The hourly job that commissions case narratives has to actually run.

It did not. `tenant_scope` was imported inside `_run`, and used inside
`_pass` — a sibling closure, not nested in it — so every tick raised
`NameError: name 'tenant_scope' is not defined` before correlation started.

Nothing surfaced it. Cases kept forming, because reads compute and store them;
only the *acting* half is this job's, and the only acting the analyst sees is
the case analysis. So the case page said "The case analysis is being written"
for ever, on every case, and had done for weeks: zero narratives were
generated in the seven days before this was found.

The tests that existed asserted the task was registered in the beat schedule
and that its source contained `emit=True`. Both passed throughout. A task that
is scheduled, registered, dispatched and raising on every tick looks identical
to a healthy one from everywhere except its own traceback — so this one runs
it.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.tasks import case_correlation_task as task

NEWEST = datetime(2026, 10, 6, 11, 54, tzinfo=timezone.utc)


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class _Engine:
    async def dispose(self):
        return None


@pytest.fixture
def ran(monkeypatch):
    """Run the real task body, stubbing only what reaches outside it."""
    calls: dict[str, object] = {}

    monkeypatch.setattr(task, "create_async_engine", lambda *a, **k: _Engine())
    monkeypatch.setattr(task, "async_sessionmaker", lambda *a, **k: _Session)

    async def _newest(_db):
        return NEWEST

    monkeypatch.setattr(task, "_newest_alert", _newest)
    monkeypatch.setattr(task, "_read_watermark", lambda: None)
    monkeypatch.setattr(task, "_write_watermark", lambda when: calls.setdefault("watermark", when))

    async def _correlate(db, **kwargs):
        calls["kwargs"] = kwargs
        return {"cases": [{"case_key": "abc"}]}

    import app.services.alert_correlation_service as svc

    monkeypatch.setattr(svc, "correlate_alerts", _correlate)
    return calls


def test_the_hourly_job_runs_without_raising(ran):
    """The regression. It raised NameError here, every hour, for weeks."""
    outcome = task.correlate_and_notify(force=True)

    assert outcome["ran"] is True
    assert outcome["cases"] == 1


def test_it_asks_for_every_tenant_and_tells_correlation_to_act(ran):
    """`emit=True` is what commissions a narrative; without it the job would
    run cleanly and still leave every case analysis unwritten."""
    task.correlate_and_notify(force=True)

    kwargs = ran["kwargs"]
    assert kwargs["emit"] is True
    assert kwargs["scope"].all_tenants is True


def test_it_records_the_watermark_it_accounted_for(ran):
    task.correlate_and_notify(force=True)
    assert ran["watermark"] == NEWEST


def test_an_hour_with_no_new_alerts_is_skipped_not_failed(monkeypatch, ran):
    """The early return is a real behaviour and must stay distinguishable from
    the job falling over — which is exactly the distinction that was lost."""
    monkeypatch.setattr(task, "_read_watermark", lambda: NEWEST)

    outcome = task.correlate_and_notify()

    assert outcome["ran"] is False
    assert outcome["reason"] == "no new alerts"


def test_no_alerts_at_all_is_also_a_clean_skip(monkeypatch, ran):
    async def _none(_db):
        return None

    monkeypatch.setattr(task, "_newest_alert", _none)

    outcome = task.correlate_and_notify(force=True)

    assert outcome == {"ran": False, "reason": "no alerts"}
