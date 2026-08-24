from __future__ import annotations

from app.tasks import alert_recovery_task as rec


class _Inspector:
    def __init__(self, active=None, reserved=None, scheduled=None):
        self._active = active
        self._reserved = reserved
        self._scheduled = scheduled

    def active(self):
        return self._active

    def reserved(self):
        return self._reserved

    def scheduled(self):
        return self._scheduled


def _control(inspector, ping_result=None):
    class _Control:
        @staticmethod
        def inspect(timeout=None):
            return inspector

        @staticmethod
        def ping(timeout=None):
            return ping_result

    return _Control


def test_live_task_ids_collects_every_bucket(monkeypatch):
    """A reserved or scheduled task is as alive as a running one."""
    inspector = _Inspector(
        active={"w1": [{"id": "running"}]},
        reserved={"w1": [{"id": "reserved"}]},
        scheduled={"w1": [{"request": {"id": "scheduled"}}]},
    )
    monkeypatch.setattr(rec.celery_app, "control", _control(inspector))
    assert rec._live_task_ids() == {"running", "reserved", "scheduled"}


def test_unreachable_workers_return_none_not_empty(monkeypatch):
    """
    None and empty must stay distinct.

    Empty means "nothing is running, stalled runs are safe to re-queue". None
    means "the workers did not answer" — re-queuing on that would run live
    investigations a second time and bill every provider twice.
    """
    class _Boom:
        @staticmethod
        def inspect(timeout=None):
            raise OSError("broker unreachable")

    monkeypatch.setattr(rec.celery_app, "control", _Boom)
    assert rec._live_task_ids() is None


def test_silent_workers_return_none_when_ping_fails(monkeypatch):
    """Every bucket empty *and* no ping reply is 'no workers', not 'all idle'."""
    inspector = _Inspector(active={}, reserved={}, scheduled={})
    monkeypatch.setattr(rec.celery_app, "control", _control(inspector, ping_result=[]))
    assert rec._live_task_ids() is None


def test_idle_workers_report_an_empty_set(monkeypatch):
    """Workers that answer the ping but hold nothing are genuinely idle."""
    inspector = _Inspector(active={}, reserved={}, scheduled={})
    monkeypatch.setattr(
        rec.celery_app, "control", _control(inspector, ping_result=[{"celery@w1": {"ok": "pong"}}])
    )
    assert rec._live_task_ids() == set()


def test_sweep_does_nothing_when_workers_cannot_be_asked(monkeypatch):
    """The sweep must abort rather than guess."""
    monkeypatch.setattr(rec, "_live_task_ids", lambda: None)
    result = rec.recover_stuck_alert_runs()
    assert result["requeued"] == 0
    assert "unreachable" in str(result.get("skipped", ""))
