from __future__ import annotations

from types import SimpleNamespace

from app.tasks import investigation_task


class _FlakyCollector:
    attempts = 0

    def __init__(self, **kwargs):
        pass

    def run(self):
        _FlakyCollector.attempts += 1
        if _FlakyCollector.attempts < 2:
            meta = SimpleNamespace(
                status=SimpleNamespace(value="failed"),
                model_dump=lambda mode="json": {"status": "failed", "error": "temporary"},
            )
            evidence = SimpleNamespace(model_dump=lambda mode="json": {})
            return evidence, meta, {}
        meta = SimpleNamespace(
            status=SimpleNamespace(value="completed"),
            model_dump=lambda mode="json": {"status": "completed"},
        )
        evidence = SimpleNamespace(model_dump=lambda mode="json": {"ok": True})
        return evidence, meta, {}


class _AlwaysFailCollector:
    def __init__(self, **kwargs):
        pass

    def run(self):
        meta = SimpleNamespace(
            status=SimpleNamespace(value="failed"),
            model_dump=lambda mode="json": {"status": "failed", "error": "still failing"},
        )
        evidence = SimpleNamespace(model_dump=lambda mode="json": {})
        return evidence, meta, {}


def test_run_collector_with_retries_eventually_succeeds(monkeypatch):
    _FlakyCollector.attempts = 0

    monkeypatch.setattr(investigation_task, "get_collector", lambda name: _FlakyCollector)
    monkeypatch.setattr(
        investigation_task,
        "settings",
        SimpleNamespace(collector_retry_attempts=3, collector_retry_backoff_sec=0.0),
    )

    result = investigation_task._run_collector_with_retries(
        collector_name="vt",
        domain="example.com",
        investigation_id="inv-1",
        observable_type="domain",
        file_artifact_id=None,
        timeout=5,
    )

    assert result["status"] == "completed"
    assert result["evidence"]["ok"] is True
    assert _FlakyCollector.attempts == 2


def test_run_collector_with_retries_exhausts_attempts(monkeypatch):
    monkeypatch.setattr(investigation_task, "get_collector", lambda name: _AlwaysFailCollector)
    monkeypatch.setattr(
        investigation_task,
        "settings",
        SimpleNamespace(collector_retry_attempts=2, collector_retry_backoff_sec=0.0),
    )

    result = investigation_task._run_collector_with_retries(
        collector_name="vt",
        domain="example.com",
        investigation_id="inv-2",
        observable_type="domain",
        file_artifact_id=None,
        timeout=5,
    )

    assert result["status"] == "failed"
    assert "still failing" in (result["meta"].get("error") or "")
