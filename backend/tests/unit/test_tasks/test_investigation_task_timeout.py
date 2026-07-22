from types import SimpleNamespace
import time

import app.tasks.investigation_task as investigation_task
from app.tasks.investigation_task import _build_timeout_result, _collector_timeout, _sandbox_collector_timeout
from app.models.enums import CollectorStatus


def test_build_timeout_result_marks_failed_with_error_meta():
    result = _build_timeout_result("urlscan")
    assert result["collector"] == "urlscan"
    assert result["status"] == "failed"
    assert result["meta"]["status"] == "failed"
    assert "timed out" in str(result["meta"]["error"]).lower()
    assert result["evidence"]["meta"]["collector"] == "urlscan"


def test_sandbox_collector_timeout_scales_from_anyrun_retry_budget(monkeypatch):
    fake_settings = SimpleNamespace(
        anyrun_parallel_limit_retries=8,
        anyrun_parallel_backoff_seconds=10,
        anyrun_transient_retries=3,
        anyrun_transient_backoff_seconds=6,
        anyrun_timeout_url_domain_seconds=45,
        anyrun_timeout_file_hash_seconds=90,
    )
    monkeypatch.setattr(investigation_task, "get_settings", lambda: fake_settings)
    assert _sandbox_collector_timeout(20) == 480


def test_collector_timeout_keeps_non_sandbox_collectors_fast():
    assert _collector_timeout("dns", 20) == 20


def test_urlscan_collector_gets_full_analysis_budget(monkeypatch):
    monkeypatch.setattr(
        investigation_task,
        "get_settings",
        lambda: SimpleNamespace(urlscan_analysis_timeout_seconds=75),
    )
    assert _collector_timeout("urlscan", 20) == 95


class _DummyEvidence:
    def __init__(self, collector_name: str, duration_ms: int):
        self.meta = SimpleNamespace(duration_ms=duration_ms)
        self._payload = {"meta": {"collector": collector_name, "duration_ms": duration_ms}}

    def model_dump(self, mode: str = "json"):
        return dict(self._payload)


class _DummyMeta:
    def __init__(self, status: CollectorStatus, duration_ms: int):
        self.status = status
        self.duration_ms = duration_ms

    def model_dump(self, mode: str = "json"):
        return {
            "status": self.status.value,
            "duration_ms": self.duration_ms,
        }


def test_domain_investigation_waits_for_anyrun_completion(monkeypatch):
    original_deadline = investigation_task.ANYRUN_ASYNC_DEADLINE
    monkeypatch.setattr(investigation_task, "ANYRUN_ASYNC_DEADLINE", 0)
    monkeypatch.setattr(investigation_task, "_publish_progress", lambda *args, **kwargs: None)

    class _Collector:
        def __init__(self, *args, **kwargs):
            self.name = kwargs.get("observable_type") == "domain" and "hybrid_analysis" or "dns"
            self.timeout = kwargs.get("timeout", 0)

        def run(self):
            if self.timeout > 20:
                time.sleep(0.05)
                return _DummyEvidence("hybrid_analysis", 50), _DummyMeta(CollectorStatus.COMPLETED, 50), {}
            return _DummyEvidence("dns", 5), _DummyMeta(CollectorStatus.COMPLETED, 5), {}

    def fake_get_collector(name: str):
        class _NamedCollector(_Collector):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.collector_name = name

            def run(self):
                if name == "hybrid_analysis":
                    time.sleep(0.05)
                    return _DummyEvidence(name, 50), _DummyMeta(CollectorStatus.COMPLETED, 50), {}
                return _DummyEvidence(name, 5), _DummyMeta(CollectorStatus.COMPLETED, 5), {}

        return _NamedCollector

    monkeypatch.setattr(investigation_task, "get_collector", fake_get_collector)

    results, statuses, anyrun_bg_future = investigation_task._run_collectors_inline(
        collectors_to_run=["dns", "hybrid_analysis"],
        domain="example.test",
        investigation_id="11111111-1111-1111-1111-111111111111",
        observable_type="domain",
        file_artifact_id=None,
        external_context=None,
        timeout=20,
    )

    monkeypatch.setattr(investigation_task, "ANYRUN_ASYNC_DEADLINE", original_deadline)
    assert anyrun_bg_future is None
    assert statuses["hybrid_analysis"] == "completed"
    assert {r["collector"] for r in results} == {"dns", "hybrid_analysis"}


def test_non_domain_investigation_can_still_defer_anyrun(monkeypatch):
    monkeypatch.setattr(investigation_task, "ANYRUN_ASYNC_DEADLINE", 0)
    monkeypatch.setattr(investigation_task, "_publish_progress", lambda *args, **kwargs: None)

    def fake_get_collector(name: str):
        class _NamedCollector:
            def __init__(self, *args, **kwargs):
                pass

            def run(self):
                if name == "hybrid_analysis":
                    time.sleep(0.05)
                    return _DummyEvidence(name, 50), _DummyMeta(CollectorStatus.COMPLETED, 50), {}
                return _DummyEvidence(name, 5), _DummyMeta(CollectorStatus.COMPLETED, 5), {}

        return _NamedCollector

    monkeypatch.setattr(investigation_task, "get_collector", fake_get_collector)

    results, statuses, anyrun_bg_future = investigation_task._run_collectors_inline(
        collectors_to_run=["dns", "hybrid_analysis"],
        domain="https://example.test/path",
        investigation_id="11111111-1111-1111-1111-111111111111",
        observable_type="url",
        file_artifact_id=None,
        external_context=None,
        timeout=20,
    )

    assert anyrun_bg_future is not None
    assert statuses["hybrid_analysis"] == "deferred"
    assert {r["collector"] for r in results} == {"dns"}
