from types import SimpleNamespace

import app.tasks.investigation_task as investigation_task
from app.tasks.investigation_task import _build_timeout_result, _collector_timeout, _sandbox_collector_timeout


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
