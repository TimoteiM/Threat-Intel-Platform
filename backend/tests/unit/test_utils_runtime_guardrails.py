from __future__ import annotations

from app.utils import runtime_guardrails as rg


def test_api_port_report_warns_on_multiple_listeners(monkeypatch):
    monkeypatch.setattr(rg, "_port_owners_windows", lambda port: ["1111", "2222"])
    report = rg.get_api_port_report(8000)
    assert report["warning_count"] == 1
    assert report["listener_pids"] == ["1111", "2222"]


def test_worker_report_detects_mixed_local_and_container(monkeypatch):
    monkeypatch.setattr(
        rg,
        "_inspect_celery_nodes",
        lambda: ["celery@my-laptop", "celery@ad8cc7c340ac"],
    )
    monkeypatch.setattr("socket.gethostname", lambda: "my-laptop")

    report = rg.get_celery_worker_report()
    assert report["node_count"] == 2
    assert report["warning_count"] >= 1
    assert any("mixed local + container" in w.lower() for w in report["warnings"])
