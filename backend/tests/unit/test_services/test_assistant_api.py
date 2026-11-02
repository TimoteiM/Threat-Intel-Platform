import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.api.assistant import router


def test_assistant_router_exposes_expected_paths() -> None:
    routes = {(route.path, tuple(sorted(route.methods or []))) for route in router.routes}

    assert ("/api/assistant/sessions", ("POST",)) in routes
    assert ("/api/assistant/sessions", ("GET",)) in routes
    assert ("/api/assistant/metrics/daily", ("GET",)) in routes
    assert ("/api/assistant/sessions/{session_id}", ("GET",)) in routes
    assert ("/api/assistant/sessions/{session_id}/entries", ("POST",)) in routes
    assert ("/api/assistant/sessions/{session_id}/run", ("POST",)) in routes
    assert ("/api/assistant/sessions/{session_id}/export", ("GET",)) in routes
    assert (
        "/api/assistant/sessions/from-investigation/{investigation_id}",
        ("POST",),
    ) in routes


def test_the_graph_repair_path_is_gone() -> None:
    """The incident graph was removed. Its repair ran on *every* session read
    and could rebuild and commit a payload up to 1.8 MB, which is a large part
    of why reading a session got slower as the estate grew."""
    import app.api.assistant as assistant

    assert not hasattr(assistant, "_graph_needs_repair")
    assert not hasattr(assistant, "_repair_stale_incident_graph")


def test_no_module_still_builds_a_graph() -> None:
    import importlib

    for name in (
        "app.services.assistant_service",
        "app.services.alert_body_ai_service",
        "app.services.alert_report_export_service",
    ):
        source = importlib.import_module(name).__file__
        with open(source, encoding="utf-8") as handle:
            assert "incident_graph" not in handle.read(), name
