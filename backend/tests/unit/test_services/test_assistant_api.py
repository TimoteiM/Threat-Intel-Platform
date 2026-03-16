import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.api.assistant import router


def test_assistant_router_exposes_expected_paths() -> None:
    routes = {(route.path, tuple(sorted(route.methods or []))) for route in router.routes}

    assert ("/api/assistant/sessions", ("POST",)) in routes
    assert ("/api/assistant/sessions", ("GET",)) in routes
    assert ("/api/assistant/sessions/{session_id}", ("GET",)) in routes
    assert ("/api/assistant/sessions/{session_id}/entries", ("POST",)) in routes
    assert ("/api/assistant/sessions/{session_id}/run", ("POST",)) in routes
    assert ("/api/assistant/sessions/{session_id}/export", ("GET",)) in routes
    assert (
        "/api/assistant/sessions/from-investigation/{investigation_id}",
        ("POST",),
    ) in routes
