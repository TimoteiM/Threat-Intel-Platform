import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.api.assistant import router
from app.api.assistant import _graph_needs_repair


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


def test_stale_two_node_graph_with_rich_interpretation_needs_repair() -> None:
    class Session:
        report_markdown = """
# Event Interpretation
Multiple sources 93.123.109.214, 45.148.10.62, 221.159.119.6, and 35.216.140.3 targeted /.env.bak.
venus25-vm ens18 entered promiscuous mode. Rule 1002 fired 8945+ times.
"""
        result_json = {
            "incident_graph": {
                "summary": {"interpretation": report_markdown},
                "nodes": [
                    {"id": "alert-unknown", "label": "Unknown problem somewhere in the system."},
                    {"id": "endpoint-smbfront-c31", "label": "smbfront-c31"},
                ],
                "edges": [{"from": "alert-unknown", "to": "endpoint-smbfront-c31", "label": "generated"}],
            }
        }

    assert _graph_needs_repair(Session())


def test_stale_two_node_graph_with_azure_interpretation_needs_repair() -> None:
    class Session:
        report_markdown = """
# Event Interpretation
Azure AD successful OAuth2 login for vanessa.schockaert@oost-vlaanderen.be to Office 365 from 193.190.147.2.
Kerberos service ticket requests and OneDrive SyncEngine managed device access were observed.
"""
        result_json = {
            "incident_graph": {
                "summary": {"interpretation": report_markdown},
                "nodes": [
                    {"id": "alert-process", "label": "process"},
                    {"id": "ip-193-190-147-2", "label": "193.190.147.2"},
                ],
                "edges": [{"from": "alert-process", "to": "ip-193-190-147-2", "label": "generated"}],
            }
        }

    assert _graph_needs_repair(Session())
