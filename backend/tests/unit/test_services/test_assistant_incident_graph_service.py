from __future__ import annotations

from app.models.database import AssistantEntry, AssistantSession
from app.services.assistant_incident_graph_service import build_assistant_incident_graph


def test_build_assistant_incident_graph_from_sanitized_tokens() -> None:
    session = AssistantSession(title="Password Spray Alert", mode="incident_correlation")
    session.entries = [
        AssistantEntry(
            entry_index=0,
            entry_label="alert",
            raw_text="",
            sanitized_text="",
            token_map_json={
                "[IP_1]": "185.234.219.41",
                "[EMAIL_1]": "ana.popescu@example.com",
                "[EMAIL_2]": "it.support@example.com",
                "[HOST_1]": "NBI0697",
            },
        )
    ]

    graph = build_assistant_incident_graph(
        session,
        "# Executive Summary\nSuccessful login after repeated failures with mailbox activity.",
    )

    assert graph["summary"]["incident"] == "Password Spray Alert"
    assert graph["summary"]["score"] >= 70
    assert any(node["type"] == "ip" for node in graph["nodes"])
    assert any(node["type"] == "user" for node in graph["nodes"])
    assert any(node["id"] == "success-login" for node in graph["nodes"])
    assert all(edge["from"] and edge["to"] for edge in graph["edges"])
