from __future__ import annotations

from app.services.soc_indicator_service import (
    build_soc_indicator_graph,
    indicator_type_for_value,
    normalize_indicator_value,
)


def test_indicator_type_for_sanitized_tokens() -> None:
    assert indicator_type_for_value("185.234.219.41", "[IP_1]") == "ip"
    assert indicator_type_for_value("ana.popescu@example.com", "[EMAIL_1]") == "email"
    assert indicator_type_for_value("DOMAIN\\user", "[ACCOUNT_1]") == "account"
    assert indicator_type_for_value("https://example.com/a", None) == "url"
    assert indicator_type_for_value("a" * 64, None) == "hash"


def test_normalize_indicator_value_keeps_urls_stable() -> None:
    assert normalize_indicator_value("HTTPS://Example.COM/Login?A=1", "url") == "https://example.com/Login?A=1"
    assert normalize_indicator_value("Example.COM", "domain") == "example.com"


def test_build_soc_indicator_graph_links_cases_and_co_observed_indicators() -> None:
    graph = build_soc_indicator_graph(
        [
            {
                "id": "1",
                "type": "ip",
                "value": "185.234.219.41",
                "normalized": "185.234.219.41",
                "source": "assistant",
                "context": "Password Spray Alert",
                "severity": "high",
                "confidence": "medium",
                "occurrences": 1,
                "first_seen": "2026-05-12T10:00:00+00:00",
                "last_seen": "2026-05-12T10:00:00+00:00",
                "assistant_session": {"id": "s1", "title": "Password Spray Alert", "severity": "high", "confidence": "medium"},
                "investigation": None,
            },
            {
                "id": "2",
                "type": "account",
                "value": "ana.popescu@example.com",
                "normalized": "ana.popescu@example.com",
                "source": "assistant",
                "context": "Password Spray Alert",
                "severity": "medium",
                "confidence": "medium",
                "occurrences": 1,
                "first_seen": "2026-05-12T10:00:00+00:00",
                "last_seen": "2026-05-12T10:00:00+00:00",
                "assistant_session": {"id": "s1", "title": "Password Spray Alert", "severity": "high", "confidence": "medium"},
                "investigation": None,
            },
        ],
        limit=50,
    )

    assert graph["summary"]["indicator_nodes"] == 2
    assert graph["summary"]["assistant_cases"] == 1
    assert any(edge["label"] == "contains" for edge in graph["edges"])
    assert any(edge.get("dashed") for edge in graph["edges"])
