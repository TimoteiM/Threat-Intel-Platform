from app.services import assistant_prompt_service as prompt_service


def test_alert_prompt_uses_sanitized_content_and_required_sections() -> None:
    sanitized_entries = [
        {"entry_label": "alert-1", "sanitized_text": "User [ACCOUNT_1] from [IP_1]"},
    ]
    raw_entries = ["User admin from 10.0.0.1"]

    system, user = prompt_service.build_alert_analysis_prompt(
        title="Suspicious login",
        sanitized_entries=sanitized_entries,
        raw_entries=raw_entries,
    )

    assert "event interpretation" in system.lower()
    assert "executive summary" not in system.lower()
    assert "notable entities" not in system.lower()
    assert "ignore low-value collection metadata" in system.lower()
    assert "error codes" in system.lower()
    assert "[ACCOUNT_1]" in user
    assert "10.0.0.1" not in user
    assert "admin" not in user


def test_alert_prompt_requires_key_indicator_tokens_to_be_preserved() -> None:
    system, _ = prompt_service.build_alert_analysis_prompt(
        title="Proxy connection",
        sanitized_entries=[
            {
                "entry_label": "alert-1",
                "sanitized_text": (
                    "srcip=[IP_1] dstip=[IP_2] user=[ACCOUNT_1] "
                    'policy="SIEMBIOT_REVERSE_PROXY" dstcountry="Romania"'
                ),
            }
        ],
        raw_entries=["srcip=10.0.0.1 dstip=10.0.0.2 user=vhorga"],
    )

    assert "include the exact token names for the key indicators that explain the event" in system.lower()
    assert "especially ip, host, email, and account tokens" in system.lower()


def test_incident_prompt_contains_timeline_iocs_root_cause_sections() -> None:
    system, user = prompt_service.build_incident_correlation_prompt(
        title="Multi-stage incident",
        sanitized_entries=[
            {"entry_label": "event-1", "sanitized_text": "Observed [IP_1]"},
            {"entry_label": "event-2", "sanitized_text": "Observed [EMAIL_1]"},
        ],
        raw_entries=["Observed 10.0.0.1", "Observed admin@example.com"],
    )

    assert "timeline" in system.lower()
    assert "attack chain" in system.lower()
    assert "root cause" in system.lower()
    assert "remediation" in system.lower()
    assert "[IP_1]" in user
    assert "admin@example.com" not in user
