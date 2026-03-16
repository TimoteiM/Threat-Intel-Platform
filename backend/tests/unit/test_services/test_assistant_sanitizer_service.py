from app.services import assistant_sanitizer_service as sanitizer


def test_sanitize_entry_replaces_ip_email_sid_and_account_like_values() -> None:
    text = (
        "User admin logged in from 10.20.30.40 with SID "
        "S-1-5-21-1234567890-123456789-123456789-1001 and email admin@example.com"
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "[IP_1]" in result.sanitized_text
    assert "[EMAIL_1]" in result.sanitized_text
    assert "[SID_1]" in result.sanitized_text
    assert "[ACCOUNT_1]" in result.sanitized_text
    assert result.token_map["[IP_1]"] == "10.20.30.40"
    assert result.summary["ips"] == 1
    assert result.summary["emails"] == 1
    assert result.summary["sids"] == 1


def test_sanitize_session_entries_reuses_same_token_for_same_indicator() -> None:
    entries = [
        "Source IP 10.20.30.40 contacted admin@example.com",
        "Destination IP 10.20.30.40 triggered for admin@example.com",
    ]

    results = sanitizer.sanitize_entries(entries)

    assert len(results.entries) == 2
    assert results.entries[0].token_map["[IP_1]"] == "10.20.30.40"
    assert results.entries[1].token_map["[IP_1]"] == "10.20.30.40"
    assert results.entries[0].sanitized_text.count("[IP_1]") == 1
    assert results.entries[1].sanitized_text.count("[IP_1]") == 1
    assert results.summary["ips"] == 1
    assert results.summary["emails"] == 1


def test_sanitize_entry_replaces_host_fields() -> None:
    text = (
        "hostname=wm-c06.siembiot.int computer=FeliciaPopa.Metrorex.local "
        "Suspicious login from host srv-01"
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "wm-c06.siembiot.int" not in result.sanitized_text
    assert "FeliciaPopa.Metrorex.local" not in result.sanitized_text
    assert "srv-01" not in result.sanitized_text
    assert "[HOST_1]" in result.sanitized_text
    assert "[HOST_2]" in result.sanitized_text
    assert "[HOST_3]" in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "wm-c06.siembiot.int"
    assert result.summary["hosts"] == 3


def test_sanitize_entries_fail_closed_on_internal_error() -> None:
    class BadStr(str):
        def replace(self, old: str, new: str, count: int = -1):  # type: ignore[override]
            raise RuntimeError("boom")

    results = sanitizer.sanitize_entries([BadStr("admin@example.com")])

    assert results.entries[0].sanitized_text == "[SANITIZATION_ERROR]"
    assert results.entries[0].token_map == {}
    assert results.summary["errors"] == 1
