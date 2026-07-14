from app.services import proxy_profiles


def test_proxy_profile_parsing_and_safe_summary(monkeypatch):
    class _Settings:
        proxy_profiles = "US=http://user:pass@example.test:8080,IN=proxy.example:9000"

    monkeypatch.setattr(proxy_profiles, "get_settings", lambda: _Settings())

    us = proxy_profiles.resolve_proxy_profile("us")
    assert us is not None
    assert us.country == "US"
    assert us.requests_proxies["https"] == "http://user:pass@example.test:8080"
    assert us.playwright_proxy == {
        "server": "http://example.test:8080",
        "username": "user",
        "password": "pass",
    }
    assert us.safe_summary == {"country": "US", "label": "US", "configured": "true"}

    countries = proxy_profiles.configured_proxy_profiles()
    assert countries == [
        {"country": "IN", "label": "IN", "configured": "true", "local_proxy": "true", "anyrun_residential": "true"},
        {"country": "US", "label": "US", "configured": "true", "local_proxy": "true", "anyrun_residential": "true"},
    ]


def test_selected_proxy_summary_reports_unconfigured_country(monkeypatch):
    class _Settings:
        proxy_profiles = ""

    monkeypatch.setattr(proxy_profiles, "get_settings", lambda: _Settings())

    summary = proxy_profiles.selected_proxy_summary({"network_profile": {"proxy_country": "BR"}})

    assert summary == {"country": "BR", "label": "BR", "configured": "false"}
