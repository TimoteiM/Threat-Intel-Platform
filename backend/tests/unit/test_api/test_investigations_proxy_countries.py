import asyncio
import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.api import investigations as investigations_api


def test_proxy_countries_response_does_not_expose_proxy_or_api_secrets(monkeypatch):
    monkeypatch.setattr(
        investigations_api,
        "configured_proxy_profiles",
        lambda: [
            {
                "country": "US",
                "label": "US",
                "configured": "true",
                "local_proxy": "true",
                "anyrun_residential": "true",
                "proxy_url": "http://user:secret@example.test:8080",
                "api_key": "should-not-leak",
            }
        ],
    )

    result = asyncio.run(investigations_api.list_proxy_countries())
    serialized = str(result)

    assert result["items"][0]["country"] == "US"
    assert "proxy_url" not in result["items"][0]
    assert "api_key" not in result["items"][0]
    assert "secret" not in serialized
    assert "should-not-leak" not in serialized
