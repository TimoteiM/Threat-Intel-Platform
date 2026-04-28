import os
from datetime import datetime, timezone
import importlib.util
import sys
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test-key")

BACKEND_ROOT = Path(__file__).resolve().parents[3]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

APP_PACKAGE_DIR = BACKEND_ROOT / "app"
app_spec = importlib.util.spec_from_file_location(
    "app",
    APP_PACKAGE_DIR / "__init__.py",
    submodule_search_locations=[str(APP_PACKAGE_DIR)],
)
assert app_spec and app_spec.loader
app_module = importlib.util.module_from_spec(app_spec)
sys.modules["app"] = app_module
app_spec.loader.exec_module(app_module)

from app.services import api_health_service as svc


class _Response:
    def __init__(self, *, status_code: int = 200, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.headers = headers or {}


def test_missing_key_returns_not_configured(monkeypatch):
    class _Settings:
        virustotal_api_key = ""
        abuseipdb_api_key = ""
        urlscan_api_key = ""

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    result = svc._probe_virustotal()

    assert result.configured is False
    assert result.status == "not_configured"


def test_header_normalization_marks_low_quota():
    response = _Response(
        headers={
            "X-RateLimit-Remaining": "12",
            "X-RateLimit-Limit": "1000",
            "X-RateLimit-Reset": str(int(datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc).timestamp())),
        }
    )

    result = svc._normalize_from_headers(
        provider="abuseipdb",
        display_name="AbuseIPDB",
        response=response,
        remaining_keys=("x-ratelimit-remaining",),
        limit_keys=("x-ratelimit-limit",),
        reset_keys=("x-ratelimit-reset",),
        unit="credits/day",
        source="response_headers",
    )

    assert result.status == "low_quota"
    assert result.remaining == 12
    assert result.limit == 1000
    assert result.reset_at is not None


def test_http_429_becomes_rate_limited():
    response = _Response(status_code=429, headers={"X-RateLimit-Remaining": "0"})

    result = svc._normalize_from_headers(
        provider="urlscan",
        display_name="URLScan",
        response=response,
        remaining_keys=("x-ratelimit-remaining",),
        limit_keys=("x-ratelimit-limit",),
        reset_keys=("x-ratelimit-reset",),
        unit="requests/minute",
        source="response_headers",
    )

    assert result.status == "rate_limited"


def test_probe_exception_becomes_unavailable(monkeypatch):
    class _Settings:
        virustotal_api_key = "vt-key"
        abuseipdb_api_key = ""
        urlscan_api_key = ""

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    def raise_error(*args, **kwargs):
        raise RuntimeError("socket timeout")

    monkeypatch.setattr(svc.requests, "get", raise_error)

    result = svc._probe_virustotal()

    assert result.status == "unavailable"
    assert "socket timeout" in str(result.error)


def test_snapshot_uses_cache_until_forced_refresh(monkeypatch):
    svc._CACHE.clear()
    calls = {"count": 0}

    def fake_probe():
        calls["count"] += 1
        return svc.APIProviderHealth(
            provider="virustotal",
            display_name="VirusTotal",
            configured=True,
            status="healthy",
        )

    first = svc._get_cached_or_probe("virustotal", fake_probe, force_refresh=False)
    second = svc._get_cached_or_probe("virustotal", fake_probe, force_refresh=False)
    third = svc._get_cached_or_probe("virustotal", fake_probe, force_refresh=True)

    assert first.status == "healthy"
    assert second.status == "healthy"
    assert third.status == "healthy"
    assert calls["count"] == 2
