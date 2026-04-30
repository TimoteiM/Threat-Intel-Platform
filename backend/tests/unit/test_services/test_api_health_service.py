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
    def __init__(self, *, status_code: int = 200, headers: dict[str, str] | None = None, json_data: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


def test_missing_key_returns_not_configured(monkeypatch):
    class _Settings:
        virustotal_api_key = ""
        abuseipdb_api_key = ""
        urlscan_api_key = ""
        opencti_api_key = ""
        opencti_api_url = ""
        anyrun_api_key = ""
        anyrun_api_key_fallback = ""
        hybrid_analysis_api_key = ""
        brave_search_api_key = ""
        google_safe_browsing_api_key = ""
        phishtank_api_key = ""
        shodan_api_key = ""
        openai_api_key = ""
        anthropic_api_key = ""

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


def test_snapshot_includes_configuration_only_providers(monkeypatch):
    class _Settings:
        virustotal_api_key = ""
        abuseipdb_api_key = ""
        urlscan_api_key = ""
        opencti_api_key = "opencti-key"
        opencti_api_url = "https://opencti.example"
        anyrun_api_key = "anyrun-a"
        anyrun_api_key_fallback = "anyrun-b"
        hybrid_analysis_api_key = "ha-key"
        brave_search_api_key = "brave-key"
        google_safe_browsing_api_key = "gsb-key"
        phishtank_api_key = ""
        shodan_api_key = ""
        openai_api_key = "openai-key"
        anthropic_api_key = "anthropic-key"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(svc, "_probe_virustotal", lambda: svc._not_configured("virustotal", "VirusTotal"))
    monkeypatch.setattr(svc, "_probe_abuseipdb", lambda: svc._not_configured("abuseipdb", "AbuseIPDB"))
    monkeypatch.setattr(svc, "_probe_urlscan", lambda: svc._not_configured("urlscan", "URLScan"))
    monkeypatch.setattr(
        svc,
        "_probe_anyrun_providers",
        lambda **kwargs: [
            svc.APIProviderHealth(
                provider="anyrun_primary",
                display_name="AnyRun Primary",
                configured=True,
                status="healthy",
                remaining=300,
                limit=300,
                unit="requests",
                limit_period="month",
            ),
            svc.APIProviderHealth(
                provider="anyrun_fallback",
                display_name="AnyRun Fallback",
                configured=True,
                status="unavailable",
                unit="requests",
                limit_period="month",
                error="Wrong authorization data",
            ),
        ],
    )

    snapshot = svc.get_api_health_snapshot(force_refresh=True)
    providers = {provider.provider: provider for provider in snapshot.providers}

    assert providers["opencti"].configured is True
    assert providers["opencti"].status == "configured"
    assert providers["anyrun_primary"].configured is True
    assert providers["anyrun_primary"].remaining == 300
    assert providers["anyrun_fallback"].status == "unavailable"
    assert "Wrong authorization data" in str(providers["anyrun_fallback"].error)
    assert providers["hybrid_analysis"].status == "configured"
    assert providers["brave_search"].status == "configured"
    assert providers["google_safe_browsing"].status == "configured"
    assert providers["openai"].status == "configured"
    assert providers["anthropic"].status == "configured"
    assert providers["phishtank"].status == "not_configured"


def test_opencti_partial_configuration_reports_missing_requirement():
    class _Settings:
        api_health_monthly_limit_overrides_map = {}
        api_health_daily_limit_overrides_map = {}

    result = svc._configured_provider(
        "opencti",
        "OpenCTI",
        configured=False,
        source="configuration",
        missing_hint=svc._missing_required_parts(api_key="present", api_url=""),
        settings=_Settings(),
    )

    assert result.status == "not_configured"
    assert "api_url" in str(result.error)


def test_configured_provider_uses_manual_monthly_limit(monkeypatch):
    class _Settings:
        api_health_monthly_limit_overrides_map = {"anyrun": 2000.0}
        api_health_daily_limit_overrides_map = {}

    monkeypatch.setattr(svc, "get_provider_usage", lambda provider: {"requests_today": 17, "requests_this_month": 410})

    result = svc._configured_provider(
        "anyrun",
        "AnyRun",
        configured=True,
        source="configuration",
        configured_unit="api keys",
        configured_count=2,
        settings=_Settings(),
    )

    assert result.status == "healthy"
    assert result.limit == 2000
    assert result.remaining == 1590
    assert result.requests_today == 17
    assert result.requests_this_month == 410
    assert result.limit_period == "month"


def test_probe_anyrun_key_reads_provider_month_limit(monkeypatch):
    monkeypatch.setattr(
        svc.requests,
        "get",
        lambda *args, **kwargs: _Response(
            status_code=200,
            json_data={
                "error": False,
                "data": {
                    "teamLimits": {
                        "limits": {
                            "api": {"month": 1350},
                        },
                        "totalLimits": {
                            "api": {"month": 1500},
                        },
                        "apiQuota": 300,
                    },
                    "limits": {
                        "api": {"month": 300},
                    }
                },
            },
        ),
    )
    monkeypatch.setattr(svc, "get_provider_usage", lambda provider, scope=None: {"requests_today": 7, "requests_this_month": 42})

    result = svc._probe_anyrun_key(
        api_key="key-1",
        index=1,
        checked_at=datetime.now(timezone.utc),
        usage={"requests_today": 7, "requests_this_month": 42},
    )

    assert result.status == "healthy"
    assert result.limit == 1500
    assert result.remaining == 1350
    assert result.requests_this_month == 42


def test_probe_anyrun_key_surfaces_invalid_auth(monkeypatch):
    monkeypatch.setattr(
        svc.requests,
        "get",
        lambda *args, **kwargs: _Response(status_code=403, json_data={"error": True, "message": "Wrong authorization data"}),
    )

    result = svc._probe_anyrun_key(
        api_key="bad-key",
        index=2,
        checked_at=datetime.now(timezone.utc),
        usage={"requests_today": 0, "requests_this_month": 0},
    )

    assert result.status == "unavailable"
    assert "Wrong authorization data" in str(result.error)
