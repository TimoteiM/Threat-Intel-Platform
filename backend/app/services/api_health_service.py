"""
External API health and quota normalization service.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable

import requests

from app.config import get_settings
from app.models.schemas import APIHealthResponse, APIProviderHealth
from app.services.provider_usage_metrics import get_provider_usage

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_SECONDS = 60
LOW_QUOTA_THRESHOLDS = {
    "virustotal": 50,
    "abuseipdb": 50,
    "urlscan": 25,
}
_CACHE: dict[str, tuple[float, APIProviderHealth]] = {}


def get_api_health_snapshot(*, force_refresh: bool = False) -> APIHealthResponse:
    settings = get_settings()
    anyrun_keys = _configured_anyrun_api_keys(settings)
    providers = [
        _get_cached_or_probe("virustotal", _probe_virustotal, force_refresh=force_refresh),
        _get_cached_or_probe("abuseipdb", _probe_abuseipdb, force_refresh=force_refresh),
        _get_cached_or_probe("urlscan", _probe_urlscan, force_refresh=force_refresh),
        _configured_provider(
            "opencti",
            "OpenCTI",
            configured=bool((settings.opencti_api_key or "").strip() and (settings.opencti_api_url or "").strip()),
            missing_hint=_missing_required_parts(
                api_key=(settings.opencti_api_key or "").strip(),
                api_url=(settings.opencti_api_url or "").strip(),
            ),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "hybrid_analysis",
            "Hybrid Analysis",
            configured=bool((settings.hybrid_analysis_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "brave_search",
            "Brave Search",
            configured=bool((settings.brave_search_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "google_safe_browsing",
            "Google Safe Browsing",
            configured=bool((settings.google_safe_browsing_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "phishtank",
            "PhishTank",
            configured=bool((settings.phishtank_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "shodan",
            "Shodan",
            configured=bool((settings.shodan_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "openai",
            "OpenAI",
            configured=bool((settings.openai_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
        _configured_provider(
            "anthropic",
            "Anthropic",
            configured=bool((settings.anthropic_api_key or "").strip()),
            source="configuration",
            settings=settings,
        ),
    ]
    providers[4:4] = _probe_anyrun_providers(settings=settings, configured_keys=anyrun_keys)
    return APIHealthResponse(
        providers=providers,
        generated_at=datetime.now(timezone.utc),
    )


def _get_cached_or_probe(
    provider: str,
    probe: Callable[[], APIProviderHealth],
    *,
    force_refresh: bool,
) -> APIProviderHealth:
    now = time.time()
    if not force_refresh:
        cached = _CACHE.get(provider)
        if cached and cached[0] > now:
            return cached[1]

    result = probe()
    _CACHE[provider] = (now + DEFAULT_CACHE_TTL_SECONDS, result)
    return result


def _probe_virustotal() -> APIProviderHealth:
    settings = get_settings()
    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        return _not_configured("virustotal", "VirusTotal")

    try:
        response = requests.get(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        return _normalize_from_headers(
            provider="virustotal",
            display_name="VirusTotal",
            response=response,
            remaining_keys=("x-apikey-remaining", "x-ratelimit-remaining", "x-rate-limit-remaining"),
            limit_keys=("x-apikey-limit", "x-ratelimit-limit", "x-rate-limit-limit"),
            reset_keys=("x-apikey-reset", "x-ratelimit-reset", "x-rate-limit-reset"),
            unit="requests/day",
            source="response_headers",
        )
    except Exception as exc:
        logger.warning("VirusTotal health probe failed: %s", exc)
        return _unavailable("virustotal", "VirusTotal", str(exc))


def _probe_abuseipdb() -> APIProviderHealth:
    settings = get_settings()
    api_key = (settings.abuseipdb_api_key or "").strip()
    if not api_key:
        return _not_configured("abuseipdb", "AbuseIPDB")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 30},
            timeout=10,
        )
        return _normalize_from_headers(
            provider="abuseipdb",
            display_name="AbuseIPDB",
            response=response,
            remaining_keys=("x-ratelimit-remaining", "ratelimit-remaining"),
            limit_keys=("x-ratelimit-limit", "ratelimit-limit"),
            reset_keys=("x-ratelimit-reset", "ratelimit-reset"),
            unit="credits/day",
            source="response_headers",
        )
    except Exception as exc:
        logger.warning("AbuseIPDB health probe failed: %s", exc)
        return _unavailable("abuseipdb", "AbuseIPDB", str(exc))


def _probe_urlscan() -> APIProviderHealth:
    settings = get_settings()
    api_key = (settings.urlscan_api_key or "").strip()
    if not api_key:
        return _not_configured("urlscan", "URLScan")

    try:
        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": api_key},
            params={"q": "page.domain:example.com", "size": 1},
            timeout=10,
        )
        return _normalize_from_headers(
            provider="urlscan",
            display_name="URLScan",
            response=response,
            remaining_keys=("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining"),
            limit_keys=("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"),
            reset_keys=("x-ratelimit-reset", "ratelimit-reset", "x-rate-limit-reset"),
            unit="requests/minute",
            source="response_headers",
        )
    except Exception as exc:
        logger.warning("URLScan health probe failed: %s", exc)
        return _unavailable("urlscan", "URLScan", str(exc))


def _probe_anyrun_providers(*, settings: Any, configured_keys: list[str]) -> list[APIProviderHealth]:
    if not configured_keys:
        return [_not_configured("anyrun", "AnyRun")]

    checked_at = datetime.now(timezone.utc)
    detail_entries: list[APIProviderHealth] = []

    for index, api_key in enumerate(configured_keys, start=1):
        scope = f"key_{index}"
        usage = get_provider_usage("anyrun", scope=scope)
        detail_entries.append(
            _probe_anyrun_key(
                api_key=api_key,
                index=index,
                checked_at=checked_at,
                usage=usage,
            )
        )

    return detail_entries


def _probe_anyrun_key(
    *,
    api_key: str,
    index: int,
    checked_at: datetime,
    usage: dict[str, int],
) -> APIProviderHealth:
    label = "Primary" if index == 1 else ("Fallback" if index == 2 else f"Key {index}")
    display_name = f"AnyRun {label}"
    provider = f"anyrun_{label.lower().replace(' ', '_')}"

    try:
        response = requests.get(
            "https://api.any.run/v1/user",
            headers={"Authorization": f"API-Key {api_key}"},
            timeout=10,
        )
    except Exception as exc:
        logger.warning("AnyRun key %s health probe failed: %s", index, exc)
        return APIProviderHealth(
            provider=provider,
            display_name=display_name,
            configured=True,
            status="unavailable",
            unit="requests",
            last_checked_at=checked_at,
            source="provider_user_api",
            requests_today=usage["requests_today"],
            requests_this_month=usage["requests_this_month"],
            limit_period="month",
            error=str(exc),
        )

    if response.status_code == 403:
        return APIProviderHealth(
            provider=provider,
            display_name=display_name,
            configured=True,
            status="unavailable",
            unit="requests",
            last_checked_at=checked_at,
            source="provider_user_api",
            requests_today=usage["requests_today"],
            requests_this_month=usage["requests_this_month"],
            limit_period="month",
            error="Wrong authorization data",
        )

    if response.status_code >= 400:
        return APIProviderHealth(
            provider=provider,
            display_name=display_name,
            configured=True,
            status="unavailable",
            unit="requests",
            last_checked_at=checked_at,
            source="provider_user_api",
            requests_today=usage["requests_today"],
            requests_this_month=usage["requests_this_month"],
            limit_period="month",
            error=f"HTTP {response.status_code}",
        )

    payload = response.json() if hasattr(response, "json") else {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    team_limits = data.get("teamLimits") if isinstance(data, dict) else {}
    team_remaining_limits = team_limits.get("limits") if isinstance(team_limits, dict) else {}
    team_total_limits = team_limits.get("totalLimits") if isinstance(team_limits, dict) else {}
    team_api_remaining = None
    if isinstance(team_remaining_limits, dict):
        team_api_remaining = _as_positive_number(((team_remaining_limits.get("api") or {}).get("month")))
    team_api_total = None
    if isinstance(team_total_limits, dict):
        team_api_total = _as_positive_number(((team_total_limits.get("api") or {}).get("month")))

    limits = data.get("limits") if isinstance(data, dict) else {}
    api_limits = limits.get("api") if isinstance(limits, dict) else {}
    personal_month_limit = _as_positive_number(api_limits.get("month")) if isinstance(api_limits, dict) else None
    team_api_quota = _as_positive_number(team_limits.get("apiQuota")) if isinstance(team_limits, dict) else None

    limit = None
    remaining = None
    threshold = None
    status = "configured"
    error = None

    if team_api_total is not None and team_api_remaining is not None:
        limit = team_api_total
        remaining = team_api_remaining
        threshold = max(limit * 0.1, 1)
        status = "low_quota" if remaining <= threshold else "healthy"
    elif personal_month_limit is not None:
        limit = personal_month_limit
        remaining = max(limit - usage["requests_this_month"], 0)
        threshold = max(limit * 0.1, 1)
        status = "low_quota" if remaining <= threshold else "healthy"
    elif team_api_quota is not None:
        limit = team_api_quota
        remaining = max(limit - usage["requests_this_month"], 0)
        threshold = max(limit * 0.1, 1)
        status = "low_quota" if remaining <= threshold else "healthy"
    else:
        error = "Quota limit was not included in the AnyRun user response."

    return APIProviderHealth(
        provider=provider,
        display_name=display_name,
        configured=True,
        status=status,
        remaining=remaining,
        limit=limit,
        unit="requests",
        low_quota_threshold=threshold,
        last_checked_at=checked_at,
        source="provider_user_api",
        requests_today=usage["requests_today"],
        requests_this_month=usage["requests_this_month"],
        limit_period="month",
        error=error,
    )


def _normalize_from_headers(
    *,
    provider: str,
    display_name: str,
    response: requests.Response,
    remaining_keys: tuple[str, ...],
    limit_keys: tuple[str, ...],
    reset_keys: tuple[str, ...],
    unit: str,
    source: str,
) -> APIProviderHealth:
    headers = getattr(response, "headers", {}) or {}
    remaining = _find_int_header(headers, remaining_keys)
    limit = _find_int_header(headers, limit_keys)
    reset_at = _find_datetime_header(headers, reset_keys)
    checked_at = datetime.now(timezone.utc)
    threshold = LOW_QUOTA_THRESHOLDS.get(provider)
    usage = get_provider_usage(provider)
    status = _status_from_response(
        status_code=getattr(response, "status_code", 0) or 0,
        remaining=remaining,
        configured=True,
        threshold=threshold,
    )
    error = None if status != "unavailable" else f"HTTP {getattr(response, 'status_code', 'unknown')}"

    return APIProviderHealth(
        provider=provider,
        display_name=display_name,
        configured=True,
        status=status,
        remaining=remaining,
        limit=limit,
        unit=unit,
        reset_at=reset_at,
        low_quota_threshold=threshold,
        last_checked_at=checked_at,
        source=source,
        requests_today=usage["requests_today"],
        requests_this_month=usage["requests_this_month"],
        error=error,
    )


def _configured_provider(
    provider: str,
    display_name: str,
    *,
    configured: bool,
    source: str,
    missing_hint: str | None = None,
    configured_unit: str | None = None,
    configured_count: int | None = None,
    settings: Any,
) -> APIProviderHealth:
    checked_at = datetime.now(timezone.utc)
    usage = get_provider_usage(provider)
    monthly_limit = _limit_override(settings, provider, period="month")
    daily_limit = _limit_override(settings, provider, period="day")
    if not configured:
        return APIProviderHealth(
            provider=provider,
            display_name=display_name,
            configured=False,
            status="not_configured",
            last_checked_at=checked_at,
            source=source,
            requests_today=usage["requests_today"],
            requests_this_month=usage["requests_this_month"],
            error=missing_hint,
        )

    remaining = None
    limit = None
    unit = configured_unit
    limit_period = None
    threshold = None
    status = "configured"

    if monthly_limit is not None:
        limit = monthly_limit
        remaining = max(monthly_limit - usage["requests_this_month"], 0)
        unit = "requests"
        limit_period = "month"
        threshold = max(monthly_limit * 0.1, 1)
        status = "low_quota" if remaining <= threshold else "healthy"
    elif daily_limit is not None:
        limit = daily_limit
        remaining = max(daily_limit - usage["requests_today"], 0)
        unit = "requests"
        limit_period = "day"
        threshold = max(daily_limit * 0.1, 1)
        status = "low_quota" if remaining <= threshold else "healthy"
    elif configured_count is not None:
        remaining = configured_count

    return APIProviderHealth(
        provider=provider,
        display_name=display_name,
        configured=True,
        status=status,
        remaining=remaining,
        limit=limit,
        unit=unit,
        low_quota_threshold=threshold,
        last_checked_at=checked_at,
        source="local_usage" if limit_period else source,
        requests_today=usage["requests_today"],
        requests_this_month=usage["requests_this_month"],
        limit_period=limit_period,
        error=None if limit_period else "Quota telemetry not exposed by this integration yet",
    )


def _status_from_response(
    *,
    status_code: int,
    remaining: int | None,
    configured: bool,
    threshold: int | None,
) -> str:
    if not configured:
        return "not_configured"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500 or status_code == 0:
        return "unavailable"
    if remaining is not None and threshold is not None and remaining <= threshold:
        return "low_quota"
    return "healthy"


def _find_int_header(headers: Any, keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = _get_header_case_insensitive(headers, key)
        if value is None:
            continue
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            continue
    return None


def _find_datetime_header(headers: Any, keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        value = _get_header_case_insensitive(headers, key)
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        try:
            timestamp = int(text)
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            continue
    return None


def _get_header_case_insensitive(headers: Any, key: str) -> str | None:
    if isinstance(headers, dict):
        for existing_key, value in headers.items():
            if str(existing_key).lower() == key.lower():
                return str(value)
    return None


def _configured_anyrun_api_keys(settings: Any) -> list[str]:
    keys: list[str] = []
    for raw in (
        getattr(settings, "anyrun_api_key", ""),
        getattr(settings, "anyrun_api_key_fallback", ""),
    ):
        value = str(raw or "").strip()
        if value and value not in keys:
            keys.append(value)
    return keys


def _missing_required_parts(*, api_key: str, api_url: str) -> str | None:
    missing: list[str] = []
    if not api_key:
        missing.append("api_key")
    if not api_url:
        missing.append("api_url")
    if not missing:
        return None
    return f"Missing required configuration: {', '.join(missing)}"


def _limit_override(settings: Any, provider: str, *, period: str) -> float | None:
    provider_key = str(provider or "").strip().lower()
    if period == "month":
        overrides = getattr(settings, "api_health_monthly_limit_overrides_map", {}) or {}
    else:
        overrides = getattr(settings, "api_health_daily_limit_overrides_map", {}) or {}
    value = overrides.get(provider_key)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_positive_number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0:
        return None
    return parsed


def _not_configured(provider: str, display_name: str) -> APIProviderHealth:
    return APIProviderHealth(
        provider=provider,
        display_name=display_name,
        configured=False,
        status="not_configured",
        low_quota_threshold=LOW_QUOTA_THRESHOLDS.get(provider),
        last_checked_at=datetime.now(timezone.utc),
        source="configuration",
    )


def _unavailable(provider: str, display_name: str, error: str) -> APIProviderHealth:
    return APIProviderHealth(
        provider=provider,
        display_name=display_name,
        configured=True,
        status="unavailable",
        low_quota_threshold=LOW_QUOTA_THRESHOLDS.get(provider),
        last_checked_at=datetime.now(timezone.utc),
        source="probe_error",
        error=error,
    )
