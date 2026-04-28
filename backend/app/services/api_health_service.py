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

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_SECONDS = 60
LOW_QUOTA_THRESHOLDS = {
    "virustotal": 50,
    "abuseipdb": 50,
    "urlscan": 25,
}
_CACHE: dict[str, tuple[float, APIProviderHealth]] = {}


def get_api_health_snapshot(*, force_refresh: bool = False) -> APIHealthResponse:
    providers = [
        _get_cached_or_probe("virustotal", _probe_virustotal, force_refresh=force_refresh),
        _get_cached_or_probe("abuseipdb", _probe_abuseipdb, force_refresh=force_refresh),
        _get_cached_or_probe("urlscan", _probe_urlscan, force_refresh=force_refresh),
    ]
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
        error=error,
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
