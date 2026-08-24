"""
AbuseIPDB requests that survive a spent key.

The free tier allows 1,000 checks a day and answers 429 once that is gone. With
one key configured that is simply the end of AbuseIPDB for the day; every
caller then records "AbuseIPDB unavailable" and the IP goes unchecked.

A second key is a second daily allowance, so the request is retried on it. The
order is fixed rather than rotated: the point is to use the spare when the first
is exhausted, not to spread load across both. That keeps consumption
predictable — one key drains, then the next — which is what a daily quota wants,
unlike ANY.RUN's monthly pool where alternating spreads the spend.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from app.config import get_settings
from app.services.provider_usage_metrics import record_provider_request

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2"

# Statuses that mean "this key is done, try another". 429 is the daily cap;
# 401/403 mean the key is rejected outright, which the next one may not be.
# Anything else is about the request, not the key, so retrying is pointless.
_TRY_NEXT_KEY_STATUSES = frozenset({401, 403, 429})


def configured_abuseipdb_api_keys(settings: Any = None) -> list[str]:
    """Every configured AbuseIPDB key, primary first. Duplicates dropped."""
    settings = settings or get_settings()
    seen: set[str] = set()
    keys: list[str] = []
    for raw in (
        getattr(settings, "abuseipdb_api_key", ""),
        getattr(settings, "abuseipdb_api_key2", ""),
    ):
        key = str(raw or "").strip()
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def abuseipdb_key_scope(api_key: str) -> str:
    for index, configured in enumerate(configured_abuseipdb_api_keys(), start=1):
        if api_key == configured:
            return f"key_{index}"
    return "unknown_key"


def abuseipdb_get(
    endpoint: str,
    *,
    params: dict[str, Any],
    timeout: float = 10.0,
    settings: Any = None,
) -> requests.Response | None:
    """
    GET an AbuseIPDB endpoint, moving to the next key when one is spent.

    Returns the first response that is not a key-exhaustion status, or the last
    response if every key is spent — so the caller still sees a real 429 to
    report rather than a synthetic error. Returns None only when no key is
    configured at all.
    """
    keys = configured_abuseipdb_api_keys(settings)
    if not keys:
        return None

    last_response: requests.Response | None = None
    for api_key in keys:
        scope = abuseipdb_key_scope(api_key)
        # Both counters: a scoped write does not also bump the total, and the
        # cost dashboard reads the total. Recording only the scope would have
        # left AbuseIPDB showing zero spend there while the keys drained.
        record_provider_request("abuseipdb")
        record_provider_request("abuseipdb", scope=scope)
        response = requests.get(
            f"{_BASE_URL}/{endpoint.lstrip('/')}",
            headers={"Key": api_key, "Accept": "application/json"},
            params=params,
            timeout=timeout,
        )
        if response.status_code not in _TRY_NEXT_KEY_STATUSES:
            return response
        last_response = response
        logger.warning(
            "AbuseIPDB %s exhausted or rejected (HTTP %s) — trying the next key",
            scope,
            response.status_code,
        )
    return last_response
