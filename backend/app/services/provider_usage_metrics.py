"""
Redis-backed provider usage counters for API health visibility.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import redis as redis_lib

from app.config import get_settings

logger = logging.getLogger(__name__)

DAY_TTL_SECONDS = 90 * 24 * 60 * 60
MONTH_TTL_SECONDS = 400 * 24 * 60 * 60


def record_provider_request(provider: str, *, count: int = 1, scope: str | None = None) -> None:
    provider_key = _normalize_provider(provider)
    if not provider_key or count <= 0:
        return

    now = datetime.now(timezone.utc)
    metric_key = _build_metric_key(provider_key, scope)
    day_key = f"api_usage:{metric_key}:day:{now.strftime('%Y-%m-%d')}"
    month_key = f"api_usage:{metric_key}:month:{now.strftime('%Y-%m')}"

    try:
        client = redis_lib.Redis.from_url(get_settings().redis_url)
        with client.pipeline() as pipe:
            pipe.incrby(day_key, count)
            pipe.expire(day_key, DAY_TTL_SECONDS)
            pipe.incrby(month_key, count)
            pipe.expire(month_key, MONTH_TTL_SECONDS)
            pipe.execute()
    except Exception as exc:
        logger.debug("Failed to record provider usage for %s: %s", provider_key, exc)


def get_provider_usage(provider: str, *, scope: str | None = None) -> dict[str, int]:
    provider_key = _normalize_provider(provider)
    if not provider_key:
        return {"requests_today": 0, "requests_this_month": 0}

    now = datetime.now(timezone.utc)
    metric_key = _build_metric_key(provider_key, scope)
    day_key = f"api_usage:{metric_key}:day:{now.strftime('%Y-%m-%d')}"
    month_key = f"api_usage:{metric_key}:month:{now.strftime('%Y-%m')}"

    try:
        client = redis_lib.Redis.from_url(get_settings().redis_url)
        today_raw, month_raw = client.mget(day_key, month_key)
        return {
            "requests_today": _safe_int(today_raw),
            "requests_this_month": _safe_int(month_raw),
        }
    except Exception as exc:
        logger.debug("Failed to fetch provider usage for %s: %s", provider_key, exc)
        return {"requests_today": 0, "requests_this_month": 0}


def _safe_int(value: object) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_provider(provider: str) -> str:
    return str(provider or "").strip().lower().replace(" ", "_")


def _build_metric_key(provider_key: str, scope: str | None) -> str:
    scope_key = _normalize_provider(scope or "")
    if not scope_key:
        return provider_key
    return f"{provider_key}:{scope_key}"
