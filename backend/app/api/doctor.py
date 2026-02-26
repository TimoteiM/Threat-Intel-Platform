from __future__ import annotations

from sqlalchemy import text

from fastapi import APIRouter
import redis

from app.config import get_settings
from app.dependencies import DBSession
from app.utils.runtime_guardrails import build_runtime_guardrail_report

router = APIRouter(prefix="/api/doctor", tags=["doctor"])


@router.get("")
async def doctor(session: DBSession) -> dict:
    settings = get_settings()
    checks: dict[str, dict] = {}

    # Database
    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception as exc:
        checks["database"] = {"ok": False, "error": str(exc)}

    # Broker/cache (Valkey/Redis-compatible)
    try:
        client = redis.Redis.from_url(settings.redis_url)
        client.ping()
        checks["redis"] = {"ok": True, "url": settings.redis_url}
    except Exception as exc:
        checks["redis"] = {"ok": False, "error": str(exc), "url": settings.redis_url}

    checks["api_keys"] = {
        "virustotal": bool(settings.virustotal_api_key),
        "anthropic": bool(settings.anthropic_api_key),
    }
    checks["runtime_guardrails"] = build_runtime_guardrail_report()

    all_ok = all(c.get("ok", True) for c in checks.values() if isinstance(c, dict))
    return {
        "ok": all_ok,
        "checks": checks,
    }
