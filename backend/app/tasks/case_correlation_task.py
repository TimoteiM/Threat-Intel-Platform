"""Correlating cases on a schedule, instead of on every page load.

`correlate_alerts` does two things: it works out which alerts belong together,
and it acts on the answer — firing case webhooks and commissioning an AI
narrative for every case whose shape changed. The first is cheap and idempotent.
The second costs a model call.

Both used to happen on the read path, so opening an alert ran correlation over
the window and could queue narratives for any case that had moved since the last
time anybody looked. On a busy estate that is a model call per page view, and a
lot of concurrent workers, for work nobody asked for.

Now reads compute and store; this job acts. Hourly, and only when alerts have
actually arrived since the last pass — an hour in which nothing was ingested
cannot have changed any case, so correlating again would spend the query to
re-derive an identical answer.

The watermark is the newest alert event time this job has already accounted
for, kept in Redis beside the other operational counters. Losing it is safe in
the direction that matters: an unknown watermark runs the pass.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.models.database import AlertBodyInvestigationRun
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

_WATERMARK_KEY = "tip:correlation:watermark"


def _redis():
    import redis as redis_lib

    return redis_lib.from_url(get_settings().redis_url, decode_responses=True)


def _read_watermark() -> datetime | None:
    try:
        raw = _redis().get(_WATERMARK_KEY)
    except Exception as exc:  # noqa: BLE001 — an unreadable watermark runs the pass
        logger.info("Correlation watermark unreadable (%s); running anyway", exc)
        return None
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _write_watermark(value: datetime) -> None:
    try:
        _redis().set(_WATERMARK_KEY, value.isoformat())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not store the correlation watermark: %s", exc)


async def _newest_alert(db) -> datetime | None:
    return (
        await db.execute(
            select(func.max(AlertBodyInvestigationRun.created_at))
        )
    ).scalar()


@celery_app.task(name="app.tasks.case_correlation_task.correlate_and_notify")
def correlate_and_notify(hours: int | None = None, force: bool = False) -> dict[str, Any]:
    """Run correlation for real: group, merge, and act on what changed.

    `force` runs regardless of the watermark, for an operator who wants a pass
    now.
    """
    import asyncio

    settings = get_settings()
    window = int(hours or getattr(settings, "correlation_window_hours", 48))

    async def _run() -> dict[str, Any]:
        from app.services.alert_correlation_service import correlate_alerts

        # A dedicated, unpooled engine per invocation, for the reason the two
        # neighbouring tasks already carry: Celery runs each task in a worker
        # thread and `asyncio.run` builds a fresh event loop every time, so the
        # app-wide pooled engine hands the new loop asyncpg connections bound to
        # the previous one. The first beat tick works and the second raises
        # "attached to a different loop" — which is exactly what it did.
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        try:
            return await _pass(factory, correlate_alerts, window, force)
        finally:
            # Must be awaited on the loop that opened the connections.
            await engine.dispose()

    async def _pass(factory, correlate_alerts, window: int, force: bool) -> dict[str, Any]:
        async with factory() as db:
            newest = await _newest_alert(db)
            if newest is None:
                return {"ran": False, "reason": "no alerts"}

            watermark = _read_watermark()
            if not force and watermark is not None and newest <= watermark:
                # Nothing has been ingested since the last pass, so no case can
                # have changed. Re-deriving the same answer costs a scan of the
                # window for nothing.
                return {"ran": False, "reason": "no new alerts", "watermark": watermark.isoformat()}

            result = await correlate_alerts(db, hours=window, limit=500, emit=True)
            _write_watermark(newest)
            return {
                "ran": True,
                "cases": len(result.get("cases") or []),
                "window_hours": window,
                "watermark": newest.isoformat(),
            }

    outcome = asyncio.run(_run())
    if outcome.get("ran"):
        logger.info(
            "Scheduled correlation: %s case(s) over %sh, watermark %s",
            outcome["cases"], outcome["window_hours"], outcome["watermark"],
        )
    else:
        logger.debug("Scheduled correlation skipped: %s", outcome.get("reason"))
    return outcome
