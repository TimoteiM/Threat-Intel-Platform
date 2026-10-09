"""Alarm when the analysis pipeline stops producing verdicts.

Written after a stall that ran 2h38m with no signal but a person looking at a
screen. Migration 055 renamed a column, `api` was rebuilt, `worker` and `beat`
were not, and the worker died with `UndefinedColumnError` on every analysis
task. Alerts accumulated in `queued`, which looks identical to a quiet estate.

Two tasks, because the outage had two separable faults and each deserves its
own alarm:

  `watch_pipeline`  the symptom. Alerts waiting AND nothing completing.
  `watch_schema`    the cause. This container's code expecting columns the
                    database does not have, which is a half-finished deploy.

The schema check also runs once at worker start, because that is the moment
the fault is created and the cheapest moment to notice it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _pipeline() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.pipeline_health_service import check

    async with AsyncSessionLocal() as db:
        return (await check(db)).as_json()


async def _schema() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.schema_drift_service import check

    async with AsyncSessionLocal() as db:
        return await check(db)


@celery_app.task(name="app.tasks.pipeline_watch_task.watch_pipeline")
def watch_pipeline() -> dict[str, Any]:
    """Queue depth and time since the last verdict.

    Returns the measurement as well as logging it, so the value is visible in
    the task result even when nobody is reading logs — which was the condition
    during the outage.
    """
    try:
        return asyncio.run(_pipeline())
    except Exception as exc:  # a watchdog that dies silently is worse than none
        logger.error("pipeline_watch_failed error=%s", type(exc).__name__)
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}


@celery_app.task(name="app.tasks.pipeline_watch_task.watch_schema")
def watch_schema() -> dict[str, Any]:
    """Whether this container's code matches the database it is talking to."""
    try:
        return asyncio.run(_schema())
    except Exception as exc:
        logger.error("schema_watch_failed error=%s", type(exc).__name__)
        return {"ok": None, "error": f"{type(exc).__name__}: {exc}"}
