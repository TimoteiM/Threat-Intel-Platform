"""Alarm when the analysis pipeline stops producing verdicts.

Written after a stall that ran 2h38m with no signal but a person looking at a
screen. Migration 055 renamed a column, `api` was rebuilt, `worker` and `beat`
were not, and the worker died with `UndefinedColumnError` on every analysis
task. Alerts accumulated in `queued`, which looks identical to a quiet estate.

Three tasks, because each fault is separable and each deserves its own alarm:

  `watch_pipeline`  the symptom. Alerts waiting AND nothing completing.
  `watch_schema`    the cause. This container's code expecting columns the
                    database does not have, which is a half-finished deploy.
  `watch_ingest`    the layer above both. Whether each source is still sending
                    at all — the queue is downstream of ingest, so a dead feed
                    produces the same queue as a healthy quiet one. Two of the
                    four largest sources in the estate were silent for 17 and
                    22 days before anyone noticed.

The schema check also runs once at worker start, because that is the moment
the fault is created and the cheapest moment to notice it.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date
from typing import Any

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _pipeline() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.pipeline_health_service import check

    async with AsyncSessionLocal() as db:
        return (await check(db)).as_json()


#: The ten-day estate collapse. Declared here rather than derived, because a
#: baseline must not treat it as a normal fortnight — and because the cause is
#: still unknown, so it cannot be identified by any rule the code could apply.
COLLAPSE = (date(2026, 9, 25), date(2026, 10, 5))


async def _freshness_shadow() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.emitter_freshness_service import check

    async with AsyncSessionLocal() as db:
        reports = await check(db, excluded_ranges=[COLLAPSE])
        return {k: v.as_json() for k, v in reports.items()}


async def _materialise() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.graph_materialisation_service import sweep

    async with AsyncSessionLocal() as db:
        return (await sweep(db)).as_json()


async def _ingest() -> dict[str, Any]:
    from app.db.session import AsyncSessionLocal
    from app.services.ingest_freshness_service import check

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


@celery_app.task(name="app.tasks.pipeline_watch_task.watch_ingest")
def watch_ingest() -> dict[str, Any]:
    """Whether every source that has ever delivered is still delivering.

    Returns the per-source measurement as well as logging it, for the same
    reason the pipeline watchdog does: during the outage this family of bugs
    produced, nobody was reading logs.
    """
    try:
        return asyncio.run(_ingest())
    except Exception as exc:
        logger.error("ingest_watch_failed error=%s", type(exc).__name__)
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}


@celery_app.task(name="app.tasks.pipeline_watch_task.materialise_graphs")
def materialise_graphs() -> dict[str, Any]:
    """Write graph rows for runs that have none.

    The graph tables are a cache whose only writer was a CLI somebody had to
    remember to run. This is what keeps them warm, and `remaining` in the
    result is the backlog.
    """
    try:
        return asyncio.run(_materialise())
    except Exception as exc:
        logger.error("graph_materialise_sweep_failed error=%s", type(exc).__name__)
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}


@celery_app.task(name="app.tasks.pipeline_watch_task.emitter_freshness_shadow")
def emitter_freshness_shadow() -> dict[str, Any]:
    """Volume against each emitter's own baseline — SHADOW, never alarms.

    Computes and logs so a week of output can set the threshold, which is the
    monitor rule applied before shipping rather than after: the first ingest
    alarm passed 21 tests and then reported 2.5 days of silence for a source
    delivering 97 alerts in 12 hours.
    """
    try:
        return asyncio.run(_freshness_shadow())
    except Exception as exc:
        logger.error("emitter_freshness_shadow_failed error=%s", type(exc).__name__)
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}
