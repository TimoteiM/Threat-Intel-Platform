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
    from app.db.session import CeleryAsyncSessionLocal as AsyncSessionLocal
    from app.services.pipeline_health_service import check

    async with AsyncSessionLocal() as db:
        return (await check(db)).as_json()


#: The ten-day estate collapse. Declared here rather than derived, because a
#: baseline must not treat it as a normal fortnight — and because the cause is
#: still unknown, so it cannot be identified by any rule the code could apply.
COLLAPSE = (date(2026, 9, 25), date(2026, 10, 5))


async def _freshness_shadow() -> dict[str, Any]:
    from app.db.session import CeleryAsyncSessionLocal as AsyncSessionLocal
    from app.services.emitter_freshness_service import check

    async with AsyncSessionLocal() as db:
        reports = await check(db, excluded_ranges=[COLLAPSE])
        return {k: v.as_json() for k, v in reports.items()}


async def _materialise() -> dict[str, Any]:
    from app.db.session import CeleryAsyncSessionLocal as AsyncSessionLocal
    from app.services.graph_materialisation_service import sweep

    async with AsyncSessionLocal() as db:
        return (await sweep(db)).as_json()


async def _ingest() -> dict[str, Any]:
    from app.db.session import CeleryAsyncSessionLocal as AsyncSessionLocal
    from app.services.ingest_freshness_service import check

    async with AsyncSessionLocal() as db:
        return (await check(db)).as_json()


async def _schema() -> dict[str, Any]:
    from app.db.session import CeleryAsyncSessionLocal as AsyncSessionLocal
    from app.services.schema_drift_service import check

    async with AsyncSessionLocal() as db:
        return await check(db)


#: Returned by every watch task that could not run.
#:
#: Structurally distinguishable from a successful result, because the failure
#: shapes these tasks used to return were not. `{"ran": False, "error": ...}`
#: carries no `materialised`, no `remaining`, no `ok` — so a caller reading
#: `result.get("materialised", 0)` saw 0 done and `result.get("remaining")`
#: None, which reads as "the sweep finished with nothing to do". A drain loop
#: read exactly that on 2026-10-13 and reported success while 36 sweeps an
#: hour were failing, and had been for a month.
#:
#: So the failure now announces itself. `app/services/absence.py` has said how
#: to do this since the first honest-absence work: a value that is not there
#: carries the reason it is not there, in a shape a renderer cannot mistake
#: for a value. Same idea, one layer out.
FAILED = "failed"


def _failure(name: str, exc: BaseException) -> dict[str, Any]:
    """Log the message, not just the type, and return an unmistakable shape.

    A month of bare `RuntimeError` in this log is half the reason the event
    loop fault took a month to surface: the exception text said *which* loop
    conflict it was and only the discarded return value ever carried it.
    """
    logger.error(
        "%s_failed error=%s message=%s", name, type(exc).__name__, exc,
        exc_info=True,
    )
    return {
        FAILED: True,
        "ran": False,
        "error": f"{type(exc).__name__}: {exc}",
        "task": name,
    }


def succeeded(result: Any) -> bool:
    """Whether a watch result is a result at all.

    Every caller should ask this before reading any field. Written here rather
    than left to each caller, because nothing read these results at all — the
    tasks are beat-scheduled and their returns discarded, so the only evidence
    of failure was a log line carrying the exception *type*.

    `ran is False` is treated as failure as well as the explicit marker. That
    is the shape these tasks used to return, and a caller that cannot
    recognise the shape responsible for the incident is not much of a guard.
    """
    if not isinstance(result, dict):
        return False
    if result.get(FAILED):
        return False
    return result.get("ran") is not False


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
        return _failure("pipeline_watch", exc)


@celery_app.task(name="app.tasks.pipeline_watch_task.watch_schema")
def watch_schema() -> dict[str, Any]:
    """Whether this container's code matches the database it is talking to."""
    try:
        return asyncio.run(_schema())
    except Exception as exc:
        return _failure("schema_watch", exc)


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
        return _failure("ingest_watch", exc)


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
        return _failure("graph_materialise_sweep", exc)


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
        return _failure("emitter_freshness_shadow", exc)


@celery_app.task(name="app.tasks.pipeline_watch_task.code_version")
def code_version_task() -> dict[str, Any]:
    """What code the *worker* process is running.

    The API answers this over HTTP at /health. The worker cannot, and it needs
    its own because `--reload` does not cover Celery: the API now reloads on a
    file change and the worker does not, so api-new/worker-old is the live
    skew. That is worse than both being stale — both-stale is at least
    self-consistent, while a skew has two processes writing the same tables
    under different rules.

    Read it the way a live process must always be read: enqueue through the
    broker and take the result. `docker compose exec worker python` spawns a
    new interpreter that re-imports from the mount, so it reports the source
    and never the process — which is how a two-hour staleness stayed invisible
    on 2026-10-12.

        from app.tasks.celery_app import celery_app
        celery_app.send_task("app.tasks.pipeline_watch_task.code_version")

    Two processes are on the same code when `code_fingerprint` matches.
    """
    from app.code_version import code_version

    return code_version()
