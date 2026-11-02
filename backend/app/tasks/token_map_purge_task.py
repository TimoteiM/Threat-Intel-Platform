"""The backstop sweep for investigation token maps, and the thing that reports it.

A token map is supposed to be purged when its investigation completes. This
deletes the ones that were not, and **says so** — because a map reaching the
24-hour wall-clock ceiling is not housekeeping, it is one of two findings:

* the ceiling is too short for a real investigation, or
* investigations are finishing without purging their map.

Either way somebody should know, and neither is visible from a row count.

The warning is logged *here* rather than in `token_boundary`. That module
handles real hostnames and accounts in every call and imports no logger at
all — a property a test asserts by parsing its AST — so it returns a
`PurgeResult` and the caller surfaces it. The boundary states facts; this
reports them.

This task **reports a heartbeat**, which puts it in `INSTRUMENTED` rather than
`NOT_INSTRUMENTED`. The criterion in `watch_liveness_service` is whether
silence and health are distinguishable, and here they are not: a pass with
nothing due deletes nothing and logs nothing, and no API or report path can
reach the table to notice that rows are accumulating — deliberately, that is
decision C. A task doing work nobody can see is exactly the case where the
only evidence it ran is its own.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.db.session import sanitizer_engine
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.token_map_purge_task.purge_token_maps")
def purge_token_maps() -> dict[str, int | str]:
    """Delete token maps past the ceiling. Hourly.

    Hourly rather than every minute: the ceiling is 24 hours, so a pass that
    is an hour late costs an hour of a map that has already outlived its
    investigation by a day. A pass with nothing due is one indexed read.
    """
    from app.services import token_boundary as tb

    # The sanitizer's own connection. `tip_app` — what the rest of this
    # worker uses — has no privilege on `investigation_token_maps`, so this
    # sweep would get `permission denied` on the application engine. That is
    # the separation working, not a bug to route around.
    with Session(sanitizer_engine()) as db:
        result = tb.purge_expired(db)
        db.commit()

    # Success path only, and after the work — never in a `finally`. A
    # heartbeat that survives the failure it exists to expose is worse than
    # none, because it actively asserts health.
    from app.tasks.pipeline_watch_task import record_heartbeat

    asyncio.run(record_heartbeat(
        "purge_token_maps",
        {"deleted": result.deleted, "reason": result.reason,
         "warned": bool(result.warning)},
    ))

    if result.warning:
        # WARNING, not INFO. Logging at INFO is not reporting — the whole
        # reason this platform now distinguishes the two is a point-in-time
        # refusal that sat at INFO for weeks.
        logger.warning("[token-maps] %s", result.warning)
    elif result.deleted:
        logger.info("[token-maps] purged %s map(s) (%s)", result.deleted, result.reason)

    return {"deleted": result.deleted, "reason": result.reason}
