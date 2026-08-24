"""
Re-queue alert runs whose worker died underneath them.

A deploy, an OOM kill or a crash takes the worker down mid-task. Celery leaves
the message unacknowledged, so Redis eventually redelivers it — but only after
the visibility timeout, which must stay above the task's own 30-minute limit to
avoid running a task twice. "Eventually, in up to an hour" is not the same as
"never interrupted": the run sits in `processing`, the caller sees nothing, and
whoever sent the alert has no idea it stalled.

This closes that window. It looks for runs that claim to be in flight, asks the
workers what they are actually executing, and re-queues anything nobody is
working on.

The dangerous mistake here would be re-queuing a run that *is* progressing, so
liveness is established from the workers themselves rather than guessed from
age. If the workers cannot be reached, the sweep does nothing at all — a missed
recovery costs one cycle, a wrong one runs an investigation twice and bills
every provider a second time.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

IN_FLIGHT_STATUSES = ("queued", "processing")

# How long a run must have been in flight before it is considered for recovery.
# Short, because liveness comes from the workers rather than from this number —
# it only avoids racing a run that was dispatched moments ago and has not been
# picked up yet.
MIN_AGE_SECONDS = 180

# A run that keeps dying is a poison message. After this many attempts it is
# failed loudly instead of being re-queued forever.
MAX_RECOVERY_ATTEMPTS = 3


def _live_task_ids() -> set[str] | None:
    """
    Task ids the workers currently hold, or None if they could not be asked.

    None is not an empty set, and the difference matters: empty means "nothing
    is running, everything stalled is safe to re-queue", while None means "no
    idea", and acting on no idea is how a run gets executed twice.
    """
    try:
        # inspect() waits out the full timeout on every call — it cannot know how
        # many workers should answer — and this makes three of them, so the
        # timeout is paid three times. Kept short: the replies are local and this
        # runs every three minutes forever.
        inspector = celery_app.control.inspect(timeout=2)
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}
        scheduled = inspector.scheduled() or {}
    except Exception as exc:
        logger.warning("Could not inspect workers for stuck-run recovery: %s", exc)
        return None

    if not active and not reserved and not scheduled:
        # No worker answered at all — distinct from workers answering "idle".
        if not celery_app.control.ping(timeout=3):
            logger.warning("No Celery worker responded to ping — skipping recovery sweep")
            return None

    live: set[str] = set()
    for bucket in (active, reserved, scheduled):
        for entries in bucket.values():
            for entry in entries or []:
                task_id = (entry or {}).get("id") or ((entry or {}).get("request") or {}).get("id")
                if task_id:
                    live.add(str(task_id))
    return live


@celery_app.task(name="tasks.recover_stuck_alert_runs", time_limit=300)
def recover_stuck_alert_runs() -> dict[str, Any]:
    from app.tasks.alert_body_task import run_alert_body_investigation_task

    live_task_ids = _live_task_ids()
    if live_task_ids is None:
        return {"checked": 0, "requeued": 0, "skipped": "workers unreachable"}

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=MIN_AGE_SECONDS)
    requeued: list[str] = []
    abandoned: list[str] = []

    with Session(sync_engine) as session:
        runs = session.execute(
            select(AlertBodyInvestigationRun).where(
                AlertBodyInvestigationRun.status.in_(IN_FLIGHT_STATUSES),
                AlertBodyInvestigationRun.created_at < cutoff,
            )
        ).scalars().all()

        for run in runs:
            result = run.result_json if isinstance(run.result_json, dict) else {}
            task_id = str(result.get("task_id") or "")
            if task_id and task_id in live_task_ids:
                continue  # genuinely running

            attempts = int(result.get("recovery_attempts") or 0)
            if attempts >= MAX_RECOVERY_ATTEMPTS:
                run.status = "failed"
                run.result_json = {
                    **result,
                    "status": "failed",
                    "error": (
                        f"Abandoned after {attempts} recovery attempts — the run did not "
                        "survive being re-queued."
                    ),
                }
                flag_modified(run, "result_json")
                abandoned.append(str(run.id))
                continue

            options = result.get("dispatch_options") or {}
            try:
                task = run_alert_body_investigation_task.apply_async(
                    args=[str(run.id)],
                    kwargs={
                        "requested_collectors": options.get("requested_collectors"),
                        "max_indicators": options.get("max_indicators", 30),
                        "run_ip_lookup": options.get("run_ip_lookup", True),
                        "run_ai": options.get("run_ai", True),
                        "include_raw_evidence": options.get("include_raw_evidence", False),
                        "reuse_prior_investigations": options.get("reuse_prior_investigations"),
                        "spawn_investigations": options.get("spawn_investigations"),
                    },
                )
            except Exception as exc:
                logger.exception("Failed to re-queue stuck alert run %s: %s", run.id, exc)
                continue

            run.status = "queued"
            run.result_json = {
                **result,
                "task_id": task.id,
                "recovery_attempts": attempts + 1,
                "recovered_at": datetime.now(timezone.utc).isoformat(),
            }
            flag_modified(run, "result_json")
            requeued.append(str(run.id))

        session.commit()

    if requeued or abandoned:
        logger.info(
            "Stuck-run recovery: re-queued %s, abandoned %s", len(requeued), len(abandoned)
        )
    return {
        "checked": len(runs),
        "requeued": len(requeued),
        "abandoned": len(abandoned),
        "requeued_ids": requeued[:20],
    }
