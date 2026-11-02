"""Reading the half of a live alert's window that had not happened yet.

An alert arriving in real time is analysed immediately — waiting ten minutes to
start would be the wrong trade for every alert, including the ones that turn out
to matter. So the first read takes what exists and this task takes the rest.

Two mechanisms, deliberately overlapping:

* **A scheduled task per alert**, dispatched with a countdown that lands just
  after the window closes. This is the one that runs in the normal case.
* **A sweep every minute**, which picks up anything the countdown lost. A Celery
  countdown lives in the broker, so a Redis restart or a worker killed mid-flight
  drops it silently, and "the follow-up usually happens" is not a property worth
  having. The sweep reads the same due-rows the countdown would have.

Both call the same function, and calling it twice is a no-op, because the read
starts from the stored high-water mark and merges on each document's own
`index:id`. That is what makes the pair safe rather than merely redundant.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun, AlertLogContext
from app.services import alert_log_context_store as store
from app.services.alert_log_context_service import collect_for_alert, follow_up_start
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def complete_one(row_id: uuid.UUID) -> dict[str, object]:
    """Read the remainder of one alert's window and fold it in.

    Safe to call at any time, any number of times: if the window has not closed
    yet it reads only as far as the present and stays pending; if it has already
    been read to the end the query covers no time at all and merges nothing.
    """
    with Session(sync_engine) as db:
        row = db.get(AlertLogContext, row_id)
        if row is None:
            return {"row": str(row_id), "status": "missing"}
        if row.status in store.TERMINAL_STATUSES:
            return {"row": str(row_id), "status": row.status, "note": "already finished"}

        run = db.get(AlertBodyInvestigationRun, row.run_id)
        if run is None:
            return {"row": str(row_id), "status": "orphaned"}

        event_time = _aware(run.event_time)
        covered_until = _aware(row.covered_until)
        alert_fields = (run.result_json or {}).get("alert_fields") or {}

        # Start *before* the high-water mark, not at it. A document whose event
        # time fell inside the covered slice can be indexed after that slice was
        # read — measured indexing lag on this cluster is p99 4.2s and up to
        # 15.8s — and a follow-up starting exactly at the mark would step over
        # it for ever. The overlap is re-read and the duplicates merge away on
        # each document's own index:id, so the cost is a few repeated hits.
        settings = get_settings()
        read_from = follow_up_start(
            window_start=_aware(row.window_start),
            covered_until=covered_until,
            overlap_seconds=int(getattr(settings, "alert_log_overlap_seconds", 300)),
        )

        context = collect_for_alert(
            tenant_id=run.tenant_id,
            event_time=event_time,
            entity_host=run.entity_host,
            entity_user=run.entity_user,
            alert_body=run.alert_body,
            alert_fields=alert_fields,
            start_override=read_from,
        )
        before = len(row.logs or [])
        row = store.record_attempt(db, row, context)
        analysis_outcome = _maybe_reanalyse(row, before)
        result = {
            "row": str(row_id),
            "run": str(row.run_id),
            "status": row.status,
            "logs": len(row.logs or []),
            "attempts": int(row.attempts or 0),
            "new_logs": len(row.logs or []) - before,
            "analysis": analysis_outcome,
        }

    logger.info(
        "Alert log follow-up %s: status=%s logs=%s (+%s new) attempt=%s analysis=%s",
        row_id, result["status"], result["logs"], result["new_logs"],
        result["attempts"], result["analysis"],
    )
    return result


def refresh_now(run_id: uuid.UUID) -> dict[str, object]:
    """Read this alert's logs again, up to the present, because an analyst asked.

    Distinct from `complete_one` in two ways, both of which are the point.

    It reads past the window's end. The alert's window is ten minutes either
    side of its event time, so once that has passed the scheduled follow-up has
    nothing left to read and declines — `complete_one` returns "already
    finished" for every terminal row. What the analyst is looking at is exactly
    that case: the window closed, and since then either the host did more
    things or the cluster indexed documents whose event time fell inside the
    window after the window was read.

    And it runs on a terminal row. Reaching past the window is a decision about
    what a case is, so it is never made on a schedule — it happens when
    somebody asks, and it is recorded as having been asked for.

    Everything underneath is the existing follow-up path: the read starts
    before the stored high-water mark and documents merge on their own
    `index:id`, so calling this twice adds nothing and calling it during a
    scheduled follow-up cannot double-count.
    """
    with Session(sync_engine) as db:
        row = (
            db.execute(
                select(AlertLogContext).where(AlertLogContext.run_id == run_id)
            ).scalars().first()
        )
        if row is None:
            return {"run": str(run_id), "status": "missing", "new_logs": 0}

        run = db.get(AlertBodyInvestigationRun, row.run_id)
        if run is None:
            return {"run": str(run_id), "status": "orphaned", "new_logs": 0}

        settings = get_settings()
        now = datetime.now(timezone.utc)
        read_from = follow_up_start(
            window_start=_aware(row.window_start),
            covered_until=_aware(row.covered_until),
            overlap_seconds=int(getattr(settings, "alert_log_overlap_seconds", 300)),
        )
        context = collect_for_alert(
            tenant_id=run.tenant_id,
            event_time=_aware(run.event_time),
            entity_host=run.entity_host,
            entity_user=run.entity_user,
            alert_body=run.alert_body,
            alert_fields=(run.result_json or {}).get("alert_fields") or {},
            start_override=read_from,
            end_override=now,
        )
        before = len(row.logs or [])
        # The scheduled lifecycle, preserved across a manual read.
        #
        # `record_attempt` owns the automatic follow-up's state machine: it
        # counts the attempt, and after `alert_log_followup_max_attempts`
        # failures it marks the row `failed`, which is terminal. That is right
        # for a timer and wrong for a person — an analyst pressing this while
        # the cluster is unreachable would spend the retry budget and leave a
        # row holding 175 good logs permanently failed, with the scheduled
        # follow-up switched off.
        #
        # It also sets `status = "unavailable"` on a failed read, which would
        # relabel a row that has logs as having none.
        #
        # So a manual refresh may improve the row and never degrade it.
        prior = {
            "status": row.status,
            "reason": row.reason,
            "attempts": int(row.attempts or 0),
            "next_attempt_at": row.next_attempt_at,
            "last_error": row.last_error,
            # `record_attempt` advances this from the window's wall-clock
            # coverage rather than from what was read, so a failed read would
            # still move the mark and the next follow-up would begin past a
            # slice nobody has looked at.
            "covered_until": row.covered_until,
        }
        row = store.record_attempt(db, row, context)
        gained = len(row.logs or []) - before
        if context.status in {"unavailable", "failed", "skipped"} and gained <= 0:
            row.status = prior["status"]
            row.reason = prior["reason"]
            row.attempts = prior["attempts"]
            row.next_attempt_at = prior["next_attempt_at"]
            row.last_error = prior["last_error"]
            row.covered_until = prior["covered_until"]

        # After `record_attempt`, which rewrites `sources` from the read.
        reached = context.read_until or now
        # Only advanced when the cluster actually answered. Moving the mark
        # after a failed read would make the next follow-up start past a slice
        # nobody has read.
        if context.status not in {"unavailable", "failed", "skipped"} and (
            _aware(row.covered_until) is None or _aware(row.covered_until) < reached
        ):
            row.covered_until = reached
        sources = dict(row.sources or {})
        sources["manual_refresh"] = {
            "at": now.isoformat(),
            "read_from": read_from.isoformat(),
            # Said plainly, because it is past the alert's own window and the
            # window figures elsewhere on the page still describe the alert.
            "read_until": reached.isoformat(),
            "new_logs": len(row.logs or []) - before,
        }
        row.sources = sources
        db.commit()

        result = {
            "run": str(row.run_id),
            "status": row.status,
            "logs": len(row.logs or []),
            "new_logs": len(row.logs or []) - before,
            "read_until": reached.isoformat(),
            "reason": context.reason,
        }

    logger.info(
        "Alert log manual refresh %s: %s log(s), +%s new, read to %s",
        run_id, result["logs"], result["new_logs"], result["read_until"],
    )
    return result


@celery_app.task(name="app.tasks.alert_log_followup_task.complete_alert_log_context", max_retries=0)
def complete_alert_log_context(row_id: str) -> dict[str, object]:
    """The per-alert follow-up, dispatched with a countdown when the alert is live."""
    try:
        parsed = uuid.UUID(str(row_id))
    except ValueError:
        logger.error("Invalid alert log context id: %s", row_id)
        return {"row": str(row_id), "status": "invalid"}
    try:
        return complete_one(parsed)
    except Exception as exc:  # noqa: BLE001 — a failed follow-up must not retry for ever
        logger.warning("Alert log follow-up %s failed: %s", row_id, exc)
        with Session(sync_engine) as db:
            row = db.get(AlertLogContext, parsed)
            if row is not None and row.status not in store.TERMINAL_STATUSES:
                row.last_error = f"{type(exc).__name__}: {exc}"[:500]
                db.commit()
        return {"row": str(row_id), "status": "error"}


@celery_app.task(name="app.tasks.alert_log_followup_task.sweep_alert_log_context")
def sweep_alert_log_context(limit: int = 50) -> dict[str, object]:
    """Anything still owed a read, whether or not its countdown survived."""
    settings = get_settings()
    if not getattr(settings, "alert_log_context_enabled", True):
        return {"swept": 0, "reason": "disabled"}

    with Session(sync_engine) as db:
        rows = [r.id for r in store.due(db, limit=limit)]

    completed = 0
    for row_id in rows:
        try:
            complete_one(row_id)
            completed += 1
        except Exception as exc:  # noqa: BLE001 — one bad row must not stop the sweep
            logger.warning("Alert log sweep could not complete %s: %s", row_id, exc)
    if rows:
        logger.info("Alert log sweep: %s due, %s completed", len(rows), completed)
    return {"due": len(rows), "completed": completed}


def schedule_followup(row: AlertLogContext) -> str | None:
    """Ask for the remainder of this window once it has closed.

    Returns the Celery task id, or None when nothing is owed. The countdown is
    measured from now to the window's end plus a settling delay, because a log
    written at the last second of the window is not searchable at that second.
    """
    if row is None or row.status in store.TERMINAL_STATUSES:
        return None
    settings = get_settings()
    now = datetime.now(timezone.utc)
    window_end = _aware(row.window_end)
    countdown = max(
        0,
        int((window_end - now).total_seconds()) + int(settings.alert_log_followup_delay_seconds),
    )
    async_result = complete_alert_log_context.apply_async(args=[str(row.id)], countdown=countdown)
    logger.info(
        "Alert log follow-up for run %s scheduled in %ss (window ends %s)",
        row.run_id, countdown, window_end.isoformat(),
    )
    return getattr(async_result, "id", None)


def _maybe_reanalyse(row: AlertLogContext, before: int) -> str:
    """Decide what happens to the analysis now that late logs have landed.

    Default is to leave it and say so. Two reasons, and the second is the one
    that settles it:

    * A model call per completed window is a real cost on a platform that
      ingests thousands of alerts a day, most of which are noise.
    * Re-analysis rewrites the run payload wholesale, and that is exactly how a
      CAPE sandbox report written into an investigation's evidence went missing
      — the second writer replaced what the first had added. Doing that
      automatically to every live alert would be repeating a known failure at
      volume.

    So the late logs are attached, the analysis is marked as not having seen
    them, and an analyst decides. ALERT_LOG_REANALYSE_ON_COMPLETE flips it.
    """
    added = len(row.logs or []) - before
    if added <= 0:
        return "unchanged"
    if not getattr(get_settings(), "alert_log_reanalyse_on_complete", False):
        return "flagged_for_analyst"

    from app.tasks.alert_body_task import run_alert_body_investigation_task

    run_alert_body_investigation_task.delay(str(row.run_id))
    logger.info("Re-analysis queued for run %s after %s late log events", row.run_id, added)
    return "reanalysis_queued"


@celery_app.task(name="app.tasks.alert_log_followup_task.retry_log_context_after_recovery")
def retry_log_context_after_recovery(limit: int = 500) -> dict[str, object]:
    """Put failed and unavailable rows back in the queue after an outage is fixed.

    The case this exists for: the internal CA is installed, and every alert that
    arrived while it was missing is sitting in `unavailable`, some having spent
    all five attempts proving the same thing. Those five attempts say nothing
    about whether the cluster answers now, so they are reset.

    Verifies the connection *first*, with the real configuration. Reopening
    hundreds of rows against a cluster that still cannot be reached would spend
    every one of their retries re-discovering that.
    """
    from app.services import opensearch_client as osc

    settings = get_settings()
    try:
        with osc.OpenSearchClient(settings=settings) as client:
            health = client.ping()
    except Exception as exc:  # noqa: BLE001
        return {
            "reopened": 0,
            "blocked": True,
            "reason": f"The log cluster is still not reachable with the current configuration: "
                      f"{osc.redact(exc)[:200]}",
        }

    with Session(sync_engine) as db:
        rows = store.retryable(db, limit=limit)
        outcome = store.reopen_for_retry(db, rows)

    outcome["blocked"] = False
    outcome["cluster"] = health.get("cluster")
    outcome["examined"] = len(rows)
    logger.info("Log context recovery: %s", outcome)
    return outcome


@celery_app.task(name="app.tasks.alert_log_followup_task.refresh_log_context")
def refresh_log_context(limit: int = 200, run_id: str | None = None) -> dict[str, object]:
    """Re-read stored windows so they carry fields added after they were fetched.

    Retrieval keeps a fixed projection of each document — 1,644 mapped fields is
    far too many to store whole — so a column added to that projection is absent
    from everything already stored. `data.win.system.channel` was added for the
    analyst's System Channel column, and without this every existing alert would
    show a dash in it for ever.

    Replaces rather than merges: the merge keeps the record it already has,
    which is the poorer one here. Bounded, and skips anything still owed a
    follow-up so it cannot race with one.
    """
    settings = get_settings()
    if not getattr(settings, "alert_log_context_enabled", True):
        return {"refreshed": 0, "reason": "disabled"}

    with Session(sync_engine) as db:
        query = select(AlertLogContext).where(AlertLogContext.status.in_(("collected", "empty")))
        if run_id:
            query = query.where(AlertLogContext.run_id == uuid.UUID(str(run_id)))
        rows = [r.id for r in db.execute(query.limit(limit)).scalars().all()]

    refreshed, failed, unchanged = 0, 0, 0
    for row_id in rows:
        try:
            with Session(sync_engine) as db:
                row = db.get(AlertLogContext, row_id)
                run = db.get(AlertBodyInvestigationRun, row.run_id) if row else None
                if row is None or run is None:
                    continue

                context = collect_for_alert(
                    tenant_id=run.tenant_id,
                    event_time=run.event_time,
                    entity_host=run.entity_host,
                    entity_user=run.entity_user,
                    alert_body=run.alert_body,
                    alert_fields=(run.result_json or {}).get("alert_fields") or {},
                )
                if context.status in ("unavailable", "skipped") or not context.logs:
                    unchanged += 1
                    continue

                row.logs = context.logs
                row.truncated = bool(context.truncated)
                row.sources = context.sources or row.sources
                row.updated_at = datetime.now(timezone.utc)
                db.commit()
                refreshed += 1
        except Exception as exc:  # noqa: BLE001 — one bad row must not stop the pass
            logger.warning("Could not refresh log context %s: %s", row_id, exc)
            failed += 1

    logger.info("Log context refresh: %s refreshed, %s unchanged, %s failed", refreshed, unchanged, failed)
    return {"examined": len(rows), "refreshed": refreshed, "unchanged": unchanged, "failed": failed}
