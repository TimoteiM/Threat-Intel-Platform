"""Celery task that investigates every indicator found in a pasted alert body."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun
from app.services.alert_body_investigation_service import run_alert_body_investigation
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _load_run(run_uuid: uuid.UUID) -> AlertBodyInvestigationRun | None:
    with Session(sync_engine) as db:
        run = db.get(AlertBodyInvestigationRun, run_uuid)
        if run:
            db.expunge(run)
        return run


def _is_cancelled(run_uuid: uuid.UUID) -> bool:
    with Session(sync_engine) as db:
        run = db.get(AlertBodyInvestigationRun, run_uuid)
        return bool(run and str(run.status or "").lower() == "cancelled")


def _update_run(run_uuid: uuid.UUID, **fields: Any) -> bool:
    with Session(sync_engine) as db:
        run = db.get(AlertBodyInvestigationRun, run_uuid)
        if not run:
            return False
        if str(run.status or "").lower() == "cancelled":
            return False
        for key, value in fields.items():
            setattr(run, key, value)
        db.commit()
        return True


@celery_app.task(
    bind=True,
    name="tasks.run_alert_body_investigation",
    time_limit=1800,
    soft_time_limit=1740,
)
def run_alert_body_investigation_task(
    self,
    run_id: str,
    *,
    requested_collectors: list[str] | None = None,
    max_indicators: int = 30,
    run_ip_lookup: bool = True,
    run_ai: bool = True,
    include_raw_evidence: bool = False,
    reuse_prior_investigations: bool | None = None,
    spawn_investigations: bool | None = None,
) -> str:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError:
        logger.error("Invalid alert-body run_id: %s", run_id)
        return run_id

    run = _load_run(parsed_id)
    if not run:
        logger.error("Alert-body investigation run not found: %s", run_id)
        return run_id
    if str(run.status or "").lower() in TERMINAL_STATUSES:
        logger.info("Alert-body run %s already %s — skipping", run_id, run.status)
        return run_id

    alert_body = run.alert_body
    context = run.context
    title = run.title
    _update_run(parsed_id, status="processing")

    try:
        payload = run_alert_body_investigation(
            alert_body=alert_body,
            run_id=run_id,
            title=title,
            context=context,
            requested_collectors=requested_collectors,
            max_indicators=max_indicators,
            run_ip_lookup=run_ip_lookup,
            run_ai=run_ai,
            include_raw_evidence=include_raw_evidence,
            reuse_prior_investigations=reuse_prior_investigations,
            spawn_investigations=spawn_investigations,
            is_cancelled=lambda: _is_cancelled(parsed_id),
        )
        summary = payload.get("summary") or {}
        # The sender's own reference travels with the run, so their callback and
        # their ticket line up.
        payload["external_ref"] = (run.result_json or {}).get("external_ref")
        # The pipeline builds a fresh payload, so anything recorded at ingest is
        # otherwise lost the moment the run finishes. These say how much of a
        # large log was actually scanned — exactly the facts a reader needs when
        # the body runs to megabytes, and exactly the ones that vanished.
        for carried in (
            "alert_body_chars",
            "analysed_body_chars",
            "alert_body_truncated_for_analysis",
        ):
            if carried in (run.result_json or {}):
                payload[carried] = (run.result_json or {})[carried]
        _update_run(
            parsed_id,
            status="completed",
            indicator_count=int(summary.get("indicators_total") or 0),
            overall_verdict=str(summary.get("overall_verdict") or "inconclusive"),
            highest_risk_score=int(summary.get("highest_risk_score") or 0),
            result_json=payload,
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        logger.exception("Alert-body investigation failed: %s", run_id)
        _update_run(
            parsed_id,
            status="failed",
            result_json={
                "error": f"{type(exc).__name__}: {exc}",
                "external_ref": (run.result_json or {}).get("external_ref"),
            },
            completed_at=datetime.now(timezone.utc),
        )

    _dispatch_callback(parsed_id)
    return run_id


def _dispatch_callback(run_uuid: uuid.UUID) -> None:
    """Hand a finished run to the callback deliverer, when the sender asked for one."""
    try:
        with Session(sync_engine) as db:
            run = db.get(AlertBodyInvestigationRun, run_uuid)
            if not run or not str(run.callback_url or "").strip():
                return
        # Imported here so the alert pipeline does not depend on the HTTP client
        # when nobody registered a callback.
        from app.tasks.alert_callback_task import deliver_alert_callback

        deliver_alert_callback.delay(str(run_uuid))
    except Exception as exc:
        logger.warning("Could not queue callback for alert run %s: %s", run_uuid, exc)
