"""
Deliver a finished alert run to the sender's callback URL.

The body is the same `format=report` list the export endpoint serves, wrapped in
a small envelope so the receiver knows which delivery it is looking at:

    POST <callback_url>
    Content-Type: application/json
    X-Alert-Event: alert.completed | alert.failed
    X-Alert-Run-Id: <run id>
    X-Alert-Signature: sha256=<hmac of the body>   (when ALERT_CALLBACK_SECRET is set)

    { "event", "run_id", "external_ref", "status", "overall_verdict",
      "highest_risk_score", "delivered_at", "documents": [ … ] }

Delivery is retried with exponential backoff; every attempt is recorded on the
run so an operator can see what happened without reading logs.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import requests
from celery.exceptions import MaxRetriesExceededError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun
from app.services.alert_ingest_service import CallbackUrlError, sign_payload, validate_callback_url
from app.services.alert_investigation_spawn_service import load_outcomes_sync
from app.services.alert_report_export_service import build_documents, investigation_ids_in
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

FAILED_STATUSES = {"failed", "cancelled"}

# First retry after 10s, then doubling.
CALLBACK_BASE_BACKOFF_SECONDS = 10


@celery_app.task(
    bind=True,
    name="tasks.deliver_alert_callback",
    time_limit=180,
    soft_time_limit=150,
    # Retries are driven explicitly below, not by autoretry_for: Celery's own
    # limit would run out before ours and end the task with an unhandled
    # exception, leaving the run recorded as "retrying" for ever.
    max_retries=None,
)
def deliver_alert_callback(self, run_id: str) -> str:
    """POST the run's report list to its callback URL."""
    settings = get_settings()
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError:
        logger.error("Invalid run id for callback: %s", run_id)
        return run_id

    with Session(sync_engine) as db:
        run = db.get(AlertBodyInvestigationRun, parsed_id)
        if not run:
            logger.error("Callback skipped — alert run %s not found", run_id)
            return run_id
        callback_url = str(run.callback_url or "").strip()
        payload = dict(run.result_json or {})
        status = str(run.status or "")
        overall_verdict = run.overall_verdict
        highest_risk_score = run.highest_risk_score
        title = run.title

    if not callback_url:
        return run_id

    try:
        validate_callback_url(callback_url)
    except CallbackUrlError as exc:
        # The URL passed validation at ingest time; if it no longer resolves to an
        # allowed address, refuse rather than deliver.
        _record(parsed_id, status="refused", error=str(exc), attempt=self.request.retries + 1)
        logger.warning("Callback for %s refused: %s", run_id, exc)
        return run_id

    payload.setdefault("run_id", run_id)
    payload.setdefault("title", title)
    outcomes = load_outcomes_sync(investigation_ids_in(payload))
    documents = build_documents(payload, outcomes, shape="report")

    envelope: dict[str, Any] = {
        "event": "alert.failed" if status in FAILED_STATUSES else "alert.completed",
        "run_id": run_id,
        "external_ref": payload.get("external_ref"),
        "status": status,
        "overall_verdict": overall_verdict,
        "highest_risk_score": highest_risk_score,
        "delivered_at": datetime.now(timezone.utc).isoformat(),
        "document_count": len(documents),
        "documents": documents,
    }
    body = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ThreatIntelPlatform-AlertCallback/1.0",
        "X-Alert-Event": envelope["event"],
        "X-Alert-Run-Id": run_id,
    }
    signature = sign_payload(body)
    if signature:
        headers["X-Alert-Signature"] = signature

    attempt = self.request.retries + 1
    try:
        response = requests.post(
            callback_url,
            data=body,
            headers=headers,
            timeout=settings.alert_callback_timeout_seconds,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return _retry_or_give_up(
            self, run_id, parsed_id, error=f"{type(exc).__name__}: {exc}", attempt=attempt
        )

    if 200 <= response.status_code < 300:
        _record(parsed_id, status="delivered", attempt=attempt, http_status=response.status_code)
        logger.info("Callback for %s delivered (HTTP %s, attempt %d)", run_id, response.status_code, attempt)
        return run_id

    error = f"HTTP {response.status_code}: {response.text[:300]}"
    if 400 <= response.status_code < 500:
        # 4xx is the receiver rejecting the payload — retrying changes nothing.
        _record(parsed_id, status="failed", error=error, attempt=attempt, http_status=response.status_code)
        logger.error("Callback for %s failed: %s", run_id, error)
        return run_id

    return _retry_or_give_up(
        self, run_id, parsed_id, error=error, attempt=attempt, http_status=response.status_code
    )


def _retry_or_give_up(
    task,
    run_id: str,
    run_uuid: uuid.UUID,
    *,
    error: str,
    attempt: int,
    http_status: int | None = None,
) -> str:
    """
    Schedule the next delivery attempt, or record a final failure.

    Whatever happens, the run ends up with a terminal `callback.status` — a
    receiver that never comes back must not leave the record saying "retrying"
    for ever, which is exactly what an exhausted Celery retry chain used to do.
    """
    max_retries = int(get_settings().alert_callback_max_retries)
    if attempt > max_retries:
        _record(run_uuid, status="failed", error=error, attempt=attempt, http_status=http_status)
        logger.error("Callback for %s gave up after %d attempt(s): %s", run_id, attempt, error)
        return run_id

    countdown = _backoff_seconds(attempt)
    _record(run_uuid, status="retrying", error=error, attempt=attempt, http_status=http_status)
    try:
        task.retry(countdown=countdown, max_retries=max_retries, exc=requests.HTTPError(error))
    except MaxRetriesExceededError:
        _record(run_uuid, status="failed", error=error, attempt=attempt, http_status=http_status)
        logger.error("Callback for %s gave up after %d attempt(s): %s", run_id, attempt, error)
        return run_id
    return run_id


def _backoff_seconds(attempt: int) -> int:
    """10s, 20s, 40s, 80s, … capped — predictable, unlike jittered backoff."""
    return min(600, CALLBACK_BASE_BACKOFF_SECONDS * (2 ** max(0, attempt - 1)))


def _record(
    run_uuid: uuid.UUID,
    *,
    status: str,
    attempt: int,
    error: str | None = None,
    http_status: int | None = None,
) -> None:
    """Keep the delivery state on the run itself, next to the reports it carries."""
    try:
        with Session(sync_engine) as db:
            run = db.get(AlertBodyInvestigationRun, run_uuid)
            if not run:
                return
            result = dict(run.result_json or {})
            result["callback"] = {
                **(result.get("callback") or {}),
                "url": run.callback_url,
                "status": status,
                "attempts": attempt,
                "http_status": http_status,
                "error": error,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            run.result_json = result
            db.commit()
    except Exception as exc:
        logger.warning("Could not record callback state for %s: %s", run_uuid, exc)
