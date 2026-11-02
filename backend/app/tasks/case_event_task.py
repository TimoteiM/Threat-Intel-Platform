"""Deliver a correlated-case event to the configured webhook.

    POST <CORRELATION_WEBHOOK_URL>
    Content-Type: application/json
    X-Case-Event: case.escalated | case.opened_high
    X-Case-Key: <case key>
    X-Alert-Signature: sha256=<hmac of the body>   (when ALERT_CALLBACK_SECRET is set)

Two event types rather than one carrying a mode field, because a consumer routes
"got worse" and "arrived bad" differently — one to a queue, one to a page — and
a subscriber that cannot distinguish at subscribe time distinguishes with a
parser, which is where signals get misclassified.

Delivery failure never blocks a recompute. The decision to emit is recorded on
the snapshot before this task is queued, so a webhook that is down loses a
notification, not the record that the crossing happened.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import requests

from app.config import get_settings
from app.services.alert_ingest_service import (
    CallbackUrlError,
    sign_payload,
    validate_callback_url,
)
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="tasks.deliver_case_event",
    time_limit=120,
    soft_time_limit=90,
    max_retries=5,
)
def deliver_case_event(self, payload: dict[str, Any]) -> str:
    """POST one case event. Retried with backoff; gives up quietly."""
    settings = get_settings()
    raw_url = str(settings.correlation_webhook_url or "").strip()
    if not raw_url:
        return "no webhook configured"

    try:
        url = validate_callback_url(raw_url)
    except CallbackUrlError as exc:
        # A misconfigured target is not retryable — retrying would just repeat
        # the same refusal every backoff until the retries run out.
        logger.error("case webhook URL refused: %s", exc)
        return f"refused: {exc}"
    if not url:
        return "no webhook configured"

    body = json.dumps(
        {**payload, "delivered_at": datetime.now(timezone.utc).isoformat()},
        default=str,
    ).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "X-Case-Event": str(payload.get("event") or ""),
        "X-Case-Key": str(payload.get("case_key") or ""),
    }
    signature = sign_payload(body)
    if signature:
        headers["X-Alert-Signature"] = signature

    try:
        response = requests.post(
            url, data=body, headers=headers,
            timeout=settings.alert_callback_timeout_seconds,
        )
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — every failure retries the same way
        countdown = min(300, 10 * (2 ** self.request.retries))
        try:
            raise self.retry(exc=exc, countdown=countdown)
        except self.MaxRetriesExceededError:
            logger.error(
                "gave up delivering %s for case %s: %s",
                payload.get("event"), str(payload.get("case_key"))[:12], exc,
            )
            return "gave up"

    logger.info(
        "delivered %s for case %s (%s)",
        payload.get("event"), str(payload.get("case_key"))[:12], response.status_code,
    )
    return "delivered"


def dispatch(events: list[dict[str, Any]]) -> int:
    """Queue delivery for events already recorded in the database.

    Called after the recompute has committed, so a receiver that reacts
    instantly cannot beat the record it is reacting to. Broker failures are
    logged and swallowed: a page load must not fail because Redis is down.
    """
    if not events or not str(get_settings().correlation_webhook_url or "").strip():
        return 0
    queued = 0
    for event in events:
        try:
            deliver_case_event.delay(event)
            queued += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "could not queue %s for case %s: %s",
                event.get("event"), str(event.get("case_key"))[:12], exc,
            )
    return queued
