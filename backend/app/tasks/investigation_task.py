"""
Investigation Task — orchestrates the full investigation pipeline.

Flow:
1. Create investigation record in DB
2. Launch collectors in parallel (Celery chord)
3. On completion, run analysis task (chord callback)
4. Analysis task aggregates evidence + calls Claude + persists results
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

import redis as redis_lib
from celery import chord
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import Investigation
from app.models.enums import InvestigationState
from app.collectors.registry import available_collectors
from app.db.session import sync_engine
from app.tasks.celery_app import celery_app
from app.tasks.collector_task import run_collector
from app.tasks.analysis_task import run_analysis

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(
    bind=True,
    name="tasks.run_investigation",
)
def run_investigation(
    self,
    investigation_id: str,
    domain: str,
    context: str | None = None,
    client_domain: str | None = None,
    investigated_url: str | None = None,
    client_url: str | None = None,
    external_context: dict | None = None,
    requested_collectors: list[str] | None = None,
) -> str:
    """
    Main entry point — starts the full investigation pipeline.

    Called by the API endpoint after creating the investigation record.

    Args:
        investigation_id: UUID of the investigation (already created in DB)
        domain: Target domain to investigate
        context: User-provided notes/ticket reference
        client_domain: Optional client domain for similarity comparison
        investigated_url: Specific URL to screenshot for visual comparison
        client_url: Specific client URL to compare against
        external_context: CTI enrichment data
        requested_collectors: Which collectors to run (default: all)

    Returns:
        investigation_id (for tracking)
    """
    logger.info(f"[{investigation_id}] Starting investigation for {domain}")

    # ── Determine which collectors to run ──
    if requested_collectors:
        # Validate requested collectors exist
        valid = set(available_collectors())
        collectors_to_run = [c for c in requested_collectors if c in valid]
    else:
        collectors_to_run = settings.default_collectors_list

    if not collectors_to_run:
        logger.error(f"[{investigation_id}] No valid collectors requested")
        _update_state(investigation_id, InvestigationState.FAILED)
        return investigation_id

    # ── Update state to gathering ──
    _update_state(investigation_id, InvestigationState.GATHERING)
    _publish_progress(investigation_id, InvestigationState.GATHERING,
                      f"Starting {len(collectors_to_run)} collectors...", 5)

    # ── Build collector chord ──
    # All collectors run in parallel, then analysis runs as the callback
    collector_tasks = [
        run_collector.s(
            domain=domain,
            collector_name=name,
            investigation_id=investigation_id,
            timeout=settings.collector_timeout,
        )
        for name in collectors_to_run
    ]

    callback = run_analysis.s(
        domain=domain,
        investigation_id=investigation_id,
        context=context,
        client_domain=client_domain,
        investigated_url=investigated_url,
        client_url=client_url,
        external_context=external_context,
        max_iterations=settings.max_analyst_iterations,
    )

    # Launch: parallel collectors → aggregate + analyze
    chord(collector_tasks)(callback)

    return investigation_id


def _update_state(investigation_id: str, state: InvestigationState) -> None:
    """Update investigation state in Postgres."""
    try:
        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            if inv:
                inv.state = state.value
                inv.updated_at = datetime.now(timezone.utc)
                session.commit()
    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to update state: {e}")


def _publish_progress(
    investigation_id: str,
    state: InvestigationState,
    message: str,
    percent: int,
) -> None:
    """Push progress event to Redis for SSE streaming."""
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        r.publish(
            f"investigation:{investigation_id}",
            json.dumps({
                "type": "state_change",
                "investigation_id": investigation_id,
                "state": state.value,
                "message": message,
                "percent_complete": percent,
            }),
        )
    except Exception as e:
        logger.warning(f"Failed to publish progress: {e}")
