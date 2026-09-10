"""Detonate a set of indicators an analyst picked out, one at a time.

Sequential on purpose. The licence permits one analysis at a time, so a
parallel fan-out would have every submission after the first rejected — and
each one averages 111 seconds, so a selection of six is roughly eleven minutes
of wall clock. That is why this is a Celery task and not a thread in the API
process: it outlives a request, and it survives an API restart.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import Investigation
from app.services.collector_rerun_service import (
    ANYRUN_COLLECTOR,
    evict_sandbox_cache,
    rerun_collector_sync,
)
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.tasks.sandbox_task.run_sandbox_batch",
    bind=True,
    max_retries=0,
)
def run_sandbox_batch(self, investigation_ids: list[str]) -> dict[str, Any]:
    """Run the sandbox against each investigation in turn."""
    results: list[dict[str, Any]] = []

    for investigation_id in investigation_ids:
        try:
            inv_id = uuid.UUID(str(investigation_id))
        except ValueError:
            results.append({"investigation_id": investigation_id, "status": "failed", "error": "bad_id"})
            continue

        with Session(sync_engine) as db:
            inv = db.get(Investigation, inv_id)
            if inv is None:
                results.append({"investigation_id": investigation_id, "status": "failed", "error": "not_found"})
                continue
            domain = str(inv.domain or "").strip()
            observable_type = str(inv.observable_type or "domain").strip()

        # A cached verdict would come back instantly and teach the analyst
        # nothing they did not already have on the page.
        try:
            evict_sandbox_cache(domain, observable_type)
        except Exception as exc:
            logger.warning("sandbox batch: cache eviction failed for %s: %s", domain, exc)

        logger.info("sandbox batch: detonating %s (%s)", domain, investigation_id)
        results.append(rerun_collector_sync(str(investigation_id), ANYRUN_COLLECTOR))

    completed = sum(1 for r in results if r.get("status") == "completed")
    logger.info("sandbox batch finished: %s of %s completed", completed, len(results))
    return {"requested": len(investigation_ids), "completed": completed, "results": results}
