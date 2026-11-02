"""
Batch Task — dispatches investigations for a batch of domains.

Creates Investigation DB records for each domain and dispatches
the investigation pipeline for each one.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import Batch, Investigation
from app.tasks.celery_app import celery_app
from app.tasks.investigation_task import run_investigation

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(
    bind=True,
    name="tasks.process_batch",
    time_limit=300,
    soft_time_limit=270,
)
def process_batch(
    self,
    batch_id: str,
    domains: list[str],
    context: str | None = None,
    client_domain: str | None = None,
) -> str:
    """
    Create investigation records and dispatch pipelines for each domain.

    Args:
        batch_id: UUID of the batch
        domains: List of validated domain strings
        context: Shared context for all investigations
        client_domain: Optional client domain for similarity comparison

    Returns:
        batch_id
    """
    logger.info(f"[batch:{batch_id}] Processing {len(domains)} domains")

    bid = uuid.UUID(batch_id)

    # Create investigation records in DB
    investigation_ids = []
    with Session(sync_engine) as session:
        # Update batch status
        batch = session.get(Batch, bid)
        if batch:
            batch.status = "processing"

        for domain in domains:
            inv = Investigation(
                domain=domain,
                context=context,
                client_domain=client_domain,
                state="created",
                batch_id=bid,
                max_analyst_iterations=settings.max_analyst_iterations,
            )
            session.add(inv)
            session.flush()
            investigation_ids.append(str(inv.id))

        session.commit()

    # Dispatch investigation tasks
    for inv_id, domain in zip(investigation_ids, domains):
        run_investigation.delay(
            investigation_id=inv_id,
            domain=domain,
            context=context,
            client_domain=client_domain,
        )

    logger.info(f"[batch:{batch_id}] Dispatched {len(investigation_ids)} investigations")
    return batch_id
