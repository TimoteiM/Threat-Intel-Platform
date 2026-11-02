"""
Watchlist Task — periodic re-investigation of watched domains.

Celery Beat dispatches this task on a schedule (every hour).
It queries watchlist entries that are due for re-check and
launches investigation pipelines for each one.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import Investigation, WatchlistEntry
from app.tasks.celery_app import celery_app
from app.tasks.investigation_task import run_investigation

logger = logging.getLogger(__name__)
settings = get_settings()

INTERVAL_DELTAS = {
    "weekly": timedelta(days=7),
    "biweekly": timedelta(days=14),
    "monthly": timedelta(days=30),
}


def compute_next_check(interval: str, from_time: datetime) -> datetime:
    """Compute the next check time based on interval."""
    delta = INTERVAL_DELTAS.get(interval, timedelta(days=7))
    return from_time + delta


@celery_app.task(
    bind=True,
    name="tasks.watchlist_check",
    time_limit=300,
    soft_time_limit=270,
)
def watchlist_scheduled_check(self) -> str:
    """
    Periodic task: find active watchlist entries due for re-check
    and dispatch investigation pipelines for each one.

    Runs every hour via Celery Beat. Only processes entries where:
    - status == "active"
    - schedule_interval is set (not NULL)
    - next_check_at <= now
    """
    now = datetime.now(timezone.utc)
    dispatched = 0

    with Session(sync_engine) as session:
        due_entries = session.execute(
            select(WatchlistEntry).where(
                WatchlistEntry.status == "active",
                WatchlistEntry.schedule_interval.isnot(None),
                WatchlistEntry.next_check_at <= now,
            )
        ).scalars().all()

        if not due_entries:
            logger.info("[watchlist-check] No entries due for re-check")
            return "no_entries_due"

        logger.info(
            f"[watchlist-check] Found {len(due_entries)} entries due for re-check"
        )

        for entry in due_entries:
            # Create investigation record (sync — same pattern as batch_task.py)
            inv = Investigation(
                domain=entry.domain,
                context=(
                    f"Scheduled watchlist re-investigation ({entry.schedule_interval}). "
                    f"Notes: {entry.notes or 'None'}"
                ),
                state="created",
                max_analyst_iterations=settings.max_analyst_iterations,
            )
            session.add(inv)
            session.flush()

            # Dispatch the investigation pipeline
            run_investigation.delay(
                investigation_id=str(inv.id),
                domain=entry.domain,
                context=inv.context,
            )

            # Update watchlist entry timestamps
            entry.last_checked_at = now
            entry.next_check_at = compute_next_check(
                entry.schedule_interval, now
            )
            dispatched += 1

            logger.info(
                f"[watchlist-check] Dispatched investigation for {entry.domain} "
                f"(next check: {entry.next_check_at.isoformat()})"
            )

        session.commit()

    logger.info(f"[watchlist-check] Dispatched {dispatched} investigations")
    return f"dispatched_{dispatched}"
