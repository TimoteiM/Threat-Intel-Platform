"""Ask again about the addresses whose stored verdict has gone old.

Why this is a task and not a request-time refresh: a case page that triggered
a lookup would make an analyst wait on AbuseIPDB to draw a graph, and would
spend the daily quota in whatever order people happened to open cases. The
reasoning behind what it selects, and the four measurements that got the
justification right on the fourth try, are in `ip_refresh_service`.

Failures are not swallowed and not hidden: `lookup_ip_with_history` stores
NULL for a provider that did not answer, so a refreshed row whose check failed
says so rather than recording a confident zero. The summary below counts those
separately, because "150 refreshed" over 150 failed checks is the shape of a
monitor that reports its own activity as success.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.services.ip_refresh_service import (
    PER_RUN,
    _DUE_SQL,
    due_sql_params,
    select,
)
from app.services.ip_lookup_service import lookup_ip_with_history
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.ip_refresh_task.refresh_stale_ip_lookups")
def refresh_stale_ip_lookups(limit: int = PER_RUN) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with Session(sync_engine) as db:
        rows = db.execute(text(_DUE_SQL), due_sql_params(now)).all()
    picked = select(rows, now=now, limit=limit)

    answered = 0
    unanswered = 0
    for item in picked.due:
        # Never raises; provider errors come back inside the result.
        result = lookup_ip_with_history(item.value)
        if (result.get("abuseipdb") or {}).get("abuse_confidence_score") is None:
            unanswered += 1
        else:
            answered += 1

    summary = {
        "due": picked.total_due,
        "attempted": len(picked.due),
        "answered": answered,
        # A refreshed row that nobody answered is a new timestamp on the same
        # absence. Counted apart so a run of these cannot read as progress.
        "unanswered": unanswered,
        "skipped_for_cap": picked.skipped_for_cap,
        "not_routable": picked.not_routable,
    }
    # No address values and no provider responses: this line goes to the same
    # log as everything else and the lookup payloads carry third-party report
    # text. Counts only.
    logger.info(
        "ip refresh: %d due, %d attempted, %d answered, %d unanswered, "
        "%d left for the next run",
        summary["due"], summary["attempted"], summary["answered"],
        summary["unanswered"], summary["skipped_for_cap"],
    )
    return summary
