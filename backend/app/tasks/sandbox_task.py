"""Detonate a set of indicators an analyst picked out, one at a time.

Sequential on purpose. The licence permits one analysis at a time, so a
parallel fan-out would have every submission after the first rejected — and
each one averages 111 seconds, so a selection of six is roughly eleven minutes
of wall clock. That is why this is a Celery task and not a thread in the API
process: it outlives a request, and it survives an API restart.

After each detonation the originating alert run is refreshed, so the sandbox
verdict shows up on the page the analyst pressed the button on. Without it the
run's stored `indicator_reports` keep the snapshot taken when the run first
finished, and the new evidence is only visible by navigating away to the child
investigation.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun, Investigation
from app.services.alert_body_investigation_service import (
    ALERT_REPORT_SCHEMA_VERSION,
    summarize_indicator_reports,
)
from app.services.alert_investigation_spawn_service import (
    build_investigation_report,
    load_outcomes_sync,
)
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
def run_sandbox_batch(self, investigation_ids: list[str], run_id: str | None = None) -> dict[str, Any]:
    """Run the sandbox against each investigation in turn, refreshing the run."""
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
        outcome = rerun_collector_sync(str(investigation_id), ANYRUN_COLLECTOR)
        results.append(outcome)

        if run_id:
            try:
                refresh_run_report(run_id, str(investigation_id))
            except Exception as exc:  # never lose a detonation to a bookkeeping failure
                logger.warning(
                    "sandbox batch: could not refresh run %s for %s: %s", run_id, investigation_id, exc
                )

    completed = sum(1 for r in results if r.get("status") == "completed")
    logger.info("sandbox batch finished: %s of %s completed", completed, len(results))
    return {"requested": len(investigation_ids), "completed": completed, "results": results}


def refresh_run_report(run_id: str, investigation_id: str) -> bool:
    """Rebuild one indicator report in an alert run from its investigation.

    Uses `build_investigation_report` — the same builder the read-time hydration
    calls — so a sandbox refresh and a normal hydration can never produce two
    different shapes for the same investigation.
    """
    outcomes = load_outcomes_sync([investigation_id])
    outcome = outcomes.get(investigation_id)
    if not outcome:
        return False

    with Session(sync_engine) as db:
        run = db.get(AlertBodyInvestigationRun, uuid.UUID(run_id))
        if run is None:
            return False

        stored = dict(run.result_json or {})
        reports = list(stored.get("indicator_reports") or [])
        changed = False

        for index, report in enumerate(reports):
            if not isinstance(report, dict):
                continue
            ref = report.get("investigation") or report.get("prior_investigation") or {}
            if str(ref.get("investigation_id") or "") != investigation_id:
                continue
            reports[index] = build_investigation_report(
                schema_version=str(report.get("schema_version") or ALERT_REPORT_SCHEMA_VERSION),
                indicator=report.get("indicator") or {},
                observable_type=str((report.get("indicator") or {}).get("observable_type") or "domain"),
                investigation_id=investigation_id,
                outcome=outcome,
                started_at=str(report.get("started_at") or datetime.now(timezone.utc).isoformat()),
                duration_ms=report.get("duration_ms"),
            )
            # So the row can say the sandbox was run deliberately, rather than
            # the analyst having to infer it from a collector chip appearing.
            reports[index]["sandboxed_on_request_at"] = datetime.now(timezone.utc).isoformat()
            changed = True

        if not changed:
            return False

        summary = summarize_indicator_reports(reports)
        ai_report = stored.get("ai_report")
        stored["indicator_reports"] = reports
        stored["reports"] = ([ai_report] if ai_report else []) + reports
        stored["summary"] = {**(stored.get("summary") or {}), **summary}
        run.result_json = stored
        run.overall_verdict = summary.get("overall_verdict") or run.overall_verdict
        run.highest_risk_score = summary.get("highest_risk_score") or run.highest_risk_score
        db.commit()

    logger.info("sandbox batch: refreshed run %s for %s", run_id, investigation_id)
    return True
