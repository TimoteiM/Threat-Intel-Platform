"""Run one collector again for an investigation that has already concluded.

Lifted out of the `rerun-collector` endpoint so more than one caller can use
it. The endpoint still runs it on a thread and returns immediately; the sandbox
batch task runs it in a loop, one indicator after another, which is the only
safe way to drive ANY.RUN — the licence permits a single analysis at a time, so
firing several of these at once means all but the first fail on submission.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import redis as redis_lib
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.registry import get_collector
from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import CollectorResult, Evidence, Investigation
from app.services.hybrid_analysis_service import evict_anyrun_cache

logger = logging.getLogger(__name__)

# The ANY.RUN collector is registered under its original vendor name.
ANYRUN_COLLECTOR = "hybrid_analysis"


def evict_sandbox_cache(domain: str, observable_type: str) -> None:
    """Both cache layers have to go, or the re-run returns the stored verdict."""
    indicator_type = "hash" if observable_type in {"hash", "file"} else "url"
    indicator = (
        domain
        if observable_type in {"hash", "file"}
        else (f"https://{domain}" if observable_type == "domain" else domain)
    )
    evict_anyrun_cache(indicator, indicator_type)


def rerun_collector_sync(investigation_id: str, collector_name: str) -> dict[str, Any]:
    """Run the collector, merge its evidence, recompute the report, announce it.

    Blocking, and for the sandbox that means minutes. Never call it on the event
    loop. Returns a summary rather than raising: a batch must survive one
    indicator failing.
    """
    settings = get_settings()
    collector_cls = get_collector(collector_name)
    if not collector_cls:
        return {"investigation_id": investigation_id, "status": "failed", "error": "unknown_collector"}

    try:
        inv_id = uuid.UUID(investigation_id)
    except ValueError:
        return {"investigation_id": investigation_id, "status": "failed", "error": "bad_id"}

    with Session(sync_engine) as db:
        inv_row = db.get(Investigation, inv_id)
        if inv_row is None:
            return {"investigation_id": investigation_id, "status": "failed", "error": "not_found"}
        domain = str(inv_row.domain or "").strip()
        observable_type = str(inv_row.observable_type or "domain").strip()

    if observable_type not in collector_cls.supported_types:
        return {
            "investigation_id": investigation_id,
            "status": "skipped",
            "error": f"unsupported_type:{observable_type}",
        }

    started = datetime.now(timezone.utc)
    try:
        collector = collector_cls(
            domain=domain,
            investigation_id=investigation_id,
            observable_type=observable_type,
            timeout=settings.collector_timeout,
        )
        evidence, meta, _ = collector.run()
        result_evidence = evidence.model_dump(mode="json")
        status = meta.status.value
        error = None
    except Exception as exc:
        logger.exception("rerun %s for %s failed: %s", collector_name, investigation_id, exc)
        result_evidence = {}
        status = "failed"
        error = str(exc)
    finished = datetime.now(timezone.utc)

    try:
        with Session(sync_engine) as db:
            ev_row = db.execute(
                select(Evidence).where(Evidence.investigation_id == inv_id)
            ).scalar_one_or_none()
            if ev_row is not None:
                existing: dict = {}
                if ev_row.evidence_json:
                    existing = (
                        json.loads(ev_row.evidence_json)
                        if isinstance(ev_row.evidence_json, str)
                        else dict(ev_row.evidence_json)
                    )
                existing[collector_name] = result_evidence
                ev_row.evidence_json = existing
                inv_row = db.get(Investigation, inv_id)
                if inv_row:
                    inv_row.updated_at = datetime.now(timezone.utc)

            # collector_results is a separate table from evidence_json, and it
            # is the one anything downstream reads to answer "which collectors
            # ran" — the alert-body indicator reports among them. Writing only
            # the evidence blob left a re-run invisible to every one of them.
            row = db.execute(
                select(CollectorResult).where(
                    CollectorResult.investigation_id == inv_id,
                    CollectorResult.collector_name == collector_name,
                )
            ).scalars().first()
            if row is None:
                row = CollectorResult(
                    investigation_id=inv_id,
                    collector_name=collector_name,
                )
                db.add(row)
            row.status = status
            row.evidence_json = result_evidence
            row.error = error
            row.started_at = started
            row.completed_at = finished
            row.duration_ms = int((finished - started).total_seconds() * 1000)
            db.commit()
    except Exception as exc:
        logger.error("rerun %s: could not persist for %s: %s", collector_name, investigation_id, exc)
        return {"investigation_id": investigation_id, "status": "failed", "error": "persist_failed"}

    recomputed = None
    try:
        from app.tasks.analysis_task import recompute_report_for_existing_investigation

        recomputed = recompute_report_for_existing_investigation(
            investigation_id, reason=f"collector_rerun:{collector_name}"
        )
    except Exception as exc:
        logger.error("rerun %s: report recompute failed for %s: %s", collector_name, investigation_id, exc)

    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        r.publish(
            f"investigation:{investigation_id}",
            json.dumps(
                {
                    "type": "evidence_updated",
                    "investigation_id": investigation_id,
                    "collector": collector_name,
                    "report_recomputed": bool(recomputed),
                    "message": (
                        f"{collector_name} re-run complete — evidence and report updated"
                        if recomputed
                        else f"{collector_name} re-run complete — evidence updated; report recompute failed"
                    ),
                }
            ),
        )
    except Exception:
        pass

    return {
        "investigation_id": investigation_id,
        "collector": collector_name,
        "status": status,
        "report_recomputed": bool(recomputed),
    }
