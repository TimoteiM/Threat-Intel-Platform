"""
Investigation Task — orchestrates the full investigation pipeline.

Flow:
1. Create investigation record in DB
2. Run collectors in parallel via ThreadPoolExecutor (inline, no Celery sub-tasks)
3. Call analysis directly in the same task
4. Analysis aggregates evidence + calls Claude + persists results

NOTE: Collectors run as regular Python threads inside run_investigation — no
Celery chord/group/sub-tasks. This is necessary on Windows with worker_pool="threads"
because Celery chords and group().get() are unreliable (callback never fires,
or get() hangs indefinitely). ThreadPoolExecutor is simpler and 100% reliable.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
import uuid
from datetime import datetime, timezone

import redis as redis_lib
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import Investigation
from app.models.enums import InvestigationState
from app.collectors.registry import available_collectors, get_collector, get_collectors_for_type
from app.db.session import sync_engine
from app.tasks.celery_app import celery_app
from app.tasks.analysis_task import run_analysis

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(
    bind=True,
    name="tasks.run_investigation",
    # Must be high enough to cover all collectors + full analysis
    # (replaces the per-task chord callback — this task runs end-to-end)
    time_limit=660,
    soft_time_limit=600,
)
def run_investigation(
    self,
    investigation_id: str,
    domain: str,
    observable_type: str = "domain",
    context: str | None = None,
    client_domain: str | None = None,
    investigated_url: str | None = None,
    client_url: str | None = None,
    external_context: dict | None = None,
    requested_collectors: list[str] | None = None,
    file_artifact_id: str | None = None,
) -> str:
    """
    Main entry point — starts the full investigation pipeline.

    Called by the API endpoint after creating the investigation record.

    Args:
        investigation_id: UUID of the investigation (already created in DB)
        domain: Observable value (domain, IP, URL, hash, filename)
        observable_type: Type of observable (domain|ip|url|hash|file)
        context: User-provided notes/ticket reference
        client_domain: Optional client domain for similarity comparison
        investigated_url: Specific URL to screenshot for visual comparison
        client_url: Specific client URL to compare against
        external_context: CTI enrichment data
        requested_collectors: Which collectors to run (already filtered by service)
        file_artifact_id: Artifact ID for uploaded file (file type only)

    Returns:
        investigation_id (for tracking)
    """
    logger.info(
        f"[{investigation_id}] Starting investigation for {domain} "
        f"(type={observable_type})"
    )

    # ── Guard: verify investigation exists in DB before doing any work ──
    # Protects against stale re-queued tasks where the investigation row was
    # never committed (race condition from before the commit-before-dispatch fix).
    # Without this check, the task runs for minutes (screenshots, Claude) then fails at persist.
    try:
        with Session(sync_engine) as _check_session:
            if not _check_session.get(Investigation, uuid.UUID(investigation_id)):
                logger.error(
                    f"[{investigation_id}] Investigation not found in DB at task start — "
                    "aborting. (Stale task or commit race condition.)"
                )
                return investigation_id
    except Exception as _check_err:
        logger.error(f"[{investigation_id}] DB existence check failed: {_check_err} — aborting.")
        return investigation_id

    # ── Determine which collectors to run ──
    try:
        supported_for_type = set(get_collectors_for_type(observable_type))

        if requested_collectors:
            # Service already filtered; still validate against registry + type support
            valid = set(available_collectors()) & supported_for_type
            collectors_to_run = [c for c in requested_collectors if c in valid]
        else:
            collectors_to_run = [
                c for c in settings.default_collectors_list if c in supported_for_type
            ]

        if not collectors_to_run:
            logger.error(f"[{investigation_id}] No valid collectors for type={observable_type}")
            _update_state(investigation_id, InvestigationState.FAILED)
            _publish_progress(
                investigation_id,
                InvestigationState.FAILED,
                f"No valid collectors for observable type '{observable_type}'",
                100,
            )
            return investigation_id

        _update_state(investigation_id, InvestigationState.GATHERING)
        collector_statuses = {name: "running" for name in collectors_to_run}
        _publish_progress(
            investigation_id,
            InvestigationState.GATHERING,
            f"Starting {len(collectors_to_run)} collectors...",
            5,
            collectors=collector_statuses,
        )

        safe_results, collector_statuses = _run_collectors_inline(
            collectors_to_run=collectors_to_run,
            domain=domain,
            investigation_id=investigation_id,
            observable_type=observable_type,
            file_artifact_id=file_artifact_id,
            timeout=settings.collector_timeout,
        )

        logger.info(
            f"[{investigation_id}] Collectors complete: "
            f"{len(safe_results)}/{len(collectors_to_run)} succeeded. Starting analysis..."
        )

        _update_state(investigation_id, InvestigationState.EVALUATING)
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            "Collectors complete. Correlating evidence...",
            60,
            collectors=collector_statuses,
        )

        run_analysis(
            safe_results,
            domain=domain,
            investigation_id=investigation_id,
            observable_type=observable_type,
            context=context,
            client_domain=client_domain,
            investigated_url=investigated_url,
            client_url=client_url,
            external_context=external_context,
            max_iterations=settings.max_analyst_iterations,
        )
    except Exception as exc:
        logger.exception(f"[{investigation_id}] Investigation task failed: {exc}")
        _update_state(investigation_id, InvestigationState.FAILED)
        _publish_progress(
            investigation_id,
            InvestigationState.FAILED,
            f"Investigation failed: {type(exc).__name__}",
            100,
        )

    return investigation_id


def _run_collectors_inline(
    collectors_to_run: list[str],
    domain: str,
    investigation_id: str,
    observable_type: str,
    file_artifact_id: str | None,
    timeout: int,
) -> tuple[list[dict], dict[str, str]]:
    """
    Run all collectors in parallel using ThreadPoolExecutor.

    Each collector is instantiated and called directly — no Celery sub-tasks.
    Returns a list of result dicts (same format as run_collector Celery task).
    Failed collectors are logged and excluded from the returned list.
    """
    def _run_one(name: str) -> dict:
        collector_cls = get_collector(name)
        if not collector_cls:
            logger.warning(f"[{investigation_id}] Unknown collector: {name}")
            return {
                "collector": name,
                "status": "failed",
                "evidence": {},
                "meta": {"status": "failed", "error": "Unknown collector"},
                "artifacts": {},
                "duration_ms": None,
            }

        collector = collector_cls(
            domain=domain,
            investigation_id=investigation_id,
            timeout=timeout,
            observable_type=observable_type,
            file_artifact_id=file_artifact_id,
        )

        evidence, meta, raw_artifacts = collector.run()

        return {
            "collector": name,
            "status": meta.status.value,
            "evidence": evidence.model_dump(mode="json"),
            "meta": meta.model_dump(mode="json"),
            "artifacts": {k: v.hex() for k, v in raw_artifacts.items()},
            "duration_ms": meta.duration_ms,
        }

    results: list[dict] = []
    collector_statuses: dict[str, str] = {name: "running" for name in collectors_to_run}
    start_ts = time.monotonic()
    total_collectors = max(1, len(collectors_to_run))
    max_workers = max(4, len(collectors_to_run))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix=f"collector-{investigation_id[:8]}",
    ) as pool:
        future_to_name = {pool.submit(_run_one, name): name for name in collectors_to_run}
        try:
            for future in concurrent.futures.as_completed(future_to_name, timeout=timeout + 30):
                name = future_to_name[future]
                try:
                    result = future.result()
                    results.append(result)
                    collector_statuses[name] = result.get("status", "failed")
                except Exception as e:
                    logger.error(f"[{investigation_id}] Collector '{name}' raised: {e}")
                    collector_statuses[name] = "failed"

                completed = sum(1 for s in collector_statuses.values() if s != "running")
                percent = 10 + int((completed / total_collectors) * 45)
                duration_ms = None
                if results and results[-1].get("collector") == name:
                    duration_ms = results[-1].get("duration_ms")

                _publish_progress(
                    investigation_id,
                    InvestigationState.GATHERING,
                    f"Collector {name.upper()} {collector_statuses[name]}",
                    percent,
                    collectors=collector_statuses,
                    collector=name,
                    duration_ms=duration_ms,
                    total_elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                )
        except concurrent.futures.TimeoutError:
            logger.error(
                f"[{investigation_id}] Collector phase timed out after {timeout + 30}s; "
                "continuing with completed collector results only"
            )
    return results, collector_statuses


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
    collectors: dict[str, str] | None = None,
    **extra: object,
) -> None:
    """Push progress event to Redis for SSE streaming."""
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        payload = {
            "type": "state_change",
            "investigation_id": investigation_id,
            "state": state.value,
            "message": message,
            "percent_complete": percent,
        }
        if collectors:
            payload["collectors"] = collectors
        payload.update(extra)
        r.publish(f"investigation:{investigation_id}", json.dumps(payload))
    except Exception as e:
        logger.warning(f"Failed to publish progress: {e}")
