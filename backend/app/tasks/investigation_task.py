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
    task_start = time.monotonic()

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
        return investigation_id

    # ── Update state to gathering ──
    _update_state(investigation_id, InvestigationState.GATHERING)
    _publish_progress(investigation_id, InvestigationState.GATHERING,
                      f"Starting {len(collectors_to_run)} collectors...", 5)

    # ── Run all collectors in parallel via ThreadPoolExecutor ──
    # We bypass Celery sub-tasks entirely. Collectors are plain Python functions
    # called in threads — no broker round-trips, no chord/group result tracking,
    # zero Windows-specific Celery bugs. SSE progress is still published via Redis.
    safe_results = _run_collectors_inline(
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

    # ── Run analysis directly (same task thread) ──
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

    total_duration = time.monotonic() - task_start
    if total_duration >= settings.investigation_slow_log_threshold_sec:
        logger.warning(
            "[%s] Slow investigation completed in %.2fs (threshold=%ss, type=%s, collectors=%s)",
            investigation_id,
            total_duration,
            settings.investigation_slow_log_threshold_sec,
            observable_type,
            ",".join(collectors_to_run),
        )
    else:
        logger.info("[%s] Investigation completed in %.2fs", investigation_id, total_duration)

    return investigation_id


def _run_collectors_inline(
    collectors_to_run: list[str],
    domain: str,
    investigation_id: str,
    observable_type: str,
    file_artifact_id: str | None,
    timeout: int,
) -> list[dict]:
    """
    Run all collectors in parallel using ThreadPoolExecutor.

    Each collector is instantiated and called directly — no Celery sub-tasks.
    Returns a list of result dicts (same format as run_collector Celery task).
    Failed collectors are logged and excluded from the returned list.
    """
    def _run_one(name: str) -> dict:
        result = _run_collector_with_retries(
            collector_name=name,
            domain=domain,
            investigation_id=investigation_id,
            observable_type=observable_type,
            file_artifact_id=file_artifact_id,
            timeout=timeout,
        )
        status = result.get("status", "failed")

        # Publish per-collector SSE progress (same as collector_task.py does)
        try:
            r = redis_lib.Redis.from_url(settings.redis_url)
            r.publish(
                f"investigation:{investigation_id}",
                json.dumps({
                    "type": "collector_complete",
                    "investigation_id": investigation_id,
                    "collector": name,
                    "status": status,
                }),
            )
        except Exception as pub_err:
            logger.warning(f"[{investigation_id}] Failed to publish collector progress: {pub_err}")
        return result

    results: list[dict] = []
    max_workers = max(4, len(collectors_to_run))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix=f"collector-{investigation_id[:8]}",
    ) as pool:
        future_to_name = {pool.submit(_run_one, name): name for name in collectors_to_run}
        for future in concurrent.futures.as_completed(future_to_name, timeout=timeout + 30):
            name = future_to_name[future]
            try:
                results.append(future.result())
            except Exception as e:
                logger.error(f"[{investigation_id}] Collector '{name}' raised: {e}")

    return results


def _run_collector_with_retries(
    collector_name: str,
    domain: str,
    investigation_id: str,
    observable_type: str,
    file_artifact_id: str | None,
    timeout: int,
) -> dict:
    collector_cls = get_collector(collector_name)
    if not collector_cls:
        logger.warning(f"[{investigation_id}] Unknown collector: {collector_name}")
        return {
            "collector": collector_name,
            "status": "failed",
            "evidence": {},
            "meta": {"collector": collector_name, "status": "failed", "error": "Unknown collector"},
            "artifacts": {},
        }

    attempts = max(1, int(settings.collector_retry_attempts))
    backoff = max(0.0, float(settings.collector_retry_backoff_sec))
    last_result: dict | None = None
    last_error = ""

    for attempt in range(1, attempts + 1):
        collector_start = time.monotonic()
        try:
            collector = collector_cls(
                domain=domain,
                investigation_id=investigation_id,
                timeout=timeout,
                observable_type=observable_type,
                file_artifact_id=file_artifact_id,
            )
            evidence, meta, raw_artifacts = collector.run()

            last_result = {
                "collector": collector_name,
                "status": meta.status.value,
                "evidence": evidence.model_dump(mode="json"),
                "meta": meta.model_dump(mode="json"),
                "artifacts": {k: v.hex() for k, v in raw_artifacts.items()},
            }
            if meta.status.value != "failed":
                elapsed = time.monotonic() - collector_start
                logger.info(
                    "[%s] Collector %s completed in %.2fs (attempt %d/%d)",
                    investigation_id,
                    collector_name,
                    elapsed,
                    attempt,
                    attempts,
                )
                return last_result

            last_error = (last_result["meta"] or {}).get("error", "collector returned failed status")

        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "[%s] Collector %s exception on attempt %d/%d: %s",
                investigation_id,
                collector_name,
                attempt,
                attempts,
                last_error,
            )
            last_result = {
                "collector": collector_name,
                "status": "failed",
                "evidence": {},
                "meta": {"collector": collector_name, "status": "failed", "error": last_error},
                "artifacts": {},
            }

        if attempt < attempts and backoff > 0:
            sleep_for = backoff * attempt
            logger.info(
                "[%s] Retrying collector %s in %.1fs (attempt %d/%d, reason=%s)",
                investigation_id,
                collector_name,
                sleep_for,
                attempt + 1,
                attempts,
                last_error or "failed status",
            )
            time.sleep(sleep_for)

    logger.error(
        "[%s] Collector %s failed after %d attempts (%s)",
        investigation_id,
        collector_name,
        attempts,
        last_error or "unknown error",
    )
    return last_result or {
        "collector": collector_name,
        "status": "failed",
        "evidence": {},
        "meta": {"collector": collector_name, "status": "failed", "error": last_error or "failed"},
        "artifacts": {},
    }


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
