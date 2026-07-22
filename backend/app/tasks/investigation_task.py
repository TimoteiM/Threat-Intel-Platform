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
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import Evidence, Investigation, WatchlistEntry
from app.models.enums import InvestigationState
from app.collectors.registry import available_collectors, get_collector, get_collectors_for_type
from app.db.session import sync_engine
from app.tasks.celery_app import celery_app
from app.tasks.analysis_task import (
    _attach_artifact_ids,
    _guess_content_type,
    _save_artifact_sync,
    recompute_report_for_existing_investigation,
    run_analysis,
)

logger = logging.getLogger(__name__)
settings = get_settings()

# AnyRun sandbox soft deadline within the main collector phase.
# Non-domain investigations may still proceed without it and merge the result
# later in the background. Domain investigations block on the full AnyRun
# collector result so scoring includes the final lookup/sandbox evidence.
ANYRUN_ASYNC_DEADLINE = 90  # seconds
ANYRUN_COLLECTOR_NAME = "hybrid_analysis"


def _sandbox_collector_timeout(base_timeout: int) -> int:
    """
    Derive a realistic timeout budget for the sandbox collector.

    The hybrid/Any.Run path can spend significant time in provider retry/backoff
    before a sandbox report is available. A fixed 180s window is too short for
    the retry strategy we already run, so size the collector budget from those
    configured limits and cap it below the task soft time limit.
    """
    s = get_settings()
    parallel_retries = max(0, int(getattr(s, "anyrun_parallel_limit_retries", 8) or 8))
    parallel_backoff = max(0, int(getattr(s, "anyrun_parallel_backoff_seconds", 10) or 10))
    transient_retries = max(0, int(getattr(s, "anyrun_transient_retries", 3) or 3))
    transient_backoff = max(0, int(getattr(s, "anyrun_transient_backoff_seconds", 6) or 6))
    anyrun_wait = max(
        int(getattr(s, "anyrun_timeout_url_domain_seconds", 45) or 45),
        int(getattr(s, "anyrun_timeout_file_hash_seconds", 90) or 90),
    )

    parallel_backoff_budget = parallel_backoff * parallel_retries * (parallel_retries + 1) // 2
    transient_backoff_budget = transient_backoff * transient_retries * (transient_retries + 1) // 2
    computed = anyrun_wait + parallel_backoff_budget + transient_backoff_budget + 120
    return max(base_timeout, min(480, computed))


def _collector_timeout(name: str, base_timeout: int) -> int:
    if name == "hybrid_analysis":
        return _sandbox_collector_timeout(base_timeout)
    if name == "urlscan":
        analysis_wait = max(
            30,
            int(getattr(get_settings(), "urlscan_analysis_timeout_seconds", 75) or 75),
        )
        # Leave room for the initial search, submission, and response parsing.
        return max(base_timeout, analysis_wait + 20)
    return base_timeout


def _requires_blocking_anyrun(observable_type: str) -> bool:
    return str(observable_type or "").strip().lower() == "domain"


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
    ai_model: str | None = None,  # kept for backward compat with queued tasks; ignored
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

    if _is_cancelled(investigation_id):
        logger.info("[%s] Investigation was cancelled before execution.", investigation_id)
        return investigation_id

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

        safe_results, collector_statuses, anyrun_bg_future = _run_collectors_inline(
            collectors_to_run=collectors_to_run,
            domain=domain,
            investigation_id=investigation_id,
            observable_type=observable_type,
            file_artifact_id=file_artifact_id,
            external_context=external_context,
            timeout=settings.collector_timeout,
        )

        logger.info(
            f"[{investigation_id}] Collectors complete: "
            f"{len(safe_results)}/{len(collectors_to_run)} succeeded. Starting analysis..."
        )

        if _is_cancelled(investigation_id):
            logger.info("[%s] Investigation cancelled during collector phase.", investigation_id)
            return investigation_id

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

        _update_watchlist_after_conclusion(investigation_id, domain)

        # If AnyRun was deferred, start a background thread to update evidence
        # when the sandbox finishes (does not block the investigation completion).
        if anyrun_bg_future is not None:
            _start_anyrun_background_update(anyrun_bg_future, investigation_id)

    except Exception as exc:
        logger.exception(f"[{investigation_id}] Investigation task failed: {exc}")
        if _is_cancelled(investigation_id):
            logger.info("[%s] Task exception after cancellation ignored.", investigation_id)
            return investigation_id
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
    external_context: dict | None,
    timeout: int,
) -> tuple[list[dict], dict[str, str], Optional["concurrent.futures.Future[dict]"]]:
    """
    Run all collectors in parallel using ThreadPoolExecutor.

    AnyRun (hybrid_analysis) is given a 90-second soft deadline within the main
    phase. If it finishes in time its result is included normally. If it exceeds
    the deadline the investigation proceeds without it — AnyRun continues in a
    background thread and its result is written to the DB when it eventually
    finishes (see _anyrun_background_update).

    Returns (results, collector_statuses, anyrun_background_future_or_None).
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
            timeout=_collector_timeout(name, timeout),
            observable_type=observable_type,
            file_artifact_id=file_artifact_id,
            external_context=external_context,
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

    # ── Separate AnyRun from fast collectors ─────────────────────────────────
    run_anyrun = ANYRUN_COLLECTOR_NAME in collectors_to_run
    fast_collectors = [c for c in collectors_to_run if c != ANYRUN_COLLECTOR_NAME]

    results: list[dict] = []
    collector_statuses: dict[str, str] = {name: "running" for name in collectors_to_run}
    start_ts = time.monotonic()
    total_collectors = max(1, len(collectors_to_run))
    max_workers = max(4, len(fast_collectors) + 1)  # +1 slot reserved for AnyRun

    fast_overall_timeout = max(
        (_collector_timeout(name, timeout) for name in fast_collectors),
        default=timeout,
    ) + 30 if fast_collectors else 30

    anyrun_background_future: Optional[concurrent.futures.Future] = None

    # ── Submit AnyRun to a separate long-lived executor (not joined on exit) ──
    anyrun_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
    anyrun_future:   Optional[concurrent.futures.Future] = None
    if run_anyrun:
        anyrun_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=f"anyrun-{investigation_id[:8]}",
        )
        anyrun_future = anyrun_executor.submit(_run_one, ANYRUN_COLLECTOR_NAME)
        anyrun_executor.shutdown(wait=False)  # don't block on exit

    # ── Run all fast collectors ───────────────────────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(4, len(fast_collectors)),
        thread_name_prefix=f"collector-{investigation_id[:8]}",
    ) as pool:
        future_to_name = {pool.submit(_run_one, name): name for name in fast_collectors}
        try:
            for future in concurrent.futures.as_completed(future_to_name, timeout=fast_overall_timeout):
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
                f"[{investigation_id}] Fast collector phase timed out after {fast_overall_timeout}s"
            )
            timed_out = [name for name, status in collector_statuses.items()
                         if status == "running" and name != ANYRUN_COLLECTOR_NAME]
            for name in timed_out:
                collector_statuses[name] = "failed"
                results.append(_build_timeout_result(name))
            if timed_out:
                _publish_progress(
                    investigation_id,
                    InvestigationState.GATHERING,
                    f"Collector timeout: {', '.join(n.upper() for n in timed_out)}",
                    55,
                    collectors=collector_statuses,
                    total_elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                )

    # ── Check AnyRun soft deadline ────────────────────────────────────────────
    if run_anyrun and anyrun_future is not None:
        elapsed = time.monotonic() - start_ts
        blocking_anyrun = _requires_blocking_anyrun(observable_type)
        anyrun_wait_budget = (
            _collector_timeout(ANYRUN_COLLECTOR_NAME, timeout)
            if blocking_anyrun
            else ANYRUN_ASYNC_DEADLINE
        )
        remaining = max(0.0, anyrun_wait_budget - elapsed)
        if remaining > 0:
            try:
                result = anyrun_future.result(timeout=remaining)
                results.append(result)
                collector_statuses[ANYRUN_COLLECTOR_NAME] = result.get("status", "failed")
                logger.info(
                    f"[{investigation_id}] AnyRun finished within deadline "
                    f"({elapsed + (anyrun_wait_budget - remaining):.0f}s)"
                )
                _publish_progress(
                    investigation_id,
                    InvestigationState.GATHERING,
                    f"Collector HYBRID_ANALYSIS {collector_statuses[ANYRUN_COLLECTOR_NAME]}",
                    55,
                    collectors=collector_statuses,
                    collector=ANYRUN_COLLECTOR_NAME,
                    total_elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                )
            except concurrent.futures.TimeoutError:
                if blocking_anyrun:
                    logger.warning(
                        f"[{investigation_id}] AnyRun exceeded blocking budget of {anyrun_wait_budget}s "
                        "for a domain investigation - marking collector failed"
                    )
                    collector_statuses[ANYRUN_COLLECTOR_NAME] = "failed"
                    results.append(_build_timeout_result(ANYRUN_COLLECTOR_NAME))
                    _publish_progress(
                        investigation_id,
                        InvestigationState.GATHERING,
                        "AnyRun timed out before final scoring",
                        55,
                        collectors=collector_statuses,
                        collector=ANYRUN_COLLECTOR_NAME,
                        total_elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                    )
                else:
                    logger.info(
                        f"[{investigation_id}] AnyRun exceeded {ANYRUN_ASYNC_DEADLINE}s deadline - "
                        "proceeding without it, will update evidence in background"
                    )
                    collector_statuses[ANYRUN_COLLECTOR_NAME] = "deferred"
                    anyrun_background_future = anyrun_future
                    _publish_progress(
                        investigation_id,
                        InvestigationState.GATHERING,
                        "AnyRun deferred - analysis will continue without sandbox data",
                        55,
                        collectors=collector_statuses,
                        collector=ANYRUN_COLLECTOR_NAME,
                        total_elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                    )
            except Exception as e:
                logger.error(f"[{investigation_id}] AnyRun collector raised: {e}")
                collector_statuses[ANYRUN_COLLECTOR_NAME] = "failed"
        else:
            if blocking_anyrun:
                logger.warning(
                    f"[{investigation_id}] Fast collectors consumed the AnyRun blocking budget "
                    f"({anyrun_wait_budget}s) for a domain investigation - marking AnyRun failed"
                )
                collector_statuses[ANYRUN_COLLECTOR_NAME] = "failed"
                results.append(_build_timeout_result(ANYRUN_COLLECTOR_NAME))
            else:
                logger.info(
                    f"[{investigation_id}] Fast collectors took >{ANYRUN_ASYNC_DEADLINE}s - "
                    "deferring AnyRun to background immediately"
                )
                collector_statuses[ANYRUN_COLLECTOR_NAME] = "deferred"
                anyrun_background_future = anyrun_future

    return results, collector_statuses, anyrun_background_future


def _build_timeout_result(name: str) -> dict:
    """Build a synthetic collector result for collectors that timed out."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "collector": name,
        "status": "failed",
        "evidence": {
            "meta": {
                "collector": name,
                "version": "1.0.0",
                "status": "failed",
                "started_at": now,
                "completed_at": now,
                "duration_ms": None,
                "error": "Collector timed out before completion",
            }
        },
        "meta": {
            "collector": name,
            "version": "1.0.0",
            "status": "failed",
            "started_at": now,
            "completed_at": now,
            "duration_ms": None,
            "error": "Collector timed out before completion",
        },
        "artifacts": {},
        "duration_ms": None,
    }


def _start_anyrun_background_update(
    future: "concurrent.futures.Future[dict]",
    investigation_id: str,
) -> None:
    """
    Spin up a daemon thread that waits for the deferred AnyRun future and
    merges its result into the investigation's evidence_json once done.
    """
    t = threading.Thread(
        target=_anyrun_background_update,
        args=(future, investigation_id),
        daemon=True,
        name=f"anyrun-bg-{investigation_id[:8]}",
    )
    t.start()
    logger.info(
        f"[{investigation_id}] AnyRun background update thread started (thread={t.name})"
    )


def _anyrun_background_update(
    future: "concurrent.futures.Future[dict]",
    investigation_id: str,
) -> None:
    """
    Daemon thread body — waits for the AnyRun future, then merges the sandbox
    result into evidence_json in the DB and publishes an SSE event so the
    frontend can refresh the Technical Evidence tab.
    """
    logger.info(f"[{investigation_id}] Waiting for deferred AnyRun result...")
    try:
        # Give AnyRun a generous ceiling (hard task time-limit is 660 s; we
        # already spent ~90 s in the main phase so ~480 s remains at worst).
        result = future.result(timeout=480)
        logger.info(
            f"[{investigation_id}] Deferred AnyRun finished — "
            f"status={result.get('status')}"
        )
    except concurrent.futures.TimeoutError:
        logger.warning(
            f"[{investigation_id}] Deferred AnyRun still didn't finish after 480 s — giving up"
        )
        return
    except Exception as exc:
        logger.error(f"[{investigation_id}] Deferred AnyRun future raised: {exc}")
        return

    # ── Merge into DB evidence_json ──────────────────────────────────────────
    try:
        from sqlalchemy import select as sa_select
        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            if inv is None:
                logger.warning(
                    f"[{investigation_id}] Investigation not found when trying to update AnyRun evidence"
                )
                return

            # Evidence lives in the Evidence table, related 1:1 to Investigation
            evidence_row = session.execute(
                sa_select(Evidence).where(Evidence.investigation_id == inv_id)
            ).scalar_one_or_none()

            if evidence_row is None:
                logger.warning(
                    f"[{investigation_id}] No Evidence row found — cannot update AnyRun evidence"
                )
                return

            existing: dict = {}
            if evidence_row.evidence_json:
                try:
                    existing = (
                        json.loads(evidence_row.evidence_json)
                        if isinstance(evidence_row.evidence_json, str)
                        else dict(evidence_row.evidence_json)
                    )
                except Exception:
                    existing = {}

            evidence_from_result = result.get("evidence", {})
            artifact_ids: dict[str, str] = {}
            for artifact_name, hex_data in result.get("artifacts", {}).items():
                try:
                    artifact_id = _save_artifact_sync(
                        investigation_id=investigation_id,
                        collector_name=ANYRUN_COLLECTOR_NAME,
                        artifact_name=artifact_name,
                        data=bytes.fromhex(hex_data),
                        content_type=_guess_content_type(artifact_name),
                    )
                    if artifact_id:
                        artifact_ids[artifact_name] = artifact_id
                except Exception as exc:
                    logger.warning("[%s] Failed to persist deferred ANY.RUN artifact %s: %s", investigation_id, artifact_name, exc)
            _attach_artifact_ids(evidence_from_result, artifact_ids)

            # Merge hybrid_analysis collector result into evidence
            existing[ANYRUN_COLLECTOR_NAME] = evidence_from_result

            evidence_row.evidence_json = existing
            inv.updated_at = datetime.now(timezone.utc)
            session.commit()
            logger.info(
                f"[{investigation_id}] AnyRun evidence merged into DB successfully"
            )
    except Exception as exc:
        logger.error(
            f"[{investigation_id}] Failed to persist deferred AnyRun evidence: {exc}"
        )
        return

    recomputed = recompute_report_for_existing_investigation(
        investigation_id,
        reason="deferred_anyrun_completed",
    )

    # ── Notify frontend via SSE ──────────────────────────────────────────────
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        payload = {
            "type": "evidence_updated",
            "investigation_id": investigation_id,
            "collector": ANYRUN_COLLECTOR_NAME,
            "report_recomputed": bool(recomputed),
            "message": (
                "AnyRun sandbox analysis complete — evidence and report updated"
                if recomputed else
                "AnyRun sandbox analysis complete — evidence updated; report recompute failed"
            ),
        }
        r.publish(f"investigation:{investigation_id}", json.dumps(payload))
        logger.info(f"[{investigation_id}] SSE evidence_updated published")
    except Exception as exc:
        logger.warning(f"[{investigation_id}] Failed to publish evidence_updated SSE: {exc}")


def _update_watchlist_after_conclusion(investigation_id: str, domain: str) -> None:
    """
    After an investigation concludes, update the matching watchlist entry (if any):
    - Append the new risk score to risk_score_history (last 30 kept)
    - Compute an evidence diff against the previous concluded investigation and
      store it in evidence_diff_json
    """
    from sqlalchemy import select as sa_select
    from app.services.evidence_diff_service import diff_evidence

    try:
        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            # Find watchlist entry for this domain
            watchlist_entry = session.execute(
                sa_select(WatchlistEntry).where(WatchlistEntry.domain == domain)
            ).scalar_one_or_none()
            if watchlist_entry is None:
                return

            # Get the 2 most recent concluded investigations for this domain
            concluded_invs = session.execute(
                sa_select(Investigation)
                .where(
                    Investigation.domain == domain,
                    Investigation.state == "concluded",
                )
                .order_by(Investigation.concluded_at.desc())
                .limit(2)
            ).scalars().all()

            curr_inv = next((i for i in concluded_invs if i.id == inv_id), None)
            if curr_inv is None:
                # Investigation not yet marked concluded — use first from list
                curr_inv = concluded_invs[0] if concluded_invs else None
            if curr_inv is None:
                return

            # ── Risk score history ────────────────────────────────────────────
            history: list = list(watchlist_entry.risk_score_history or [])
            history.append({
                "score": curr_inv.risk_score,
                "at": curr_inv.concluded_at.isoformat() if curr_inv.concluded_at else datetime.now(timezone.utc).isoformat(),
                "investigation_id": str(curr_inv.id),
            })
            watchlist_entry.risk_score_history = history[-30:]  # keep last 30

            # ── Evidence diff ─────────────────────────────────────────────────
            prev_inv = next((i for i in concluded_invs if i.id != curr_inv.id), None)
            if prev_inv is not None:
                curr_evidence = session.execute(
                    sa_select(Evidence).where(Evidence.investigation_id == curr_inv.id)
                ).scalar_one_or_none()
                prev_evidence = session.execute(
                    sa_select(Evidence).where(Evidence.investigation_id == prev_inv.id)
                ).scalar_one_or_none()

                if curr_evidence and prev_evidence:
                    curr_json = (
                        json.loads(curr_evidence.evidence_json)
                        if isinstance(curr_evidence.evidence_json, str)
                        else (curr_evidence.evidence_json or {})
                    )
                    prev_json = (
                        json.loads(prev_evidence.evidence_json)
                        if isinstance(prev_evidence.evidence_json, str)
                        else (prev_evidence.evidence_json or {})
                    )
                    changes = diff_evidence(prev_json, curr_json)
                    watchlist_entry.evidence_diff_json = {
                        "computed_at": datetime.now(timezone.utc).isoformat(),
                        "prev_investigation_id": str(prev_inv.id),
                        "curr_investigation_id": str(curr_inv.id),
                        "has_changes": bool(changes),
                        "changes": changes,
                    }

            session.commit()
            logger.info(
                f"[{investigation_id}] Watchlist history updated for {domain} "
                f"(score={curr_inv.risk_score}, diff_computed={prev_inv is not None})"
            )
    except Exception as exc:
        logger.warning(f"[{investigation_id}] Watchlist post-conclusion update failed: {exc}")


def _update_state(investigation_id: str, state: InvestigationState) -> None:
    """Update investigation state in Postgres."""
    try:
        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            if inv:
                current = str(inv.state or "").lower()
                if current == "cancelled" and state.value != "cancelled":
                    return
                inv.state = state.value
                inv.updated_at = datetime.now(timezone.utc)
                session.commit()
    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to update state: {e}")


def _is_cancelled(investigation_id: str) -> bool:
    try:
        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            return bool(inv and str(inv.state or "").lower() == "cancelled")
    except Exception:
        return False


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
