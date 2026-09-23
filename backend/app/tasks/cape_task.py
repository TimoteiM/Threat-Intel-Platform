"""Drive a CAPE analysis from request to stored verdict.

A Celery task rather than a thread in the API process, for the same reason the
ANY.RUN batch is: a detonation takes minutes, it has to outlive the request
that asked for it, and it has to survive an API restart. No HTTP handler here
ever waits for CAPE.

The workflow is restartable because its state is in Postgres. A worker killed
mid-poll leaves a row in `running`; `resume_sandbox_analyses` picks it up and
carries on from the CAPE task id it already stored. That is also why the
submission step is so careful — everything after it is replayable, and it is
the one step that is not.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import Artifact, Investigation, SandboxAnalysis
from app.services import cape_analysis_service as svc
from app.services import cape_client as cape
from app.services.cape_normalizer import normalize_report
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# CAPE task states that mean an existing analysis is worth adopting.
_REUSABLE_CAPE_STATES = frozenset({"reported"})


@celery_app.task(
    name="app.tasks.cape_task.run_cape_analysis",
    bind=True,
    max_retries=0,          # the workflow owns its own retry semantics
    soft_time_limit=None,
)
def run_cape_analysis(self, analysis_id: str) -> dict[str, Any]:
    """Submit (or adopt), poll, fetch, normalize, persist."""
    settings = get_settings()
    if not settings.cape_configured:
        logger.info("CAPE is not configured; analysis %s left queued", analysis_id)
        return {"analysis_id": analysis_id, "status": "skipped", "reason": "not_configured"}

    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is None:
            return {"analysis_id": analysis_id, "status": "missing"}
        if row.status in svc.TERMINAL_STATUSES:
            db.rollback()
            return {"analysis_id": analysis_id, "status": row.status, "note": "already finished"}
        # Release the row lock before the long part: holding a transaction open
        # across minutes of polling would pin a connection and block the API's
        # own reads of this row.
        analysis_uuid = row.id
        sha256 = row.sha256
        artifact_id = row.artifact_id
        sample_name = row.sample_name
        task_id = row.provider_task_id
        target_kind = getattr(row, "target_kind", "file") or "file"
        target_url = getattr(row, "target_url", None)
        db.commit()

    request_id = uuid.uuid4().hex[:12]
    try:
        with cape.CapeClient(settings=settings, request_id=request_id) as client:
            if not task_id:
                task_id = _obtain_task(
                    client, analysis_uuid, sha256, artifact_id, sample_name, settings,
                    target_kind=target_kind, target_url=target_url,
                )
            if task_id is None:
                return {"analysis_id": analysis_id, "status": svc.STATUS_FAILED}
            return _poll_and_store(client, analysis_uuid, task_id, settings)

    # ── Transient, and therefore not a verdict ──────────────────────────────
    #
    # A throttled or briefly unreachable CAPE says nothing about the analysis.
    # Marking these failed lost completed work: task 13 reached `completed` on
    # CAPE, hit the rate limit while its report was being fetched, and was
    # recorded as failed while CAPE's own UI showed it reported. The analysis
    # keeps its current state and is driven again, bounded by deadline_at.
    except (cape.CapeRateLimited, cape.CapeTimeout, cape.CapeConnectionError) as exc:
        if isinstance(exc, cape.CapeTLSError):
            _fail(analysis_uuid, "TLS verification failed", exc)
            return {"analysis_id": analysis_id, "status": svc.STATUS_FAILED}
        return _retry_later(analysis_uuid, exc)

    except cape.CapeNotConfigured as exc:
        _fail(analysis_uuid, "CAPE is not configured", exc)
    except cape.CapeAuthError as exc:
        _fail(analysis_uuid, "CAPE rejected the API token", exc)
    except cape.CapeForbidden as exc:
        _fail(analysis_uuid, "CAPE refused the operation", exc)
    except cape.CapeTLSError as exc:
        _fail(analysis_uuid, "TLS verification failed", exc)
    except cape.CapeError as exc:
        _fail(analysis_uuid, "CAPE analysis failed", exc)
    except Exception as exc:  # noqa: BLE001 — a worker crash must still land in the record
        _fail(analysis_uuid, "Unexpected error during CAPE analysis", exc)
    return {"analysis_id": analysis_id, "status": svc.STATUS_FAILED}


# ── obtaining a task ─────────────────────────────────────────────────────────


def _obtain_task(
    client: cape.CapeClient,
    analysis_id: uuid.UUID,
    sha256: str | None,
    artifact_id: uuid.UUID | None,
    sample_name: str | None,
    settings,
    *,
    target_kind: str = "file",
    target_url: str | None = None,
) -> str | None:
    """Adopt an existing CAPE analysis, or submit. Never both."""
    if target_kind == "url":
        return _obtain_url_task(client, analysis_id, target_url, settings)

    if settings.cape_reuse_existing_analysis:
        adopted = _find_reusable(client, sha256)
        if adopted is not None:
            _record_task(analysis_id, str(adopted), reused=True,
                         note="adopted an existing CAPE analysis for this hash")
            return str(adopted)

    path, filename = _resolve_sample(artifact_id, sample_name, sha256)
    if path is None:
        # Nothing to detonate. For a hash seen in an alert with no file behind
        # it this is the expected outcome, not a fault: CAPE had no prior
        # analysis and we have no sample to give it.
        _terminal(analysis_id, svc.STATUS_FAILED,
                  error="No file is available for this sample, and CAPE has no existing analysis for the hash.",
                  note="no sample available")
        return None

    _set_status(analysis_id, svc.STATUS_SUBMITTING, note=f"submitting {filename}")
    try:
        with path.open("rb") as handle:
            submission = client.submit_file(file_obj=handle, filename=filename)
    except cape.CapeAmbiguousSubmission as exc:
        # The critical case. The sample may already be detonating; resending
        # would run it twice on a pool of six machines. Reconcile by hash.
        logger.warning("Ambiguous CAPE submission for analysis %s: %s", analysis_id, exc)
        recovered = _reconcile_after_ambiguous(client, sha256)
        if recovered is not None:
            _record_task(analysis_id, str(recovered), reused=False,
                         note="recovered the task id by hash after an ambiguous submission")
            return str(recovered)
        _terminal(
            analysis_id, svc.STATUS_FAILED,
            error=("The submission timed out and CAPE reports no task for this hash. "
                   "It was NOT resubmitted automatically — retry explicitly once CAPE is reachable."),
            note="ambiguous submission, not resubmitted",
        )
        return None

    task_id = submission.task_id
    if task_id is None:
        _terminal(analysis_id, svc.STATUS_FAILED, error="CAPE returned no task id", note="no task id")
        return None
    _record_task(analysis_id, str(task_id), reused=False, note="submitted to CAPE")
    return str(task_id)


def _obtain_url_task(
    client: cape.CapeClient, analysis_id: uuid.UUID, target_url: str | None, settings
) -> str | None:
    """Ask CAPE to fetch and detonate a URL.

    Reuse works differently here. A file is identified by a hash CAPE can be
    searched on directly; a URL is looked up through extendedsearch, and only
    a completed analysis is worth adopting.
    """
    if not target_url:
        _terminal(analysis_id, svc.STATUS_FAILED,
                  error="No URL recorded for this analysis.", note="no url")
        return None

    if settings.cape_reuse_existing_analysis:
        try:
            hits = client.search_reports("url", target_url)
            adopted = max(
                (int((h.get("info") or {}).get("id") or 0) for h in hits),
                default=0,
            )
            if adopted:
                _record_task(analysis_id, str(adopted), reused=True,
                             note="adopted an existing CAPE analysis for this URL")
                return str(adopted)
        except cape.CapeError as exc:
            logger.info("CAPE URL search failed, will submit instead: %s", exc)

    _set_status(analysis_id, svc.STATUS_SUBMITTING, note=f"submitting URL {target_url[:120]}")
    try:
        submission = client.submit_url(url=target_url)
    except cape.CapeAmbiguousSubmission as exc:
        logger.warning("Ambiguous CAPE URL submission for %s: %s", analysis_id, exc)
        _terminal(
            analysis_id, svc.STATUS_FAILED,
            error=("The URL submission timed out. It was NOT resubmitted automatically — "
                   "check CAPE for a task before retrying."),
            note="ambiguous url submission",
        )
        return None

    task_id = submission.task_id
    if task_id is None:
        _terminal(analysis_id, svc.STATUS_FAILED, error="CAPE returned no task id", note="no task id")
        return None
    _record_task(analysis_id, str(task_id), reused=False, note="URL submitted to CAPE")
    return str(task_id)


def _find_reusable(client: cape.CapeClient, sha256: str) -> int | None:
    """A previous CAPE analysis good enough to adopt.

    Only `reported`: a task still running belongs to somebody else's workflow,
    and a failed one is not a result. Highest id wins, so the most recent
    analysis is preferred over a stale one.
    """
    try:
        tasks = client.search_by_sha256(sha256)
    except cape.CapeError as exc:
        logger.info("CAPE hash search failed, will submit instead: %s", exc)
        return None
    reported = [t for t in tasks if t.status in _REUSABLE_CAPE_STATES]
    if not reported:
        return None
    return max(t.task_id for t in reported)


def _reconcile_after_ambiguous(client: cape.CapeClient, sha256: str) -> int | None:
    """Did the submission land after all? Asked, never assumed."""
    try:
        tasks = client.search_by_sha256(sha256)
    except cape.CapeError:
        return None
    return max((t.task_id for t in tasks), default=None)


def _resolve_sample(
    artifact_id: uuid.UUID | None, sample_name: str | None, sha256: str | None = None
) -> tuple[Path | None, str]:
    """The file on disk for this analysis, if the platform still holds one.

    Falls back to any retained upload with this hash when no artifact was
    recorded — an analysis raised from a hash is still submittable if we
    happen to hold the file.

    The content is verified against the hash before the path is returned.
    A stored digest is a claim about a file; sending the wrong one to a
    sandbox would detonate something nobody asked for and attribute the
    result to this sample.
    """
    candidates: list[Artifact] = []
    with Session(sync_engine) as db:
        if artifact_id is not None:
            artifact = db.get(Artifact, artifact_id)
            if artifact is not None:
                candidates.append(artifact)
        if not candidates and sha256:
            candidates = list(
                db.execute(
                    select(Artifact)
                    .where(Artifact.sha256_hash == str(sha256).lower(),
                           Artifact.collector_name == "upload")
                    .order_by(Artifact.created_at.asc())
                ).scalars().all()
            )

        for artifact in candidates:
            path = Path(str(artifact.storage_path or "")).expanduser()
            if not path.is_absolute():
                path = Path("/app") / path
            if not path.exists() or not path.is_file():
                logger.info("Artifact %s is no longer retained at %s", artifact.id, path)
                continue
            if sha256 and _digest_of(path) != str(sha256).lower():
                logger.warning(
                    "Artifact %s does not hash to %s; refusing to submit it", artifact.id, str(sha256)[:16]
                )
                continue
            return path, artifact.artifact_name or sample_name or "sample.bin"

    return None, sample_name or "sample.bin"


def _digest_of(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ── polling and storing ──────────────────────────────────────────────────────


def _poll_and_store(client: cape.CapeClient, analysis_id: uuid.UUID, task_id: str, settings) -> dict[str, Any]:
    interval = max(int(settings.cape_poll_interval_seconds), 2)
    deadline = time.monotonic() + int(settings.cape_max_poll_duration_seconds)
    last_status: str | None = None

    while True:
        task = client.view_task(task_id)
        mapped = svc.CAPE_STATE_MAP.get(task.status, svc.STATUS_RUNNING)

        # Only the in-flight states are published from here. `reported` is set
        # by _store_report once the report is actually in hand: announcing it
        # on the strength of the task view would claim a result we have not
        # fetched, and would put two `reported` entries in the audit trail.
        if mapped != last_status and mapped not in svc.TERMINAL_STATUSES:
            _set_status(analysis_id, mapped, note=f"CAPE task {task_id} is {task.status}")
            last_status = mapped
        _bump_poll(analysis_id)

        if task.is_failed:
            _terminal(analysis_id, svc.STATUS_FAILED,
                      error=f"CAPE analysis finished as {task.status}", note="CAPE reported a failure")
            return {"analysis_id": str(analysis_id), "status": svc.STATUS_FAILED}

        if task.is_reported:
            return _store_report(client, analysis_id, task_id, settings)

        if time.monotonic() >= deadline:
            _terminal(
                analysis_id, svc.STATUS_TIMED_OUT,
                error=(f"CAPE task {task_id} did not reach a reported state within "
                       f"{settings.cape_max_poll_duration_seconds}s. The task may still be running on CAPE."),
                note="polling deadline reached",
            )
            return {"analysis_id": str(analysis_id), "status": svc.STATUS_TIMED_OUT}

        time.sleep(interval)


def _store_report(client: cape.CapeClient, analysis_id: uuid.UUID, task_id: str, settings) -> dict[str, Any]:
    """Fetch the authoritative report and persist the normalized findings.

    `tasks/view` is never treated as the result: it carries the lifecycle, and
    on this CAPE it does not reliably carry malscore. The report is the source.
    """
    try:
        report = client.fetch_report(task_id, formats=settings.cape_report_format_list)
    except cape.CapeResponseTooLarge as exc:
        # A finished analysis whose report will not fit is still a finished
        # analysis. Measured: one PDF produced a 139MB JSON report against a
        # 64MB ceiling, while CAPE's own IOC summary for the same task was
        # 116KB and carried the score, network, dropped files and behaviour.
        # Failing here threw all of that away and told the analyst nothing,
        # while CAPE's own UI showed a completed run.
        logger.warning("CAPE report for task %s too large (%s); falling back to the IOC summary",
                       task_id, exc)
        report = client.fetch_iocs(task_id)
    normalized = normalize_report(
        report.payload,
        task_id=int(task_id),
        report_format=report.fmt,
        report_size_bytes=report.size_bytes,
    )

    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is None:
            return {"analysis_id": str(analysis_id), "status": "missing"}

        row.normalized_json = normalized.model_dump(mode="json")
        # An analysis that recovered still carried the message from the attempt
        # that failed, so a reported result showed a red "CAPE analysis failed"
        # banner describing something that had since worked.
        row.error = None
        row.verdict = normalized.verdict
        row.malscore = normalized.malscore
        row.sha1 = normalized.sha1 or row.sha1
        row.md5 = normalized.md5 or row.md5
        row.sample_type = normalized.file_type or row.sample_type
        row.sample_size = normalized.file_size or row.sample_size
        # A bounded reference, not the report. Enough to go back to the CAPE
        # task for any finding without storing tens of megabytes per sample.
        row.raw_summary = {
            "provider": "cape",
            "task_id": int(task_id),
            "report_format": report.fmt,
            "report_size_bytes": report.size_bytes,
            "machine": normalized.machine,
            "route": normalized.route,
            "counts": {
                "signatures": len(normalized.signatures),
                "domains": len(normalized.network.domains),
                "hosts": len(normalized.network.hosts),
                "http_requests": len(normalized.network.http_requests),
                "dropped_files": len(normalized.dropped_files),
                "extracted_configs": len(normalized.extracted_configs),
                "processes": normalized.behaviour.process_count,
            },
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        svc.transition(db, row, svc.STATUS_REPORTED, actor="worker",
                       note=f"report stored ({report.fmt}, {report.size_bytes} bytes)")
        investigation_id = row.investigation_id
        verdict = row.verdict
        score = row.malscore

    _annotate_investigation(investigation_id, normalized)
    logger.info("CAPE analysis %s reported: verdict=%s malscore=%s", analysis_id, verdict, score)
    return {"analysis_id": str(analysis_id), "status": svc.STATUS_REPORTED,
            "verdict": verdict, "malscore": score, "task_id": int(task_id)}


def _annotate_investigation(investigation_id: uuid.UUID | None, normalized) -> None:
    """Put the detonation into the investigation, and think again.

    A detonation takes minutes; the collector pipeline and the AI analyst
    finish in seconds. So the verdict was always written before the sandbox
    had said anything, and the sandbox result arrived afterwards as a panel
    nothing had read. An analyst saw "benign" beside a CAPE score of 10.

    Blocking the pipeline on CAPE would be worse — it would hold every
    investigation for the length of the slowest sandbox. So the evidence is
    written when it arrives and the analyst is re-run over the complete set.

    Still additive: re-running the analyst is not the same as letting the
    sandbox set a verdict. It gets a vote alongside everything else.
    """
    if investigation_id is None:
        return
    try:
        _store_cape_evidence(investigation_id, normalized)
        _reanalyse(investigation_id)
    except Exception as exc:  # noqa: BLE001 — annotation must not fail the analysis
        logger.warning("Could not annotate investigation %s after CAPE: %s", investigation_id, exc)


def _store_cape_evidence(investigation_id: uuid.UUID, normalized) -> None:
    """Write the report where the collector's own output would have gone.

    Same shape as CapeEvidence, so the analyst prompt, the findings builder
    and the Technical Evidence panel all read it without knowing it arrived
    late.
    """
    from app.models.database import CollectorResult, Evidence

    payload = {
        "meta": {"collector": "cape", "status": "completed", "version": "1.0.0"},
        "available": True,
        "reason": None,
        "report": normalized.model_dump(mode="json"),
    }

    with Session(sync_engine) as db:
        inv = db.get(Investigation, investigation_id)
        if inv is None:
            return

        row = db.execute(
            select(CollectorResult).where(
                CollectorResult.investigation_id == investigation_id,
                CollectorResult.collector_name == "cape",
            )
        ).scalars().first()
        if row is None:
            row = CollectorResult(
                investigation_id=investigation_id,
                collector_name="cape",
                status="completed",
                version="1.0.0",
            )
            db.add(row)
        row.status = "completed"
        row.evidence_json = payload
        row.completed_at = datetime.now(timezone.utc)

        evidence = db.execute(
            select(Evidence).where(Evidence.investigation_id == investigation_id)
        ).scalars().first()
        if evidence is not None:
            merged = dict(evidence.evidence_json or {})
            merged["cape"] = payload
            # Reassigned, not mutated: SQLAlchemy does not see an in-place
            # change to a JSONB column and would never persist it.
            evidence.evidence_json = merged

        inv.updated_at = datetime.now(timezone.utc)
        db.commit()
    logger.info("Stored CAPE evidence on investigation %s", investigation_id)


def _reanalyse(investigation_id: uuid.UUID) -> None:
    """Re-run the analyst over the evidence now that the sandbox has reported."""
    from app.models.database import CollectorResult

    with Session(sync_engine) as db:
        inv = db.get(Investigation, investigation_id)
        if inv is None:
            return
        rows = db.execute(
            select(CollectorResult).where(CollectorResult.investigation_id == investigation_id)
        ).scalars().all()
        collector_results = [
            {
                "collector": r.collector_name,
                "status": r.status,
                "evidence": dict(r.evidence_json or {}),
                "meta": (r.evidence_json or {}).get("meta") or {"status": r.status},
            }
            for r in rows
        ]
        domain = str(inv.domain or "")
        observable_type = str(inv.observable_type or "domain")
        context = inv.context
        client_domain = inv.client_domain

    if not collector_results:
        return

    from app.tasks.analysis_task import run_analysis

    run_analysis.delay(
        collector_results=collector_results,
        domain=domain,
        investigation_id=str(investigation_id),
        observable_type=observable_type,
        context=context,
        client_domain=client_domain,
    )
    logger.info("Re-running the analyst for %s with the sandbox result included", investigation_id)


# ── small state helpers ──────────────────────────────────────────────────────


def _set_status(analysis_id: uuid.UUID, status: str, *, note: str | None = None) -> None:
    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is not None and row.status not in svc.TERMINAL_STATUSES:
            svc.transition(db, row, status, actor="worker", note=note)


def _record_task(analysis_id: uuid.UUID, task_id: str, *, reused: bool, note: str) -> None:
    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is None:
            return
        row.provider_task_id = str(task_id)
        row.reused_existing = bool(reused)
        svc.transition(db, row, svc.STATUS_SUBMITTED, actor="worker", note=note)


def _bump_poll(analysis_id: uuid.UUID) -> None:
    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is not None:
            row.poll_attempts = int(row.poll_attempts or 0) + 1
            db.commit()


def _terminal(analysis_id: uuid.UUID, status: str, *, error: str, note: str) -> None:
    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is not None and row.status not in svc.TERMINAL_STATUSES:
            svc.transition(db, row, status, actor="worker", note=note, error=cape.redact(error))


def _retry_later(analysis_id: uuid.UUID, exc: Exception) -> dict[str, Any]:
    """Leave the analysis alive and come back to it.

    The status is not changed, so the record still says what CAPE last told us
    and `resume_sandbox_analyses` treats it as in flight. A countdown re-drive
    recovers in about a minute rather than waiting for the next beat tick, and
    `deadline_at` is what stops this going round for ever — an analysis past
    its deadline is retired as timed_out by the resume task.
    """
    with Session(sync_engine) as db:
        row = svc.claim_for_work(db, analysis_id)
        if row is None:
            return {"analysis_id": str(analysis_id), "status": "missing"}
        if row.status in svc.TERMINAL_STATUSES:
            db.rollback()
            return {"analysis_id": str(analysis_id), "status": row.status}
        if svc.is_expired(row):
            svc.transition(
                db, row, svc.STATUS_TIMED_OUT, actor="worker",
                note="deadline reached while CAPE was unavailable",
                error=cape.redact(f"CAPE remained unavailable until the deadline: {exc}"),
            )
            return {"analysis_id": str(analysis_id), "status": svc.STATUS_TIMED_OUT}
        current = row.status
        # Recorded, so an operator reading the trail sees the interruption
        # rather than an unexplained gap between polls.
        svc.transition(db, row, current, actor="worker",
                       note=f"paused: {cape.redact(str(exc))[:160]}")

    delay = getattr(exc, "retry_after", None) or 60
    delay = max(30, min(int(delay) * 4, 300))
    logger.warning("CAPE unavailable for analysis %s; retrying in %ss (%s)", analysis_id, delay, exc)
    run_cape_analysis.apply_async(args=[str(analysis_id)], countdown=delay)
    return {"analysis_id": str(analysis_id), "status": current, "retry_in": delay}


def _fail(analysis_id: uuid.UUID, headline: str, exc: Exception) -> None:
    """Record a failure with the secret scrubbed out of the message."""
    message = cape.redact(f"{headline}: {exc}")
    logger.error("CAPE analysis %s failed — %s", analysis_id, message)
    _terminal(analysis_id, svc.STATUS_FAILED, error=message, note=headline)


# ── resume after a restart ───────────────────────────────────────────────────


@celery_app.task(name="app.tasks.cape_task.detonate_uploaded_sample", max_retries=0)
def detonate_uploaded_sample(investigation_id: str) -> dict[str, Any]:
    """Queue a detonation for a file an analyst has just uploaded.

    Runs in the worker rather than the request, because creating the analysis
    needs a synchronous session and the upload response should not wait on it.
    Idempotent through the usual key, so a double-submitted upload converges on
    one analysis instead of occupying two machines.
    """
    settings = get_settings()
    if not (settings.cape_configured and settings.cape_auto_detonate_uploads):
        return {"queued": False, "reason": "disabled"}

    try:
        inv_id = uuid.UUID(str(investigation_id))
    except ValueError:
        return {"queued": False, "reason": "bad_investigation_id"}

    with Session(sync_engine) as db:
        inv = db.get(Investigation, inv_id)
        if inv is None:
            return {"queued": False, "reason": "investigation_missing"}

        artifact = (
            db.execute(
                select(Artifact)
                .where(Artifact.investigation_id == inv_id, Artifact.collector_name == "upload")
                .order_by(Artifact.created_at.asc())
            ).scalars().first()
        )
        if artifact is None:
            # A hash typed in by hand rather than a file. Nothing to submit,
            # and the collector has already asked CAPE whether it knows it.
            return {"queued": False, "reason": "no_uploaded_file"}

        row, created = svc.get_or_create(
            db,
            sha256=str(artifact.sha256_hash or "").lower(),
            client=inv.client_domain,
            sample_name=artifact.artifact_name,
            sample_size=artifact.size_bytes,
            investigation_id=inv_id,
            artifact_id=artifact.id,
            requested_by="upload",
        )
        analysis_id = str(row.id)
        already = row.status

    if created:
        logger.info("Auto-detonating uploaded sample for investigation %s", investigation_id)
        run_cape_analysis.delay(analysis_id)
        return {"queued": True, "analysis_id": analysis_id}

    logger.info("Upload already has analysis %s (%s); not queueing another", analysis_id, already)
    return {"queued": False, "analysis_id": analysis_id, "reason": "already_exists"}


@celery_app.task(name="app.tasks.cape_task.resume_sandbox_analyses")
def resume_sandbox_analyses() -> dict[str, Any]:
    """Pick up analyses a killed worker left in flight.

    Safe to run repeatedly: an analysis that already has a CAPE task id is
    resumed by polling it, and one that does not is re-driven through the same
    idempotent path — never resubmitted behind the workflow's back.
    """
    settings = get_settings()
    if not settings.cape_configured:
        return {"resumed": 0, "reason": "not_configured"}

    resumed = 0
    with Session(sync_engine) as db:
        candidates = svc.resumable(db)
        stale = [r for r in candidates if svc.is_expired(r)]
        pending = [r for r in candidates if r not in stale]

        for row in stale:
            svc.transition(db, row, svc.STATUS_TIMED_OUT, actor="beat",
                           note="exceeded its polling deadline while unattended",
                           error="Analysis exceeded its maximum polling duration.")

        ids = [str(r.id) for r in pending]

    for analysis_id in ids:
        run_cape_analysis.delay(analysis_id)
        resumed += 1

    if resumed:
        logger.info("Resumed %d in-flight CAPE analyses", resumed)
    return {"resumed": resumed, "timed_out": len(stale)}
