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
        db.commit()

    request_id = uuid.uuid4().hex[:12]
    try:
        with cape.CapeClient(settings=settings, request_id=request_id) as client:
            if not task_id:
                task_id = _obtain_task(client, analysis_uuid, sha256, artifact_id, sample_name, settings)
            if task_id is None:
                return {"analysis_id": analysis_id, "status": svc.STATUS_FAILED}
            return _poll_and_store(client, analysis_uuid, task_id, settings)

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
    sha256: str,
    artifact_id: uuid.UUID | None,
    sample_name: str | None,
    settings,
) -> str | None:
    """Adopt an existing CAPE analysis, or submit the file. Never both."""
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
    report = client.fetch_report(task_id, formats=settings.cape_report_format_list)
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
    """Surface the detonation where the analyst is already looking.

    Deliberately additive: the sandbox does not overwrite a classification or
    drive an action. A score is evidence for a person, and this platform does
    not contain or remediate on the strength of one detonation.
    """
    if investigation_id is None:
        return
    try:
        with Session(sync_engine) as db:
            inv = db.get(Investigation, investigation_id)
            if inv is None:
                return
            inv.updated_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — annotation must not fail the analysis
        logger.warning("Could not annotate investigation %s after CAPE: %s", investigation_id, exc)


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


def _fail(analysis_id: uuid.UUID, headline: str, exc: Exception) -> None:
    """Record a failure with the secret scrubbed out of the message."""
    message = cape.redact(f"{headline}: {exc}")
    logger.error("CAPE analysis %s failed — %s", analysis_id, message)
    _terminal(analysis_id, svc.STATUS_FAILED, error=message, note=headline)


# ── resume after a restart ───────────────────────────────────────────────────


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
