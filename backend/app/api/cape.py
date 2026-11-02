"""Sandbox analyses: ask for one, watch it, read the result.

POST   /api/cape/analyses            → submit an eligible sample (analyst+)
GET    /api/cape/analyses            → recent analyses, newest first
GET    /api/cape/analyses/{id}       → status and audit trail
GET    /api/cape/analyses/{id}/result→ the normalized findings
POST   /api/cape/analyses/{id}/retry → re-drive a failed workflow safely
GET    /api/cape/status              → connectivity test (admin only)

No endpoint here returns the CAPE token, the base URL, or any header. The
connectivity test answers reachability, version and machine availability and
nothing else — an administrator needs to know whether it works, not what the
credential is.

Permissions use the two roles this platform actually has. There is no
viewer/auditor role to reuse, and inventing one here would put a second
authorisation model next to the existing one. Read is open to any signed-in
user; submitting and retrying additionally require a human account, because an
API key is an ingest credential and must not be able to detonate files.

Tenant isolation is by the `client` label, the same string Investigation and
AlertBodyInvestigationRun carry. This platform does not bind users to tenants —
there is no such column on `users` — so this filters rather than enforces. That
is a product gap, noted here so the next reader does not mistake the filter for
a boundary.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import AlertBodyInvestigationRun, Artifact, Investigation, SandboxAnalysis
from app.services import cape_analysis_service as svc
from app.services import cape_baseline_service as cape_baseline
from app.api.auth import ROLE_ANALYST, ADMIN_ROLES, has_admin_rights
from app.services import cape_client as cape

# Who may ask for a detonation. Derived from the shared role vocabulary rather
# than a literal tuple, so a new role with admin rights is not silently denied.
SUBMIT_ROLES = tuple(ADMIN_ROLES) + (ROLE_ANALYST,)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cape", tags=["cape"])


class SubmitRequest(BaseModel):
    """What to detonate.

    Deliberately no URL, host or endpoint field of any kind: where CAPE lives
    is administrator configuration, and a request that could name it would make
    this an SSRF gadget.
    """

    artifact_id: str | None = Field(default=None, description="A stored file artifact to detonate.")
    investigation_id: str | None = Field(default=None, description="Attach the analysis to this investigation.")
    alert_run_id: str | None = Field(default=None, description="Attach the analysis to this alert run.")
    sha256: str | None = Field(default=None, min_length=64, max_length=64,
                               description="Required when no artifact is given: look CAPE up by hash.")
    force_new: bool = Field(default=False, description="Detonate again even if an analysis exists.")
    # No URL field. A domain or URL investigation is detonated by naming the
    # investigation; the target comes from the stored observable. Accepting a
    # URL here would let a request choose what the sandbox reaches out to.


@router.get("/status")
async def cape_status(request: Request) -> dict[str, Any]:
    """Is CAPE reachable, and how much of the pool is free. Administrators only."""
    _require_admin(request)
    settings = get_settings()
    if not settings.cape_configured:
        return {
            "configured": False,
            "enabled": bool(settings.cape_enabled),
            "reachable": False,
            "detail": "CAPE is not configured. Set CAPE_ENABLED, CAPE_API_BASE_URL and CAPE_API_TOKEN.",
        }

    def probe() -> dict[str, Any]:
        try:
            with cape.CapeClient(settings=settings) as client:
                status = client.status()
            return {
                "configured": True,
                "enabled": True,
                "reachable": True,
                "version": status.version,
                "machines_total": status.machines_total,
                "machines_available": status.machines_available,
                "tasks": status.tasks,
                "tls_verified": bool(settings.cape_verify_tls),
            }
        except cape.CapeError as exc:
            # redact() has already run inside the exception, but this is the
            # boundary where a message becomes an HTTP body, so it runs again.
            return {
                "configured": True,
                "enabled": bool(settings.cape_enabled),
                "reachable": False,
                "error_kind": type(exc).__name__,
                "detail": cape.redact(str(exc))[:500],
            }

    return await run_in_threadpool(probe)


@router.post("/analyses", status_code=202)
async def submit_analysis(body: SubmitRequest, request: Request, db: DBSession) -> dict[str, Any]:
    """Queue a detonation. Returns immediately — CAPE takes minutes.

    202 rather than 200 on purpose: nothing has been analysed yet, and an API
    that blocked here would hold a worker for the length of a detonation.
    """
    identity = _require_human(request)
    settings = get_settings()
    if not settings.cape_configured:
        raise HTTPException(503, "The CAPE sandbox integration is not configured.")

    artifact: Artifact | None = None
    target_kind = "file"
    target_url: str | None = None
    sha256 = (body.sha256 or "").strip().lower()
    sample_name = None
    sample_size = None
    client_label = None
    investigation_id = _as_uuid(body.investigation_id, "investigation_id")
    alert_run_id = _as_uuid(body.alert_run_id, "alert_run_id")

    if body.artifact_id:
        artifact = (
            await db.execute(select(Artifact).where(Artifact.id == _as_uuid(body.artifact_id, "artifact_id")))
        ).scalars().first()
        if artifact is None:
            raise HTTPException(404, "No such artifact.")
        sha256 = str(artifact.sha256_hash or "").strip().lower()
        sample_name = artifact.artifact_name
        sample_size = artifact.size_bytes
        if investigation_id is None:
            investigation_id = artifact.investigation_id

    # The tenant label, taken from whatever the analysis hangs off. This runs
    # BEFORE the SHA-256 is required, because for a hash investigation the
    # digest is derived from the investigation itself — validating first made
    # that derivation unreachable and rejected every submission from the UI,
    # which sends only an investigation id.
    if investigation_id is not None:
        inv = (await db.execute(select(Investigation).where(Investigation.id == investigation_id))).scalars().first()
        if inv is None:
            raise HTTPException(404, "No such investigation.")
        client_label = inv.client_domain
        sample_name = sample_name or inv.domain
        # An investigation of a hash carries the digest as its observable, so
        # the UI can ask for a detonation with one identifier rather than
        # having to know the hash itself.
        if len(sha256) != 64 and str(inv.observable_type or "") in ("hash", "file"):
            candidate = str(inv.domain or "").strip().lower()
            if len(candidate) == 64:
                sha256 = candidate
        # A domain or URL is detonated by fetching it, not by hashing it. CAPE
        # downloads the page and runs whatever comes back.
        if str(inv.observable_type or "") in ("domain", "url"):
            target_kind = "url"
            target_url = str(inv.domain or "").strip()
    if alert_run_id is not None:
        run = (
            await db.execute(select(AlertBodyInvestigationRun).where(AlertBodyInvestigationRun.id == alert_run_id))
        ).scalars().first()
        if run is None:
            raise HTTPException(404, "No such alert run.")
        client_label = client_label or run.alert_client

    if target_kind == "file" and len(sha256) != 64:
        raise HTTPException(
            400,
            "Nothing to analyse. Supply artifact_id or sha256, or run this against a "
            "file, hash, domain or URL investigation.",
        )

    # The UI submits an investigation id and nothing else, so the uploaded
    # sample has to be found here. Without this every file submission reached
    # the worker with no artifact and failed with "No file is available" —
    # while the file sat on disk the whole time.
    if artifact is None:
        stored = (
            await db.execute(
                select(Artifact)
                .where(Artifact.sha256_hash == sha256, Artifact.collector_name == "upload")
                .order_by(Artifact.created_at.asc())
            )
        ).scalars().all()
        for candidate in stored:
            if _artifact_file(candidate) is not None:
                artifact = candidate
                sample_name = sample_name or candidate.artifact_name
                sample_size = sample_size or candidate.size_bytes
                break

    if sample_size and int(sample_size) > int(settings.cape_max_upload_bytes):
        raise HTTPException(
            413, f"That sample is larger than the {settings.cape_max_upload_bytes} byte submission limit."
        )

    run_seq = 1
    if body.force_new:
        run_seq = await run_in_threadpool(_next_run_seq, sha256, client_label, target_url)

    def create() -> tuple[dict[str, Any], bool]:
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine

        with Session(sync_engine) as sync_db:
            row, created = svc.get_or_create(
                sync_db,
                sha256=sha256 or None,
                target_kind=target_kind,
                target_url=target_url,
                client=client_label,
                sample_name=sample_name,
                sample_size=sample_size,
                investigation_id=investigation_id,
                alert_run_id=alert_run_id,
                artifact_id=artifact.id if artifact else None,
                requested_by=str(identity.get("username") or ""),
                run_seq=run_seq,
            )
            return svc.to_public_dict(row), created

    payload, created = await run_in_threadpool(create)

    if created:
        # Audited: who asked, for what, from where. The durable trail is the
        # row's own state_history; this line is for the operator reading logs.
        logger.info(
            "CAPE submission requested by %s for sha256=%s (analysis %s, client=%s)",
            identity.get("username"), sha256[:16], payload["id"], client_label,
        )
        from app.tasks.cape_task import run_cape_analysis

        run_cape_analysis.delay(payload["id"])
    else:
        logger.info(
            "CAPE submission by %s de-duplicated onto existing analysis %s",
            identity.get("username"), payload["id"],
        )

    payload["created"] = created
    payload["note"] = (
        ("Queued: CAPE will fetch and detonate this URL in an isolated sandbox."
         if target_kind == "url" else
         "Queued for detonation in an isolated sandbox.")
        if created
        else "An analysis for this sample already exists; showing that one."
    )
    return payload


@router.get("/analyses")
async def list_analyses(
    request: Request,
    db: DBSession,
    client: str | None = Query(default=None, description="Filter by tenant label."),
    status: str | None = Query(default=None),
    investigation_id: str | None = Query(default=None),
    alert_run_id: str | None = Query(default=None),
    sha256: str | None = Query(default=None, min_length=64, max_length=64),
    limit: int = Query(default=25, ge=1, le=100),
) -> dict[str, Any]:
    _require_signed_in(request)
    query = select(SandboxAnalysis).order_by(SandboxAnalysis.created_at.desc()).limit(limit)
    if client:
        query = query.where(SandboxAnalysis.client == client)
    if investigation_id:
        query = query.where(SandboxAnalysis.investigation_id == _as_uuid(investigation_id, "investigation_id"))
    if alert_run_id:
        query = query.where(SandboxAnalysis.alert_run_id == _as_uuid(alert_run_id, "alert_run_id"))
    if sha256:
        query = query.where(SandboxAnalysis.sha256 == sha256.strip().lower())
    if status:
        if status not in svc.ALL_STATUSES:
            raise HTTPException(400, f"Unknown status. One of: {', '.join(svc.ALL_STATUSES)}")
        query = query.where(SandboxAnalysis.status == status)
    rows = (await db.execute(query)).scalars().all()
    return {"items": [svc.to_public_dict(r) for r in rows]}


@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, request: Request, db: DBSession) -> dict[str, Any]:
    _require_signed_in(request)
    return svc.to_public_dict(await _load(analysis_id, db))


@router.get("/analyses/{analysis_id}/result")
async def get_analysis_result(analysis_id: str, request: Request, db: DBSession) -> dict[str, Any]:
    """The normalized findings. Empty until the analysis reaches `reported`."""
    _require_signed_in(request)
    row = await _load(analysis_id, db)
    payload = svc.to_public_dict(row)
    # Labelled on the way out, not on the way in: every analysis already
    # stored gains the sandbox/sample distinction without being re-detonated.
    payload["result"] = await cape_baseline.annotate(db, dict(row.normalized_json or {})) or None
    payload["available"] = row.status == svc.STATUS_REPORTED and bool(row.normalized_json)
    # Guest-image limitations travel with the result, not just the request, so
    # an empty PDF report is never read as "nothing happened".
    result_limits = list((row.normalized_json or {}).get("limitations") or [])
    payload["limitations"] = list(dict.fromkeys(payload["limitations"] + result_limits))
    return payload


@router.post("/analyses/{analysis_id}/retry")
async def retry_analysis(analysis_id: str, request: Request, db: DBSession) -> dict[str, Any]:
    """Re-drive a workflow that failed. Never a blind resubmission.

    A retry resumes from whatever the analysis already knows: if a CAPE task id
    was recorded, it is polled again rather than the sample being detonated a
    second time.
    """
    identity = _require_human(request)
    row = await _load(analysis_id, db)
    if row.status not in svc.RETRYABLE_STATUSES:
        raise HTTPException(
            409,
            f"An analysis in '{row.status}' cannot be retried. "
            "Submit again with force_new to run a fresh detonation.",
        )

    def restart() -> dict[str, Any]:
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from datetime import datetime, timedelta, timezone

        settings = get_settings()
        with Session(sync_engine) as sync_db:
            locked = svc.claim_for_work(sync_db, row.id)
            if locked is None:
                raise HTTPException(404, "No such analysis.")
            locked.error = None
            locked.completed_at = None
            locked.deadline_at = datetime.now(timezone.utc) + timedelta(
                seconds=int(settings.cape_max_poll_duration_seconds)
            )
            svc.transition(
                sync_db, locked, svc.STATUS_QUEUED,
                actor=str(identity.get("username") or "unknown"), note="retry requested",
            )
            return svc.to_public_dict(locked)

    payload = await run_in_threadpool(restart)
    logger.info("CAPE analysis %s retried by %s", analysis_id, identity.get("username"))

    from app.tasks.cape_task import run_cape_analysis

    run_cape_analysis.delay(str(row.id))
    return payload


# ── helpers ──────────────────────────────────────────────────────────────────


def _next_run_seq(sha256: str | None, client: str | None, target_url: str | None = None) -> int:
    from sqlalchemy.orm import Session
    from app.db.session import sync_engine
    from sqlalchemy import func

    with Session(sync_engine) as db:
        query = select(func.max(SandboxAnalysis.run_seq)).where(
            SandboxAnalysis.client == client,
            SandboxAnalysis.provider == svc.PROVIDER_CAPE,
        )
        if target_url:
            query = query.where(SandboxAnalysis.target_url == svc.normalise_url(target_url))
        else:
            query = query.where(SandboxAnalysis.sha256 == sha256)
        highest = db.execute(query).scalar()
    return int(highest or 0) + 1


async def _load(analysis_id: str, db: DBSession) -> SandboxAnalysis:
    row = (
        await db.execute(select(SandboxAnalysis).where(SandboxAnalysis.id == _as_uuid(analysis_id, "analysis_id")))
    ).scalars().first()
    if row is None:
        raise HTTPException(404, "No such analysis.")
    return row


def _artifact_file(artifact: Artifact):
    """The artifact's file on disk, or None when it is no longer retained.

    Most historical uploads have been swept by the retention policy, so an
    artifact row is not evidence that a sample still exists.
    """
    from pathlib import Path

    path = Path(str(artifact.storage_path or "")).expanduser()
    if not path.is_absolute():
        path = Path("/app") / path
    return path if path.exists() and path.is_file() else None


def _as_uuid(value: str | None, field: str) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError as exc:
        raise HTTPException(400, f"Invalid {field}.") from exc


def _require_signed_in(request: Request) -> dict[str, Any]:
    identity = getattr(request.state, "identity", None)
    if not identity:
        raise HTTPException(401, "Sign in first.")
    return identity


def _require_human(request: Request) -> dict[str, Any]:
    """A person, not an ingest key.

    The alert ingest credential reaches this API by design; it must not be able
    to detonate files. Submitting is an analyst action with a name attached.
    """
    identity = _require_signed_in(request)
    if identity.get("kind") != "user":
        raise HTTPException(403, "Sandbox submission requires a signed-in user account.")
    if str(identity.get("role") or "") not in SUBMIT_ROLES:
        raise HTTPException(403, "Your role may not submit samples to the sandbox.")
    return identity


def _require_admin(request: Request) -> dict[str, Any]:
    identity = _require_signed_in(request)
    if identity.get("kind") != "user" or not has_admin_rights(identity.get("role")):
        raise HTTPException(403, "Administrator access is required.")
    return identity
