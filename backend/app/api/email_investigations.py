"""Email investigation intake endpoints (submit + poll status)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    Path as FastAPIPath,
    Query,
    Request,
    UploadFile,
)
from sqlalchemy import func, or_, select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import EmailInvestigationRun
from app.tasks.cancellation import find_task_ids, revoke_task_ids
from app.tasks.email_investigation_task import run_email_investigation

router = APIRouter(prefix="/api/email-investigations", tags=["email-investigations"])
logger = logging.getLogger(__name__)
settings = get_settings()

_EMAIL_UPLOAD_DIR = (Path(settings.artifact_local_path) / "email-intake").resolve()
_EMAIL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _history_verdict_from_result(result_json: dict[str, Any] | None) -> str:
    payload = result_json or {}
    resolution = payload.get("resolution") or {}
    verdict = (
        resolution.get("overall_verdict")
        or resolution.get("classification")
        or (resolution.get("conclusion") or {}).get("classification")
        or "unknown"
    )
    return str(verdict).strip().lower() or "unknown"


@router.get("/upload")
async def email_upload_info() -> dict[str, Any]:
    return {
        "message": "Use POST multipart/form-data with field 'file' (.eml or .msg).",
        "supported_methods": ["POST"],
        "endpoint": "/api/email-investigations/upload",
    }


@router.post("/upload")
async def upload_email_investigation(
    db: DBSession,
    file: UploadFile = File(...),
    context: str = Form(default=""),
    max_urls: int = Form(default=20),
    max_attachment_hashes: int = Form(default=5),
    include_url_screenshots: bool = Form(default=False),
    run_anyrun: bool = Form(default=False),
    run_ai: bool = Form(default=True),
    ml_phishing_score: str | None = Form(default=None),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    name = (file.filename or "").strip()
    lowered = name.lower()
    if not (lowered.endswith(".eml") or lowered.endswith(".msg")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Supported types: .eml, .msg",
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded email file is empty.")

    # Captured here because here is where it exists. The endpoint has a
    # session and was throwing the actor away, so every run became
    # permanently unattributable — and attributing a submission is only
    # possible at submission.
    from app.services import actor_attribution

    run = EmailInvestigationRun(
        filename=Path(name).name,
        resolution_source="queued",
        result_json={"status": "queued", "error": None},
        **await actor_attribution.resolve(request, db),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    file_path = _EMAIL_UPLOAD_DIR / f"{run.id}_{Path(name).name}"
    try:
        file_path.write_bytes(payload)
    except OSError as exc:
        run.result_json = {
            **(run.result_json or {}),
            "status": "failed",
            "error": f"Could not persist uploaded file: {exc}",
        }
        await db.commit()
        raise HTTPException(status_code=500, detail="Failed to stage uploaded file.") from exc

    try:
        task = run_email_investigation.delay(
            str(run.id),
            str(file_path),
            context=context,
            max_urls=max_urls,
            max_attachment_hashes=max_attachment_hashes,
            include_url_screenshots=include_url_screenshots,
            run_anyrun=run_anyrun,
            run_ai=run_ai,
            ml_phishing_score=ml_phishing_score,
        )
        run.result_json = {
            **(run.result_json or {}),
            "status": "queued",
            "task_id": task.id,
        }
        await db.commit()
    except Exception as exc:
        run.result_json = {
            **(run.result_json or {}),
            "status": "failed",
            "error": f"Queue dispatch failed: {type(exc).__name__}: {exc}",
        }
        await db.commit()
        logger.exception("Failed to queue email investigation %s", run.id)
        raise HTTPException(status_code=500, detail="Failed to enqueue email investigation.") from exc

    return {
        "run_id": str(run.id),
        "history_id": str(run.id),
        "status": str((run.result_json or {}).get("status") or "queued"),
        "message": "Email investigation queued.",
    }


@router.get("/history")
async def list_email_investigation_history(
    db: DBSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
    classification: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        normalized_search = (search or "").strip()
        normalized_classification = (classification or "").strip().lower()
        filters = []
        if normalized_search:
            pattern = f"%{normalized_search}%"
            filters.append(
                or_(
                    EmailInvestigationRun.filename.ilike(pattern),
                    EmailInvestigationRun.email_subject.ilike(pattern),
                    EmailInvestigationRun.sender_email.ilike(pattern),
                    EmailInvestigationRun.sender_domain.ilike(pattern),
                )
            )
        if normalized_classification:
            filters.append(
                func.lower(
                    func.coalesce(
                        EmailInvestigationRun.result_json["resolution"]["overall_verdict"].astext,
                        EmailInvestigationRun.result_json["resolution"]["classification"].astext,
                        "unknown",
                    )
                ) == normalized_classification
            )

        query = select(EmailInvestigationRun)
        count_query = select(func.count(EmailInvestigationRun.id))
        for clause in filters:
            query = query.where(clause)
            count_query = count_query.where(clause)

        rows = (
            (
                await db.execute(
                    query
                    .order_by(EmailInvestigationRun.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        total = int((await db.execute(count_query)).scalar() or 0)
    except Exception as exc:
        logger.warning("Email history list unavailable: %s", exc)
        return {"items": [], "total": 0, "limit": limit, "offset": offset}
    items = [
        {
            "id": str(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "completed_at": (r.result_json or {}).get("completed_at"),
            "status": str((r.result_json or {}).get("status") or "queued"),
            "filename": r.filename,
            "email_subject": r.email_subject,
            "sender_email": r.sender_email,
            "sender_domain": r.sender_domain,
            "sender_ip": r.sender_ip,
            "resolution_source": r.resolution_source,
            "classification": _history_verdict_from_result(r.result_json),
            "error": (r.result_json or {}).get("error"),
            "urls_count": int((r.result_json or {}).get("urls_count") or 0),
            "attachments_count": int((r.result_json or {}).get("attachments_count") or 0),
        }
        for r in rows
    ]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/history/{run_id}")
async def get_email_investigation_history_item(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    return await get_email_investigation_run(db=db, run_id=run_id)


@router.get("/{run_id}")
async def get_email_investigation_run(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid run id format.") from exc

    row = (
        (
            await db.execute(
                select(EmailInvestigationRun).where(EmailInvestigationRun.id == parsed_id)
            )
        )
        .scalars()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Email investigation run not found.")

    row_result = dict(row.result_json or {})
    run_status = str(row_result.get("status") or "queued")
    base = {
        "run_id": str(row.id),
        "history_id": str(row.id),
        "status": run_status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row_result.get("completed_at"),
        "filename": row.filename,
        "email_subject": row.email_subject,
        "sender_email": row.sender_email,
        "sender_domain": row.sender_domain,
        "sender_ip": row.sender_ip,
        "resolution_source": row.resolution_source,
        "error": row_result.get("error"),
    }

    if run_status == "completed":
        payload = row_result
        payload.update(base)
        return payload

    return base


#: How many indicators one request will ask the estate about. Each hit costs
#: two extra aggregations (first/last seen, and the collection floor), so the
#: cost is per *hit* and not per indicator — 7 indicators on run 113 with 2
#: hits took 168 ms concurrently. The cap is a bound on a pathological
#: message (a newsletter with 400 links), and when it bites the response says
#: so: a silently truncated indicator list reads as "the estate was asked
#: about everything", which is the one thing this endpoint must not imply.
_ESTATE_INDICATOR_CAP = 40


def _estate_indicators(result: dict[str, Any]) -> list[dict[str, str]]:
    """The observables from a parsed email that the estate can be asked about.

    Domains and addresses only. URLs are deliberately not included: this
    estate has no proxy logs, so a URL has no field to answer it, and
    `lookup()` returns `out_of_scope` rather than a zero.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    def add(value: Any, kind: str, origin: str) -> None:
        text = str(value or "").strip().lower()
        if not text or (text, kind) in seen:
            return
        seen.add((text, kind))
        out.append({"value": text, "kind": kind, "origin": origin})

    add(result.get("sender_domain"), "domain", "sender domain")
    add(result.get("sender_ip"), "ip", "sending address from the Received chain")
    for domain in (result.get("url_domains") or []):
        add(domain, "domain", "domain of a link in the body")
    return out


@router.get("/{run_id}/estate-dns")
async def email_investigation_estate_dns(
    db: DBSession,
    run_id: str = FastAPIPath(...),
    tenant_id: str = Query(..., min_length=1),
    days: int = Query(default=7, ge=1, le=120),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Did anything in this customer's estate resolve the names in this email?

    Two questions, never merged, each with its own named absence — see
    `estate_lookup_service`. A hit is only half an answer: the half an analyst
    acts on is *when* it was first resolved relative to the email's arrival,
    and that comparison is withheld unless a trustworthy arrival time exists.

    `tenant_id` is required and is not inferred. `email_investigation_runs`
    carries no tenant column, so the run cannot name its own customer; a
    guessed tenant here would run one customer's indicators against another's
    logs. The scope check rejects a tenant the caller may not read with a 404,
    not a 403, so the endpoint does not confirm that the tenant exists.
    """
    import asyncio

    from app.services import absence, email_anchor, estate_lookup_service, tenant_scope

    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid run id format.") from exc

    row = (
        await db.execute(
            select(EmailInvestigationRun).where(EmailInvestigationRun.id == parsed_id)
        )
    ).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Email investigation run not found.")

    # Scope first, before the run's contents are touched. `assert_can_read`
    # raises 404 rather than 403 on purpose: a 403 confirms the tenant exists.
    identity = getattr(getattr(request, "state", None), "identity", None)
    tenant_scope.assert_can_read(tenant_scope.scope_of(identity), tenant_id)

    result = dict(row.result_json or {})
    indicators = _estate_indicators(result)
    dropped = max(0, len(indicators) - _ESTATE_INDICATOR_CAP)
    indicators = indicators[:_ESTATE_INDICATOR_CAP]

    # The baseline, before any lookup. Resolved at parse time and stored,
    # because the Received chain is not retained and cannot be re-read.
    stored = result.get("arrival")
    baseline: dict[str, Any]
    reference_time = None
    reference_anchor = None
    if absence.is_absent(stored):
        baseline = {"resolved": False, "absence": stored}
    elif isinstance(stored, dict) and stored.get("at"):
        try:
            reference_time = datetime.fromisoformat(str(stored["at"]))
        except ValueError:
            reference_time = None
        if reference_time is not None:
            reference_anchor = email_anchor.anchor_statement(stored)
        baseline = {
            "resolved": reference_time is not None and bool(reference_anchor),
            "anchor": stored.get("anchor"),
            "at": stored.get("at"),
            "statement": stored.get("statement"),
            "written_by": stored.get("written_by"),
            "sender_date_disagrees": stored.get("sender_date_disagrees"),
        }
    else:
        # A run parsed before the anchor existed. Not an error and not a
        # fallback to its upload time: `created_at` is when an analyst opened
        # the investigation, which is later than arrival for every
        # retrospectively reported message.
        baseline = {
            "resolved": False,
            "absence": absence.absent(
                absence.CHECK_FAILED,
                "This run was parsed before an arrival time was extracted, "
                "and the Received chain is not retained, so when the message "
                "arrived cannot be recovered. The run's own timestamp is its "
                "upload time, which is not when the email arrived.",
            ).as_json(),
        }

    if not baseline["resolved"]:
        reference_time, reference_anchor = None, None

    client = estate_lookup_service.estate_client_for(tenant_id)

    def _one(indicator: dict[str, str]) -> dict[str, Any]:
        answer = estate_lookup_service.lookup(
            indicator["value"], kind=indicator["kind"], tenant_id=tenant_id,
            days=days, client=client,
            reference_time=reference_time, reference_anchor=reference_anchor,
        )
        answer["origin"] = indicator["origin"]
        return answer

    # Concurrent because the per-indicator latency is network-bound and the
    # cluster handles them independently; `to_thread` because the estate
    # client is the synchronous OpenSearch adapter.
    answers = await asyncio.gather(
        *(asyncio.to_thread(_one, indicator) for indicator in indicators)
    ) if indicators else []

    return {
        "run_id": str(row.id),
        "tenant_id": tenant_id,
        "window_days": days,
        "baseline": baseline,
        "indicators": list(answers),
        "indicator_count": len(answers),
        # Stated, not silent. See `_ESTATE_INDICATOR_CAP`.
        "indicators_not_asked": dropped,
        "cap": _ESTATE_INDICATOR_CAP,
        "comparison_available": bool(reference_anchor),
    }


@router.post("/{run_id}/cancel")
async def cancel_email_investigation_run(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid run id format.") from exc

    row = (
        (
            await db.execute(
                select(EmailInvestigationRun).where(EmailInvestigationRun.id == parsed_id)
            )
        )
        .scalars()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Email investigation run not found.")

    row_result = dict(row.result_json or {})
    status = str(row_result.get("status") or "queued").lower()
    if status not in {"queued", "processing", "running"}:
        raise HTTPException(status_code=409, detail="Only queued or running investigations can be cancelled.")

    task_ids: list[str] = []
    known = str(row_result.get("task_id") or "").strip()
    if known:
        task_ids.append(known)

    discovered = find_task_ids(
        task_name="tasks.run_email_investigation",
        first_arg_value=run_id,
    )
    for tid in discovered:
        if tid not in task_ids:
            task_ids.append(tid)
    revoked = revoke_task_ids(task_ids)

    row.result_json = {
        **row_result,
        "status": "cancelled",
        "error": "Cancelled by user",
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.commit()

    return {
        "run_id": str(row.id),
        "status": "cancelled",
        "revoked_task_ids": revoked,
    }
