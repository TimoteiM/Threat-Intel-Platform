"""Email investigation intake endpoints (submit + poll status)."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Path as FastAPIPath, Query, UploadFile
from sqlalchemy import select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import EmailInvestigationRun
from app.tasks.email_investigation_task import run_email_investigation

router = APIRouter(prefix="/api/email-investigations", tags=["email-investigations"])
logger = logging.getLogger(__name__)
settings = get_settings()

_EMAIL_UPLOAD_DIR = (Path(settings.artifact_local_path) / "email-intake").resolve()
_EMAIL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


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
    run_ai: bool = Form(default=True),
    ml_phishing_score: str | None = Form(default=None),
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

    run = EmailInvestigationRun(
        filename=Path(name).name,
        status="queued",
        resolution_source="queued",
        result_json={},
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    file_path = _EMAIL_UPLOAD_DIR / f"{run.id}_{Path(name).name}"
    try:
        file_path.write_bytes(payload)
    except OSError as exc:
        run.status = "failed"
        run.error = f"Could not persist uploaded file: {exc}"
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
            run_ai=run_ai,
            ml_phishing_score=ml_phishing_score,
        )
        run.task_id = task.id
        await db.commit()
    except Exception as exc:
        run.status = "failed"
        run.error = f"Queue dispatch failed: {type(exc).__name__}: {exc}"
        await db.commit()
        logger.exception("Failed to queue email investigation %s", run.id)
        raise HTTPException(status_code=500, detail="Failed to enqueue email investigation.") from exc

    return {
        "run_id": str(run.id),
        "history_id": str(run.id),
        "status": run.status,
        "message": "Email investigation queued.",
    }


@router.get("/history")
async def list_email_investigation_history(
    db: DBSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    try:
        rows = (
            (
                await db.execute(
                    select(EmailInvestigationRun)
                    .order_by(EmailInvestigationRun.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
    except Exception as exc:
        logger.warning("Email history list unavailable: %s", exc)
        return {"items": [], "limit": limit, "offset": offset}
    items = [
        {
            "id": str(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "status": r.status,
            "filename": r.filename,
            "email_subject": r.email_subject,
            "sender_email": r.sender_email,
            "sender_domain": r.sender_domain,
            "sender_ip": r.sender_ip,
            "resolution_source": r.resolution_source,
            "error": r.error,
            "urls_count": int((r.result_json or {}).get("urls_count") or 0),
            "attachments_count": int((r.result_json or {}).get("attachments_count") or 0),
        }
        for r in rows
    ]
    return {"items": items, "limit": limit, "offset": offset}


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

    base = {
        "run_id": str(row.id),
        "history_id": str(row.id),
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "filename": row.filename,
        "email_subject": row.email_subject,
        "sender_email": row.sender_email,
        "sender_domain": row.sender_domain,
        "sender_ip": row.sender_ip,
        "resolution_source": row.resolution_source,
        "error": row.error,
    }

    if row.status == "completed":
        payload = dict(row.result_json or {})
        payload.update(base)
        return payload

    return base
