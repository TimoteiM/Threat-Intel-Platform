"""
Investigation API endpoints.

POST /api/investigations               → Start new investigation
POST /api/investigations/upload-file   → Upload file sample for investigation
GET  /api/investigations               → List all investigations
GET  /api/investigations/{id}          → Get investigation details
GET  /api/investigations/{id}/evidence → Get raw evidence
GET  /api/investigations/{id}/report   → Get analyst report
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

import redis as redis_lib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from sqlalchemy import select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import Investigation
from app.models.schemas import InvestigationCreate
from app.services.investigation_service import InvestigationService
from app.tasks.cancellation import find_task_ids, revoke_task_ids

router = APIRouter(prefix="/api/investigations", tags=["investigations"])
settings = get_settings()


@router.post("")
async def create_investigation(request: InvestigationCreate, session: DBSession):
    """Start a new domain investigation."""
    service = InvestigationService(session)
    try:
        result = await service.create(request)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
async def list_investigations(
    session: DBSession,
    limit: int = 10,
    offset: int = 0,
    state: str | None = None,
    search: str | None = None,
    observable_type: str | None = None,
):
    """List investigations with pagination and optional search/filter."""
    service = InvestigationService(session)
    investigations = await service.list_all(
        limit=limit, offset=offset, state=state, search=search,
        observable_type=observable_type,
    )
    total = await service.count(state=state, search=search, observable_type=observable_type)
    return {
        "items": [
            {
                "id": str(inv.id),
                "domain": inv.domain,
                "observable_type": getattr(inv, "observable_type", "domain"),
                "state": inv.state,
                "classification": inv.classification,
                "risk_score": inv.risk_score,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
            }
            for inv in investigations
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{investigation_id}")
async def get_investigation(investigation_id: str, session: DBSession):
    """Get investigation metadata."""
    service = InvestigationService(session)
    inv = await service.get(investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {
        "id": str(inv.id),
        "domain": inv.domain,
        "observable_type": getattr(inv, "observable_type", "domain"),
        "state": inv.state,
        "classification": inv.classification,
        "confidence": inv.confidence,
        "risk_score": inv.risk_score,
        "recommended_action": inv.recommended_action,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "concluded_at": inv.concluded_at.isoformat() if inv.concluded_at else None,
    }


@router.get("/{investigation_id}/evidence")
async def get_evidence(investigation_id: str, session: DBSession):
    """Get collected evidence JSON."""
    service = InvestigationService(session)
    evidence = await service.get_evidence(investigation_id)
    if not evidence:
        raise HTTPException(404, "Evidence not yet collected")
    return evidence


@router.get("/{investigation_id}/report")
async def get_report(investigation_id: str, session: DBSession):
    """Get analyst report."""
    service = InvestigationService(session)
    report = await service.get_report(investigation_id)
    if not report:
        raise HTTPException(404, "Report not yet generated")
    return report


@router.post("/upload-file")
async def upload_file_investigation(
    session: DBSession,
    file: UploadFile = File(...),
    context: str = Form(default=""),
):
    """
    Upload a file sample for fast hash-based analysis.

    Computes SHA-256 and investigates as observable_type='hash' so VT can do a
    direct hash lookup (faster than file submission). The uploaded binary is
    still stored as an artifact for traceability.
    """
    import hashlib
    from app.models.schemas import InvestigationCreate

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(400, "Uploaded file is empty")

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    filename = file.filename or "unknown"

    # Create the investigation via the service (hash-first for speed)
    request = InvestigationCreate(
        domain=sha256,
        observable_type="hash",
        context=context or None,
        requested_collectors=["vt", "hybrid_analysis"],
    )

    service = InvestigationService(session)
    try:
        result = await service.create_file(request, file_bytes, sha256, filename)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{investigation_id}/cancel")
async def cancel_investigation(investigation_id: str, session: DBSession):
    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid investigation id format.") from exc

    inv = (
        (
            await session.execute(
                select(Investigation).where(Investigation.id == parsed_id)
            )
        )
        .scalars()
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    state = str(inv.state or "").lower()
    if state not in {"created", "gathering", "evaluating"}:
        raise HTTPException(status_code=409, detail="Only queued or running investigations can be cancelled.")

    task_ids: list[str] = []
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        tracked = r.get(f"investigation-task:{investigation_id}")
        if tracked:
            task_ids.append(tracked.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    discovered = find_task_ids(
        task_name="tasks.run_investigation",
        kwarg_key="investigation_id",
        kwarg_value=investigation_id,
    )
    for tid in discovered:
        if tid not in task_ids:
            task_ids.append(tid)
    revoked = revoke_task_ids(task_ids)

    inv.state = "cancelled"
    inv.updated_at = datetime.now(timezone.utc)
    inv.concluded_at = datetime.now(timezone.utc)
    await session.commit()

    return {
        "investigation_id": investigation_id,
        "status": "cancelled",
        "revoked_task_ids": revoked,
    }
