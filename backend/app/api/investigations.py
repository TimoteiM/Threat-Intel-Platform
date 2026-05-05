"""
Investigation API endpoints.

POST /api/investigations                          → Start new investigation
POST /api/investigations/upload-file              → Upload file sample for investigation
GET  /api/investigations                          → List all investigations
GET  /api/investigations/{id}                     → Get investigation details
GET  /api/investigations/{id}/evidence            → Get raw evidence
GET  /api/investigations/{id}/report              → Get analyst report
POST /api/investigations/{id}/rerun-collector     → Re-run a single collector and merge result
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any
import uuid

import redis as redis_lib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.dependencies import DBSession
from app.models.database import Investigation, Evidence
from app.models.schemas import InvestigationCreate
from app.services.investigation_service import InvestigationService
from app.services.investigation_intelligence import build_investigation_intelligence
from app.tasks.cancellation import find_task_ids, revoke_task_ids
from app.services.hybrid_analysis_service import evict_anyrun_cache
from app.collectors.registry import get_collector, get_collectors_for_type

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
    classification: str | None = None,
    dedupe: bool = False,
):
    """List investigations with pagination and optional search/filter."""
    service = InvestigationService(session)
    investigations = await service.list_all(
        limit=limit, offset=offset, state=state, search=search,
        observable_type=observable_type,
        classification=classification,
        dedupe=dedupe,
    )
    total = await service.count(
        state=state,
        search=search,
        observable_type=observable_type,
        classification=classification,
        dedupe=dedupe,
    )
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


@router.get("/{investigation_id}/intelligence")
async def get_intelligence(investigation_id: str, session: DBSession):
    """Get derived SOC intelligence for timeline, graph, IOC quality, and reporting."""
    service = InvestigationService(session)
    detail = await service.get(investigation_id)
    if not detail:
        raise HTTPException(404, "Investigation not found")

    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}
    detail_dict = {
        "id": str(detail.id),
        "domain": detail.domain,
        "observable_type": getattr(detail, "observable_type", "domain"),
        "state": detail.state,
        "classification": detail.classification,
        "confidence": detail.confidence,
        "risk_score": detail.risk_score,
        "recommended_action": detail.recommended_action,
        "client_domain": detail.client_domain,
        "created_at": detail.created_at.isoformat() if detail.created_at else None,
        "updated_at": detail.updated_at.isoformat() if detail.updated_at else None,
        "concluded_at": detail.concluded_at.isoformat() if detail.concluded_at else None,
    }
    return build_investigation_intelligence(evidence=evidence, report=report, detail=detail_dict)


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


class RerunCollectorRequest(BaseModel):
    collector: str


@router.post("/{investigation_id}/rerun-collector")
async def rerun_collector(
    investigation_id: str,
    body: RerunCollectorRequest,
    session: DBSession,
):
    """Re-run a single collector for an existing investigation and merge the result."""
    import asyncio

    collector_name = body.collector.strip().lower()

    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid investigation id format.") from exc

    collector_cls = get_collector(collector_name)
    if not collector_cls:
        raise HTTPException(status_code=400, detail=f"Unknown collector: {collector_name!r}")

    result = await session.execute(
        select(Investigation).where(Investigation.id == parsed_id)
    )
    inv = result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    state = str(inv.state or "").lower()
    if state not in {"concluded", "failed"}:
        raise HTTPException(
            status_code=409,
            detail="Can only re-run collectors on concluded or failed investigations.",
        )

    observable_type = str(inv.observable_type or "domain").strip()
    if observable_type not in collector_cls.supported_types:
        raise HTTPException(
            status_code=422,
            detail=f"Collector {collector_name!r} does not support observable type {observable_type!r}.",
        )

    domain = str(inv.domain or "").strip()

    # AnyRun (hybrid_analysis) needs both cache layers evicted before re-submission
    if collector_name == "hybrid_analysis":
        indicator_type = "hash" if observable_type in {"hash", "file"} else "url"
        indicator = domain if observable_type in {"hash", "file"} else (
            f"https://{domain}" if observable_type == "domain" else domain
        )
        await asyncio.get_event_loop().run_in_executor(
            None, evict_anyrun_cache, indicator, indicator_type
        )

    def _run_in_background():
        try:
            collector = collector_cls(
                domain=domain,
                investigation_id=investigation_id,
                observable_type=observable_type,
                timeout=settings.collector_timeout,
            )
            evidence, meta, _ = collector.run()
            result_dict: dict[str, Any] = {
                "collector": collector_name,
                "status": meta.status.value,
                "evidence": evidence.model_dump(mode="json"),
                "meta": meta.model_dump(mode="json"),
            }
        except Exception as exc:
            result_dict = {
                "collector": collector_name,
                "status": "failed",
                "evidence": {},
                "meta": {"error": str(exc)},
            }

        # Merge result into evidence_json
        try:
            inv_id = uuid.UUID(investigation_id)
            with Session(sync_engine) as db:
                inv_row = db.get(Investigation, inv_id)
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
                    existing[collector_name] = result_dict["evidence"]
                    ev_row.evidence_json = existing
                    if inv_row:
                        inv_row.updated_at = datetime.now(timezone.utc)
                    db.commit()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "rerun-collector: failed to persist %s result: %s", collector_name, exc
            )
            return

        # Notify frontend via SSE
        try:
            r = redis_lib.Redis.from_url(settings.redis_url)
            r.publish(
                f"investigation:{investigation_id}",
                json.dumps({
                    "type": "evidence_updated",
                    "investigation_id": investigation_id,
                    "collector": collector_name,
                    "message": f"{collector_name} re-run complete — evidence updated",
                }),
            )
        except Exception:
            pass

    t = threading.Thread(
        target=_run_in_background,
        daemon=True,
        name=f"rerun-{collector_name}-{investigation_id[:8]}",
    )
    t.start()

    return {"investigation_id": investigation_id, "collector": collector_name, "status": "rerun_started"}
