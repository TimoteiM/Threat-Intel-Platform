"""
Investigation API endpoints.

POST /api/investigations          → Start new investigation
GET  /api/investigations          → List all investigations
GET  /api/investigations/{id}     → Get investigation details
GET  /api/investigations/{id}/evidence  → Get raw evidence
GET  /api/investigations/{id}/report    → Get analyst report
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.dependencies import DBSession
from app.models.schemas import InvestigationCreate
from app.services.investigation_service import InvestigationService

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


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
):
    """List investigations with pagination and optional search/filter."""
    service = InvestigationService(session)
    investigations = await service.list_all(
        limit=limit, offset=offset, state=state, search=search,
    )
    total = await service.count(state=state, search=search)
    return {
        "items": [
            {
                "id": str(inv.id),
                "domain": inv.domain,
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
