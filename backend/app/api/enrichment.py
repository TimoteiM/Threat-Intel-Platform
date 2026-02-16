"""
Enrichment API — add external intelligence to an investigation.

POST /api/investigations/{id}/enrich

Accepts OpenCTI observables, Flare findings, SOC ticket notes.
Triggers re-analysis with the merged context.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import DBSession
from app.models.schemas import EnrichRequest
from app.db.repository import EvidenceRepository, InvestigationRepository

router = APIRouter(tags=["enrichment"])


@router.post("/api/investigations/{investigation_id}/enrich")
async def enrich_investigation(
    investigation_id: str,
    request: EnrichRequest,
    session: DBSession,
):
    """
    Add external intelligence context to an investigation.
    Merges CTI with existing evidence for re-analysis.
    """
    import uuid

    inv_repo = InvestigationRepository(session)
    ev_repo = EvidenceRepository(session)

    inv = await inv_repo.get(uuid.UUID(investigation_id))
    if not inv:
        raise HTTPException(404, "Investigation not found")

    evidence = await ev_repo.get(uuid.UUID(investigation_id))
    if not evidence:
        raise HTTPException(404, "No evidence collected yet — cannot enrich")

    # Merge external context into evidence
    existing_context = evidence.external_context or {}
    merged = {
        "opencti_observables": (
            existing_context.get("opencti_observables", [])
            + request.opencti_observables
        ),
        "flare_findings": (
            existing_context.get("flare_findings", [])
            + request.flare_findings
        ),
        "soc_ticket_notes": request.soc_ticket_notes or existing_context.get("soc_ticket_notes"),
        "additional_context": request.additional_context or existing_context.get("additional_context"),
    }
    evidence.external_context = merged

    await session.flush()

    # TODO: Trigger re-analysis task with updated evidence
    # For now, just persist the enrichment

    return {
        "status": "enriched",
        "investigation_id": investigation_id,
        "message": "External context added. Re-analysis can be triggered.",
    }
