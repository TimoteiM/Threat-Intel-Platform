"""
Export API — download investigation reports in various formats.

GET /api/investigations/{id}/export/pdf
GET /api/investigations/{id}/export/json
GET /api/investigations/{id}/export/markdown
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.dependencies import DBSession
from app.services.investigation_service import InvestigationService
from app.services.export_service import export_pdf, export_json, export_markdown

router = APIRouter(tags=["export"])


@router.get("/api/investigations/{investigation_id}/export/pdf")
async def export_investigation_pdf(investigation_id: str, session: DBSession):
    """Download investigation report as PDF."""
    service = InvestigationService(session)

    detail = await service.get(investigation_id)
    if not detail:
        raise HTTPException(404, "Investigation not found")

    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}

    detail_dict = {
        "id": str(detail.id),
        "domain": detail.domain,
        "state": detail.state,
        "classification": detail.classification,
        "created_at": detail.created_at.isoformat() if detail.created_at else None,
    }

    pdf_bytes = export_pdf(evidence, report, detail_dict)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{detail.domain}-report.pdf"'
        },
    )


@router.get("/api/investigations/{investigation_id}/export/json")
async def export_investigation_json(investigation_id: str, session: DBSession):
    """Download full investigation data as JSON."""
    service = InvestigationService(session)

    detail = await service.get(investigation_id)
    if not detail:
        raise HTTPException(404, "Investigation not found")

    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}

    detail_dict = {
        "id": str(detail.id),
        "domain": detail.domain,
        "state": detail.state,
        "classification": detail.classification,
        "created_at": detail.created_at.isoformat() if detail.created_at else None,
    }

    json_bytes = export_json(evidence, report, detail_dict)

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{detail.domain}-full.json"'
        },
    )


@router.get("/api/investigations/{investigation_id}/export/markdown")
async def export_investigation_md(investigation_id: str, session: DBSession):
    """Download investigation report as Markdown."""
    service = InvestigationService(session)

    detail = await service.get(investigation_id)
    if not detail:
        raise HTTPException(404, "Investigation not found")

    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}

    detail_dict = {
        "id": str(detail.id),
        "domain": detail.domain,
        "state": detail.state,
        "classification": detail.classification,
        "created_at": detail.created_at.isoformat() if detail.created_at else None,
    }

    md_text = export_markdown(evidence, report, detail_dict)

    return Response(
        content=md_text.encode("utf-8"),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{detail.domain}-report.md"'
        },
    )
