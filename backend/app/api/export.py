"""
Export API — download investigation reports in various formats.

GET /api/investigations/{id}/export/pdf
GET /api/investigations/{id}/export/json
GET /api/investigations/{id}/export/markdown
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.dependencies import DBSession
from app.services import report_pdf_cache
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

    # The worker renders this as the investigation concludes, so the usual path
    # is a file read. Rendering here is the fallback for investigations that
    # finished before the cache existed, and for runs whose render failed.
    fingerprint = report_pdf_cache.pdf_fingerprint(evidence, report, detail_dict)
    pdf_bytes = await report_pdf_cache.load_cached_pdf(session, investigation_id, fingerprint)

    if pdf_bytes is None:
        try:
            # Synchronous and slow. Inline on the event loop it stalls *every*
            # request for the duration — one analyst exporting a report made the
            # whole platform stop answering, which read to everyone else as
            # "the tabs won't load".
            pdf_bytes = await asyncio.to_thread(export_pdf, evidence, report, detail_dict)
        except RuntimeError as exc:
            raise HTTPException(500, f"PDF export failed: {exc}") from exc

        if not pdf_bytes.startswith(b"%PDF"):
            raise HTTPException(500, "PDF export produced an invalid file payload.")

        await report_pdf_cache.store_pdf(session, investigation_id, fingerprint, pdf_bytes)

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

    json_bytes = await asyncio.to_thread(export_json, evidence, report, detail_dict)

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

    md_text = await asyncio.to_thread(export_markdown, evidence, report, detail_dict)

    return Response(
        content=md_text.encode("utf-8"),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{detail.domain}-report.md"'
        },
    )
