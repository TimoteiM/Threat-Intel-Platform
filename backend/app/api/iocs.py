"""
IOC API — list and export IOCs for an investigation.

GET /api/investigations/{id}/iocs
GET /api/investigations/{id}/iocs/export?format=csv|stix
"""

from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select

from app.dependencies import DBSession
from app.models.database import IOCRecord, Investigation
from app.services.stix_export import build_stix_bundle

router = APIRouter(tags=["iocs"])


@router.get("/api/investigations/{investigation_id}/iocs")
async def list_iocs(investigation_id: str, session: DBSession):
    """List all IOCs extracted for an investigation."""
    inv_id = uuid.UUID(investigation_id)
    result = await session.execute(
        select(IOCRecord).where(IOCRecord.investigation_id == inv_id)
    )
    iocs = result.scalars().all()
    return [
        {
            "id": str(ioc.id),
            "type": ioc.type,
            "value": ioc.value,
            "context": ioc.context,
            "confidence": ioc.confidence,
            "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
        }
        for ioc in iocs
    ]


@router.get("/api/investigations/{investigation_id}/iocs/export")
async def export_iocs(
    investigation_id: str,
    session: DBSession,
    format: str = Query("csv", pattern="^(csv|stix)$"),
):
    """Export IOCs as CSV or STIX 2.1 bundle."""
    inv_id = uuid.UUID(investigation_id)

    # Get investigation detail for STIX metadata
    inv = await session.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")

    result = await session.execute(
        select(IOCRecord).where(IOCRecord.investigation_id == inv_id)
    )
    iocs = result.scalars().all()
    ioc_dicts = [
        {
            "type": ioc.type,
            "value": ioc.value,
            "context": ioc.context,
            "confidence": ioc.confidence,
        }
        for ioc in iocs
    ]

    if format == "stix":
        detail = {
            "domain": inv.domain,
            "classification": inv.classification,
            "id": str(inv.id),
        }
        import json
        bundle = build_stix_bundle(ioc_dicts, detail)
        return Response(
            content=json.dumps(bundle, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{inv.domain}-iocs.stix.json"'
            },
        )
    else:
        output = io.StringIO()
        writer = csv.DictWriter(
            output, fieldnames=["type", "value", "context", "confidence"]
        )
        writer.writeheader()
        for ioc in ioc_dicts:
            writer.writerow(ioc)

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{inv.domain}-iocs.csv"'
            },
        )
