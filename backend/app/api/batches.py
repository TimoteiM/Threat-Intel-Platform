"""
Batch Investigation API — bulk domain analysis.

POST /api/batches          — upload CSV/TXT and create batch
GET  /api/batches          — list all batches
GET  /api/batches/{id}     — batch detail with investigations
GET  /api/batches/{id}/campaigns — campaign detection results
"""

from __future__ import annotations

import csv
import io
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.dependencies import DBSession
from app.services.batch_service import BatchService

router = APIRouter(tags=["batches"])


@router.post("/api/batches")
async def create_batch(
    session: DBSession,
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    context: Optional[str] = Form(None),
    client_domain: Optional[str] = Form(None),
):
    """
    Upload a CSV or TXT file of domains and start batch investigation.

    CSV: looks for a 'domain' column, falls back to first column.
    TXT: one domain per line.
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore").strip()

    if not text:
        raise HTTPException(400, "File is empty")

    domains = _parse_domains(text, file.filename or "")

    if not domains:
        raise HTTPException(400, "No valid domains found in file")

    if len(domains) > 500:
        raise HTTPException(400, f"Too many domains ({len(domains)}). Maximum is 500.")

    service = BatchService(session)
    try:
        result = await service.create(
            domains=domains,
            name=name,
            context=context,
            client_domain=client_domain,
        )
        await session.commit()
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/api/batches")
async def list_batches(
    session: DBSession,
    limit: int = 50,
    offset: int = 0,
):
    """List all batches with pagination."""
    service = BatchService(session)
    batches = await service.list_all(limit=limit, offset=offset)
    return [
        {
            "id": str(b.id),
            "name": b.name,
            "total_domains": b.total_domains,
            "completed_count": b.completed_count,
            "status": b.status,
            "created_at": b.created_at.isoformat() if b.created_at else None,
            "completed_at": b.completed_at.isoformat() if b.completed_at else None,
        }
        for b in batches
    ]


@router.get("/api/batches/{batch_id}")
async def get_batch(batch_id: str, session: DBSession):
    """Get batch detail with all investigations."""
    service = BatchService(session)
    result = await service.get_with_investigations(batch_id)
    if not result:
        raise HTTPException(404, "Batch not found")
    return result


@router.get("/api/batches/{batch_id}/campaigns")
async def get_batch_campaigns(batch_id: str, session: DBSession):
    """Detect campaigns (shared infrastructure clusters) within a batch."""
    service = BatchService(session)

    batch = await service.get(batch_id)
    if not batch:
        raise HTTPException(404, "Batch not found")

    return await service.detect_campaigns(batch_id)


def _parse_domains(text: str, filename: str) -> list[str]:
    """Parse domains from CSV or TXT content."""
    domains = []

    if filename.lower().endswith(".csv"):
        # Try CSV parsing
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames or []

        # Look for a domain column
        domain_col = None
        for name in fieldnames:
            if name.lower().strip() in ("domain", "domains", "hostname", "host", "url", "target"):
                domain_col = name
                break

        if not domain_col and fieldnames:
            domain_col = fieldnames[0]

        if domain_col:
            for row in reader:
                val = (row.get(domain_col) or "").strip()
                if val:
                    domains.append(val)
    else:
        # TXT: one domain per line
        for line in text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith("#"):
                # Handle potential CSV without header (comma-separated on one line)
                if "," in line and "\n" not in text[:100]:
                    domains.extend(part.strip() for part in line.split(",") if part.strip())
                else:
                    domains.append(line)

    return domains
