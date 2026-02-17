"""
Artifact serving endpoint.

GET /api/artifacts/{artifact_id} → Serve stored artifact file (screenshot, etc.)
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.dependencies import DBSession, Storage
from app.models.database import Artifact
from sqlalchemy import select

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


@router.get("/{artifact_id}")
async def get_artifact(artifact_id: str, session: DBSession, storage: Storage):
    """Serve a stored artifact by its ID."""
    try:
        art_uuid = uuid.UUID(artifact_id)
    except ValueError:
        raise HTTPException(400, "Invalid artifact ID")

    result = await session.execute(
        select(Artifact).where(Artifact.id == art_uuid)
    )
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(404, "Artifact not found")

    try:
        data = await storage.load(artifact.storage_path)
    except FileNotFoundError:
        raise HTTPException(404, "Artifact file not found on disk")

    return Response(
        content=data,
        media_type=artifact.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{artifact.artifact_name}"',
            "Cache-Control": "public, max-age=86400",
        },
    )
