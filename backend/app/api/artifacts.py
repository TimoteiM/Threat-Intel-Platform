"""
Artifact serving endpoint.

GET /api/artifacts/{artifact_id} → Serve stored artifact file (screenshot, etc.)
"""

from __future__ import annotations

import mimetypes
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.dependencies import DBSession, Storage
from app.models.database import Artifact
from sqlalchemy import select

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


def _resolve_artifact_content_type(content_type: str | None, artifact_name: str) -> str:
    """Best-effort MIME resolution for legacy artifacts saved with generic type."""
    current = (content_type or "").strip().lower()
    if current and current != "application/octet-stream":
        return content_type or current

    name = (artifact_name or "").lower()
    guessed: str | None = None
    if name.endswith("_png"):
        guessed = "image/png"
    elif name.endswith("_jpg") or name.endswith("_jpeg"):
        guessed = "image/jpeg"
    elif name.endswith("_json"):
        guessed = "application/json"
    elif name.endswith("_html"):
        guessed = "text/html"
    else:
        guessed, _ = mimetypes.guess_type(name)
    return guessed or "application/octet-stream"


def _ensure_filename_extension(filename: str, content_type: str) -> str:
    """Ensure download filename has a useful extension when source name has none."""
    name = (filename or "artifact").strip()
    if "." in name.rsplit("/", 1)[-1]:
        return name

    ext = mimetypes.guess_extension(content_type or "")
    if not ext:
        ext = ".bin"
    return f"{name}{ext}"


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

    resolved_type = _resolve_artifact_content_type(artifact.content_type, artifact.artifact_name)
    download_name = _ensure_filename_extension(artifact.artifact_name, resolved_type)

    return Response(
        content=data,
        media_type=resolved_type,
        headers={
            "Content-Disposition": f'inline; filename="{download_name}"',
            "Cache-Control": "public, max-age=86400",
        },
    )
