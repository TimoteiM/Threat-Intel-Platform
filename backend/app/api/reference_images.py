"""
Reference image management endpoints.

POST   /api/reference-images/{domain} → Upload a reference screenshot
GET    /api/reference-images/{domain} → Get a reference screenshot
DELETE /api/reference-images/{domain} → Delete a reference screenshot
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import Response

from app.dependencies import Storage

router = APIRouter(prefix="/api/reference-images", tags=["reference-images"])

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_TYPES = {"image/png", "image/jpeg", "image/webp"}


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain for use as a storage key."""
    return re.sub(r"[^a-zA-Z0-9.\-]", "_", domain.lower().strip())


@router.post("/{domain}")
async def upload_reference_image(
    domain: str,
    storage: Storage,
    file: UploadFile = File(...),
):
    """Upload a reference screenshot for a client domain."""
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, f"File type {file.content_type} not allowed. Use PNG, JPEG, or WebP.")

    data = await file.read()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Max {MAX_FILE_SIZE // 1024 // 1024} MB.")

    safe_domain = _sanitize_domain(domain)
    storage_path = await storage.save(
        investigation_id="reference",
        artifact_name=f"{safe_domain}.png",
        data=data,
        content_type=file.content_type,
    )

    return {
        "domain": domain,
        "storage_path": storage_path,
        "size_bytes": len(data),
        "content_type": file.content_type,
    }


@router.get("/{domain}")
async def get_reference_image(domain: str, storage: Storage):
    """Get the reference screenshot for a client domain."""
    safe_domain = _sanitize_domain(domain)

    # Try common extensions
    for ext in ["png", "jpeg", "webp"]:
        path = f"reference/{safe_domain}.{ext}" if hasattr(storage, '_get_path') else None
        # Use the storage backend's path pattern
        try:
            # LocalStorage: ./artifacts/reference/{domain}.png
            from app.storage.local import LocalStorage
            if isinstance(storage, LocalStorage):
                from pathlib import Path
                full_path = storage.base_path / "reference" / f"{safe_domain}.png"
                if full_path.exists():
                    data = await storage.load(str(full_path))
                    return Response(
                        content=data,
                        media_type="image/png",
                        headers={"Cache-Control": "public, max-age=3600"},
                    )
            else:
                # S3Storage
                storage_path = f"reference/{safe_domain}.png"
                if await storage.exists(storage_path):
                    data = await storage.load(storage_path)
                    return Response(
                        content=data,
                        media_type="image/png",
                        headers={"Cache-Control": "public, max-age=3600"},
                    )
        except (FileNotFoundError, Exception):
            continue

    raise HTTPException(404, f"No reference image found for {domain}")


@router.delete("/{domain}")
async def delete_reference_image(domain: str, storage: Storage):
    """Delete the reference screenshot for a client domain."""
    safe_domain = _sanitize_domain(domain)

    try:
        from app.storage.local import LocalStorage
        if isinstance(storage, LocalStorage):
            from pathlib import Path
            full_path = storage.base_path / "reference" / f"{safe_domain}.png"
            if full_path.exists():
                await storage.delete(str(full_path))
                return {"deleted": True, "domain": domain}
        else:
            storage_path = f"reference/{safe_domain}.png"
            if await storage.exists(storage_path):
                await storage.delete(storage_path)
                return {"deleted": True, "domain": domain}
    except Exception:
        pass

    raise HTTPException(404, f"No reference image found for {domain}")
