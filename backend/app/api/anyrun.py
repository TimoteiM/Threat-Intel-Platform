"""Serving the ANY.RUN sandbox recording for a task.

The vendor URL is public, so the browser could fetch it directly. It comes
through here instead so the file is cached locally for its 24 hours — a report
opened four times fetches 16MB once — and so the analyst can take a copy with a
filename that says what it is rather than "mp4".

The task id is validated as a UUID and the URL is built from a fixed host, so
this cannot be pointed at an arbitrary address. It is additionally required to
be a task this platform actually analysed: without that, the endpoint is an
open proxy for anyone's ANY.RUN recordings, at our bandwidth.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import Text, func, select

from app.dependencies import DBSession
from app.models.database import CollectorResult
from app.services import anyrun_video_cache as cache

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/anyrun", tags=["anyrun"])


async def _is_known_task(db: DBSession, task_id: str) -> bool:
    """Did this platform analyse this task?

    Checked against stored collector evidence rather than trusted from the
    request, so the endpoint serves our own investigations and nothing else.
    """
    found = (
        await db.execute(
            select(func.count())
            .select_from(CollectorResult)
            .where(CollectorResult.evidence_json.cast(Text).like(f"%{task_id}%"))
            .limit(1)
        )
    ).scalar()
    return bool(found)


@router.get("/video/{task_id}")
async def get_anyrun_video(
    task_id: str,
    db: DBSession,
    download: bool = Query(default=False, description="Send as an attachment."),
) -> Any:
    """Stream a task's sandbox recording, caching it locally for 24 hours."""
    if not cache.is_task_id(task_id):
        raise HTTPException(400, "Not an ANY.RUN task id")
    if not await _is_known_task(db, task_id):
        raise HTTPException(404, "No investigation on this platform references that task")

    path = cache.fetch(task_id)
    if path is None:
        raise HTTPException(
            404,
            "ANY.RUN has no recording for this task. Screencasts come from "
            "interactive sessions; URL and domain analyses usually have none.",
        )

    return FileResponse(
        path,
        media_type="video/mp4",
        filename=f"anyrun-{task_id}.mp4" if download else None,
        content_disposition_type="attachment" if download else "inline",
    )
