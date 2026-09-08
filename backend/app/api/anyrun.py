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
from sqlalchemy import select

from app.dependencies import DBSession
from app.models.database import Investigation
from app.services import anyrun_video_cache as cache

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/anyrun", tags=["anyrun"])


async def _is_known_task(db: DBSession, task_id: str) -> bool:
    """Did this platform analyse this task?

    Answered from the indexed column, not by searching evidence documents. The
    first version ran `evidence_json::text LIKE '%<id>%'` across every collector
    result — an unindexable scan over the largest column in the schema, on every
    request. It cost about seven seconds before a single byte of video moved,
    which is most of why the player felt slow: a one-megabyte range request took
    as long as the whole file, because the time was not in the transfer.

    `sandbox_video_task_id` is set at conclusion only after a recording is
    confirmed, and is partially indexed, so this is the same question asked of
    the answer rather than of the haystack.
    """
    found = (
        await db.execute(
            select(Investigation.id)
            .where(Investigation.sandbox_video_task_id == task_id)
            .limit(1)
        )
    ).scalar_one_or_none()
    return found is not None


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
