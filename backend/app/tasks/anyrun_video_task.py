"""Expire cached sandbox recordings.

The cache is a convenience copy of something ANY.RUN still holds — the
permanent URL stays in the report — so deleting it loses nothing that cannot be
fetched again. Without this the directory only grows, and at 16MB a recording
that is a disk filling up slowly enough that nobody notices until it has.
"""

from __future__ import annotations

import logging

from app.services.anyrun_video_cache import VIDEO_TTL_HOURS, purge_expired
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="tasks.purge_anyrun_videos", time_limit=300)
def purge_anyrun_videos() -> dict[str, int]:
    """Delete recordings older than their 24 hours, and dead partial downloads."""
    result = purge_expired(VIDEO_TTL_HOURS)
    if result["removed"]:
        logger.info(
            "expired %d ANY.RUN recording(s), %.1f MB reclaimed",
            result["removed"], result["bytes_freed"] / 1048576,
        )
    return result
