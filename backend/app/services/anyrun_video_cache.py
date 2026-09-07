"""The sandbox screencast, kept locally for a day.

ANY.RUN serves the recording from a public URL, so a browser could play it
straight from content.any.run without this. Two reasons it is cached here
instead: the recording is large — the one stored task's video is 16 MB — and a
report that is opened repeatedly should not re-fetch it every time; and an
analyst who wants the file on their own machine should be able to take it
without leaving the investigation.

Fetched lazily, on the first request for it, rather than at analysis time.
Video is present on 1 of 99 measured tasks and most reports are never opened,
so downloading eagerly would spend bandwidth and disk on recordings nobody
watches.

Kept for 24 hours. It is a convenience copy of something the vendor still
holds, not evidence — the permanent URL is recorded in the report either way,
so expiring the file loses nothing that cannot be fetched again.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

import requests

from app.config import get_settings

logger = logging.getLogger(__name__)

VIDEO_TTL_HOURS = 24
CACHE_DIRNAME = "anyrun-video"

# A hard ceiling on what will be written to disk. ANY.RUN does not promise a
# size, and an unbounded stream to a local path is how a disk fills up quietly.
MAX_VIDEO_BYTES = 512 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 180
CHUNK_BYTES = 1024 * 256

_TASK_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def is_task_id(value: str) -> bool:
    """ANY.RUN task ids are UUIDs. Anything else is not addressed to us.

    Deliberately strict rather than lenient: an earlier version stripped
    whitespace before matching, while video_url() and cached_path() went on to
    use the value it was handed. So "<uuid> " validated and then built a URL
    and a filename with a trailing space in them. What is checked has to be
    exactly what is used, or the check is about a different string.
    """
    return bool(_TASK_ID.match(str(value or "")))


def video_url(task_id: str) -> str:
    """The vendor URL for a task's recording.

    Built from a fixed host and a validated id rather than taken from a caller,
    so this endpoint cannot be pointed at an arbitrary address.
    """
    return f"https://content.any.run/tasks/{task_id}/download/mp4"


def cache_dir() -> Path:
    return Path(get_settings().artifact_local_path) / CACHE_DIRNAME


def cached_path(task_id: str) -> Path:
    return cache_dir() / f"{task_id}.mp4"


def cached_if_fresh(task_id: str) -> Path | None:
    """The local copy, if one exists and is inside its 24 hours."""
    path = cached_path(task_id)
    try:
        if not path.is_file():
            return None
        age_hours = (time.time() - path.stat().st_mtime) / 3600
        if age_hours > VIDEO_TTL_HOURS:
            return None
        return path
    except OSError:
        return None


def fetch(task_id: str) -> Path | None:
    """Download the recording to the cache, returning its path.

    Written to a temporary name and renamed on completion, so a request that
    dies mid-download cannot leave a truncated file that later looks cached and
    plays as a corrupt video.
    """
    if not is_task_id(task_id):
        return None
    fresh = cached_if_fresh(task_id)
    if fresh is not None:
        return fresh

    directory = cache_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = cached_path(task_id)
    partial = target.with_suffix(".mp4.part")

    try:
        with requests.get(
            video_url(task_id), timeout=DOWNLOAD_TIMEOUT_SECONDS, stream=True
        ) as response:
            if response.status_code != 200:
                logger.info(
                    "ANY.RUN has no video for task %s (HTTP %s)", task_id, response.status_code
                )
                return None
            written = 0
            with partial.open("wb") as handle:
                for chunk in response.iter_content(CHUNK_BYTES):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > MAX_VIDEO_BYTES:
                        raise ValueError(
                            f"recording exceeded {MAX_VIDEO_BYTES // (1024 * 1024)}MB"
                        )
                    handle.write(chunk)
        partial.replace(target)
        logger.info("cached ANY.RUN video for %s (%.1f MB)", task_id, written / 1048576)
        return target
    except Exception as exc:  # noqa: BLE001 — a missing video is not an error
        logger.warning("could not cache ANY.RUN video for %s: %s", task_id, exc)
        partial.unlink(missing_ok=True)
        return None


def purge_expired(ttl_hours: int = VIDEO_TTL_HOURS) -> dict[str, int]:
    """Delete recordings past their day, and any abandoned partial downloads."""
    directory = cache_dir()
    removed = freed = 0
    if not directory.is_dir():
        return {"removed": 0, "bytes_freed": 0}
    cutoff = time.time() - ttl_hours * 3600
    for path in directory.iterdir():
        try:
            if not path.is_file():
                continue
            stat = path.stat()
            # A .part older than the download timeout is a dead download; there
            # is no request still writing to it.
            expired = stat.st_mtime < cutoff or (
                path.name.endswith(".part")
                and stat.st_mtime < time.time() - DOWNLOAD_TIMEOUT_SECONDS * 2
            )
            if expired:
                size = stat.st_size
                path.unlink()
                removed += 1
                freed += size
        except OSError:
            continue
    if removed:
        logger.info("purged %d ANY.RUN video(s), freed %.1f MB", removed, freed / 1048576)
    return {"removed": removed, "bytes_freed": freed}


# How deep to look for the video object, and how much of a list to scan. The
# report nests it differently depending on how the task was submitted — the one
# recording in this deployment sits at
# items[].domain_intelligence.raw_summary.report_excerpt.analysis.content.video
# — so a fixed set of paths finds it in some shapes and silently misses it in
# others. Bounded rather than unbounded because this walks vendor JSON that has
# no contract about its own depth.
MAX_SEARCH_DEPTH = 14
MAX_SEARCH_BREADTH = 200


def find_video_reference(payload: Any) -> dict[str, str] | None:
    """The first recorded screencast anywhere in an ANY.RUN payload.

    Returns `{"task_id": ..., "url": ...}` or None. The URL must be on
    content.any.run and must carry a task id, so a `video` key from anywhere
    else in the document cannot become something this platform will fetch.
    """

    def walk(node: Any, depth: int) -> dict[str, str] | None:
        if depth > MAX_SEARCH_DEPTH:
            return None
        if isinstance(node, dict):
            video = node.get("video")
            if isinstance(video, dict) and video.get("present"):
                url = str(
                    video.get("permanentUrl") or video.get("permanent_url") or ""
                ).strip()
                if url.startswith("https://content.any.run/tasks/"):
                    task_id = url.split("/tasks/", 1)[1].split("/", 1)[0]
                    if is_task_id(task_id):
                        return {"task_id": task_id, "url": url}
            for value in node.values():
                found = walk(value, depth + 1)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node[:MAX_SEARCH_BREADTH]:
                found = walk(value, depth + 1)
                if found:
                    return found
        return None

    return walk(payload, 0)
