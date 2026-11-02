"""
The investigation PDF, rendered once and kept.

Rendering is expensive — 16 seconds on a report with long tokenised URLs, and it
grows with the evidence — and it was being repeated in full on every single
click of Export, for byte-identical output. Worse, it ran on the request, so the
analyst waited for it and the browser sometimes gave up first.

An investigation's report does not change after it concludes, so the file is
rendered once by the worker as the run finishes and stored as an artifact. By
the time anyone opens the case the PDF already exists and Export is a download.

What makes that safe is the fingerprint. The cache is keyed on a hash of the
exact inputs the PDF is built from — evidence, report and the decision fields —
so a re-analysis, a re-verdict or a watchlist escalation produces a different
fingerprint and the stale file is never served. Handing an analyst a PDF that
says "benign" after the platform changed its mind to "malicious" would be far
worse than a slow export.

The API keeps a render-on-demand path for the cases this cannot cover: the
investigations that concluded before this existed, and any run where the
background render failed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import Artifact
from app.services.export_service import export_pdf

logger = logging.getLogger(__name__)

# Stored under the investigation's artifact directory alongside collector output.
ARTIFACT_NAME = "investigation-report.pdf"
ARTIFACT_SOURCE = "export"
CONTENT_TYPE = "application/pdf"


# The `detail` fields the PDF actually renders — see `export_service`. Hashing
# the whole dict would fold in `updated_at`, which the report never shows and
# which changes whenever anything touches the investigation row; the cache would
# then miss on every request and the feature would do nothing.
#
# The reverse mistake is the dangerous one: a field that reaches the PDF but not
# this list means a changed value serving an unchanged file. Add to this list
# when `export_service` starts reading a new field.
_FINGERPRINTED_DETAIL_FIELDS = (
    "id",
    "domain",
    "observable_type",
    "state",
    "classification",
    "confidence",
    "risk_score",
    "recommended_action",
    "client_domain",
    "created_at",
    "concluded_at",
)


def pdf_fingerprint(evidence: dict, report: dict, detail: dict) -> str:
    """
    Identity of the PDF's inputs.

    Anything that would change a byte of the rendered file has to change this,
    or a stale conclusion gets served. `sort_keys` keeps it stable across dict
    ordering, and `default=str` keeps datetimes and UUIDs from raising rather
    than silently dropping out of the hash.
    """
    payload = json.dumps(
        {
            "evidence": evidence,
            "report": report,
            "detail": {key: (detail or {}).get(key) for key in _FINGERPRINTED_DETAIL_FIELDS},
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _artifact_path(investigation_id: str) -> Path:
    base = Path(get_settings().artifact_local_path)
    return base / str(investigation_id) / ARTIFACT_NAME


def _read_if_current(row: Artifact | None, fingerprint: str) -> bytes | None:
    """The stored bytes, but only when they were rendered from these inputs."""
    if row is None or row.sha256_hash != fingerprint:
        return None
    path = str(row.storage_path or "").replace("\\", "/")
    if not path or not os.path.exists(path):
        # The row outlived the file — a wiped volume, a restored database.
        return None
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        logger.warning("Cached report PDF unreadable at %s: %s", path, exc)
        return None
    return data if data.startswith(b"%PDF") else None


def _write(investigation_id: str, fingerprint: str, pdf_bytes: bytes) -> Artifact:
    path = _artifact_path(investigation_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pdf_bytes)
    return Artifact(
        investigation_id=investigation_id,
        collector_name=ARTIFACT_SOURCE,
        artifact_name=ARTIFACT_NAME,
        sha256_hash=fingerprint,
        content_type=CONTENT_TYPE,
        size_bytes=len(pdf_bytes),
        storage_path=str(path),
    )


# ── Worker side (synchronous) ────────────────────────────────────────────────


def render_and_store_sync(
    session: Session,
    investigation_id: str,
    evidence: dict,
    report: dict,
    detail: dict,
) -> bool:
    """
    Render the PDF as the investigation concludes. Never raises.

    A failed render must not fail the investigation that produced it — the run's
    own results are already persisted by this point, and the API can still
    render on demand.
    """
    try:
        fingerprint = pdf_fingerprint(evidence, report, detail)
        existing = session.execute(
            select(Artifact).where(
                Artifact.investigation_id == investigation_id,
                Artifact.artifact_name == ARTIFACT_NAME,
            )
        ).scalar_one_or_none()
        if existing is not None and existing.sha256_hash == fingerprint:
            return True

        pdf_bytes = export_pdf(evidence, report, detail)
        if not pdf_bytes.startswith(b"%PDF"):
            logger.warning("[%s] Report PDF render produced a non-PDF payload", investigation_id)
            return False

        row = _write(investigation_id, fingerprint, pdf_bytes)
        if existing is not None:
            # Re-analysis: replace in place so one investigation keeps one PDF.
            existing.sha256_hash = row.sha256_hash
            existing.size_bytes = row.size_bytes
            existing.storage_path = row.storage_path
            existing.content_type = row.content_type
        else:
            session.add(row)
        session.commit()
        logger.info(
            "[%s] Report PDF cached (%.0f KB) — Export will serve it directly",
            investigation_id,
            len(pdf_bytes) / 1024,
        )
        return True
    except Exception as exc:
        session.rollback()
        logger.warning("[%s] Could not pre-render the report PDF: %s", investigation_id, exc)
        return False


# ── API side (asynchronous) ──────────────────────────────────────────────────


async def load_cached_pdf(
    session: AsyncSession,
    investigation_id: str,
    fingerprint: str,
) -> bytes | None:
    row = (
        await session.execute(
            select(Artifact).where(
                Artifact.investigation_id == investigation_id,
                Artifact.artifact_name == ARTIFACT_NAME,
            )
        )
    ).scalar_one_or_none()
    return _read_if_current(row, fingerprint)


async def store_pdf(
    session: AsyncSession,
    investigation_id: str,
    fingerprint: str,
    pdf_bytes: bytes,
) -> None:
    """Persist a freshly rendered PDF so the next request does not repeat it."""
    try:
        row = _write(investigation_id, fingerprint, pdf_bytes)
        existing = (
            await session.execute(
                select(Artifact).where(
                    Artifact.investigation_id == investigation_id,
                    Artifact.artifact_name == ARTIFACT_NAME,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.sha256_hash = row.sha256_hash
            existing.size_bytes = row.size_bytes
            existing.storage_path = row.storage_path
            existing.content_type = row.content_type
        else:
            session.add(row)
        await session.commit()
    except Exception as exc:
        # Caching is an optimisation; the caller already has the bytes to serve.
        await session.rollback()
        logger.warning("[%s] Could not cache the rendered report PDF: %s", investigation_id, exc)


async def invalidate(session: AsyncSession, investigation_id: str) -> None:
    """Drop the cached PDF — for callers that change a report out of band."""
    row = (
        await session.execute(
            select(Artifact).where(
                Artifact.investigation_id == investigation_id,
                Artifact.artifact_name == ARTIFACT_NAME,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return
    path = str(row.storage_path or "").replace("\\", "/")
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
    await session.delete(row)
    await session.commit()
