"""
AI assistant analysis for a pasted alert body.

The same raw text the analyst pastes is sent through the existing AI Assistant
pipeline (`AssistantService`, alert_analysis mode): it is sanitised — hostnames,
accounts, IPs and emails are tokenised before the model sees them — analysed,
then the tokens are restored in the returned report.

The result is returned as one JSON block so it can lead the alert run's report
list, and the underlying assistant session is persisted so the analyst can open
it (and its incident graph) in the AI Assistant workspace.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.services.assistant_service import AssistantService

logger = logging.getLogger(__name__)

AI_REPORT_TYPE = "ai_assistant"


def run_alert_body_ai_analysis(
    *,
    alert_body: str,
    title: str,
    context: str | None = None,
    model: str | None = None,
    schema_version: str = "1.0",
    findings_digest: str | None = None,
) -> dict[str, Any]:
    """
    Analyse the alert body with the AI assistant. Never raises — a failed
    analysis is reported inside the returned block so the collector results
    still reach the analyst.
    """
    started = datetime.now(timezone.utc)
    t_start = time.perf_counter()
    try:
        result = asyncio.run(
            _analyse(
                alert_body=alert_body,
                title=title,
                context=context,
                model=model,
                findings_digest=findings_digest,
            )
        )
        status = "completed"
        error = None
    except Exception as exc:
        logger.exception("Alert-body AI analysis failed")
        result = {}
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"

    return {
        "schema_version": schema_version,
        "report_type": AI_REPORT_TYPE,
        "source": "alert_body",
        "status": status,
        "error": error,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.perf_counter() - t_start) * 1000),
        **result,
    }


async def _analyse(
    *,
    alert_body: str,
    title: str,
    context: str | None,
    model: str | None,
    findings_digest: str | None = None,
) -> dict[str, Any]:
    entry_text = alert_body
    if (context or "").strip():
        entry_text = f"{alert_body}\n\nANALYST CONTEXT:\n{context.strip()}"
    # The collectors have already run by the time we get here, so the model reads
    # the alert *and* what our sources actually found. Sanitisation happens after
    # this join, so a hostname is tokenised the same way in both halves.
    if (findings_digest or "").strip():
        entry_text = f"{entry_text}\n\n{findings_digest.strip()}"

    # A dedicated, unpooled engine for this loop. Celery runs each task in a
    # worker thread and `asyncio.run()` builds a fresh event loop every time —
    # reusing the app-wide pooled engine hands asyncpg connections bound to a
    # previous loop to the new one ("Future attached to a different loop").
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        return await _run_assistant(session_factory, entry_text=entry_text, title=title, model=model)
    finally:
        # Must be awaited on the loop that opened the connections.
        await engine.dispose()


async def _run_assistant(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    entry_text: str,
    title: str,
    model: str | None,
) -> dict[str, Any]:
    # One session per step, exactly like the assistant API endpoints do. Sessions
    # are created with expire_on_commit=False, so reusing a single session would
    # hand run_session() the session object cached at creation time — with an
    # empty entries collection — and the model would analyse a blank alert.
    async with session_factory() as db:
        assistant_session = await AssistantService(db).create_session(
            title=title[:255] or "Alert body analysis",
            mode="alert_analysis",
            source_type="alert_body",
        )
        session_id = assistant_session.id

    async with session_factory() as db:
        await AssistantService(db).add_entry(
            session_id,
            text=entry_text,
            entry_label="alert-body",
            entry_index=0,
        )

    async with session_factory() as db:
        completed = await AssistantService(db).run_session(session_id, model=model)
        result_json = completed.result_json or {}
        return {
            "assistant_session_id": str(completed.id),
            "assistant_session_url": f"/assistant?session={completed.id}",
            "mode": completed.mode,
            "title": completed.title,
            "generated_at": result_json.get("generated_at"),
            "report_markdown": completed.report_markdown or "",
            "incident_graph": result_json.get("incident_graph") or {},
            "sanitization_summary": completed.sanitization_summary_json or {},
        }
