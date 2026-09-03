"""Write the overall reading of a correlated case.

Runs out of band. Correlation is recomputed on every page load, so generating
here on demand would tie an analyst's page render to a model call and spend the
token budget on the fact that someone opened a tab. The task is queued only when
the case actually changed — the same signal that decides whether a snapshot is
appended — and the page shows whatever narrative already exists in the meantime.

A failure is recorded on the case rather than raised. The correlation, the
timeline and every per-alert resolution are already correct without this; an
absent narrative should read as "not written yet", never as a broken case.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun, AlertCaseSpine
from app.services.alert_case_narrative_service import (
    MAX_MEMBERS_IN_PROMPT,
    build_case_evidence,
)
from app.services.assistant_service import AssistantService
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="tasks.write_case_narrative",
    time_limit=600,
    soft_time_limit=540,
    max_retries=2,
)
def write_case_narrative(self, case_key: str, case: dict[str, Any], fingerprint: str) -> str:
    """Analyse one correlated case and store the result on its spine."""
    with Session(sync_engine) as db:
        spine = db.get(AlertCaseSpine, case_key)
        if spine is None:
            return "no spine row"
        # Another worker may have finished the same fingerprint while this task
        # waited in the queue. Recomputing it would buy an identical paragraph.
        if spine.narrative_fingerprint == fingerprint and spine.narrative_markdown:
            return "already current"
        spine.narrative_status = "running"
        db.commit()

        resolutions = _resolutions_for(db, case)

    evidence = build_case_evidence(case, resolutions)
    title = f"Correlated case — {case.get('entity_host')} ({case.get('score')}/100)"

    try:
        result = asyncio.run(_analyse(evidence=evidence, title=title))
        markdown = (result.get("report_markdown") or "").strip()
        if not markdown:
            raise RuntimeError("the assistant returned an empty report")
        error = None
        session_id = result.get("assistant_session_id")
        status = "completed"
    except Exception as exc:  # noqa: BLE001 — recorded, never raised at the page
        logger.exception("case narrative failed for %s", case_key[:12])
        markdown, session_id, status = "", None, "failed"
        error = f"{type(exc).__name__}: {exc}"[:1000]

    with Session(sync_engine) as db:
        spine = db.get(AlertCaseSpine, case_key)
        if spine is None:
            return "spine disappeared"
        spine.narrative_status = status
        spine.narrative_error = error
        if status == "completed":
            spine.narrative_markdown = markdown
            spine.narrative_session_id = str(session_id) if session_id else None
            spine.narrative_generated_at = datetime.now(timezone.utc)
            # Stamped only on success, so a failure leaves the case eligible for
            # another attempt rather than looking as though it had been written.
            spine.narrative_fingerprint = fingerprint
        db.commit()

    logger.info("case narrative %s for %s", status, case_key[:12])
    return status


def _resolutions_for(db: Session, case: dict[str, Any]) -> dict[str, str]:
    """Each member's own conclusion, read back rather than re-derived.

    The per-alert analysis already read the raw bodies. Handing them to the
    model again would produce another opinion about the same evidence instead
    of a synthesis of the opinions already reached.
    """
    members = case.get("alerts") or []
    run_ids = [str(member.get("run_id")) for member in members if member.get("run_id")]
    if not run_ids:
        return {}
    rows = db.execute(
        select(AlertBodyInvestigationRun.id, AlertBodyInvestigationRun.result_json)
        .where(AlertBodyInvestigationRun.id.in_(run_ids))
    ).all()
    found: dict[str, str] = {}
    for run_id, result_json in rows:
        report = ((result_json or {}).get("ai_report") or {}).get("report_markdown")
        if report:
            found[str(run_id)] = str(report)
    return found


async def _analyse(*, evidence: str, title: str) -> dict[str, Any]:
    """Run the assistant's incident_correlation mode over the case evidence.

    A fresh engine per call, for the same reason alert-body analysis uses one:
    asyncio.run closes the loop, and connections opened on a previous loop
    cannot be reused from the next one.
    """
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            session = await AssistantService(db).create_session(
                title=title[:255],
                mode="incident_correlation",
                source_type="correlated_case",
            )
            session_id = session.id

        async with factory() as db:
            await AssistantService(db).add_entry(
                session_id, text=evidence, entry_label="correlated-case", entry_index=0
            )

        async with factory() as db:
            completed = await AssistantService(db).run_session(session_id)
            return {
                "assistant_session_id": str(completed.id),
                "report_markdown": completed.report_markdown or "",
            }
    finally:
        await engine.dispose()


def dispatch(cases: list[tuple[str, dict[str, Any], str]]) -> int:
    """Queue narrative writes for cases that changed.

    Broker failures are logged and swallowed: a page load must not fail because
    Redis is down, and the case is fully readable without its narrative.
    """
    queued = 0
    for case_key, case, fingerprint in cases:
        trimmed = dict(case)
        members = trimmed.get("alerts") or []
        if len(members) > MAX_MEMBERS_IN_PROMPT:
            half = MAX_MEMBERS_IN_PROMPT // 2
            trimmed["alerts"] = members[:half] + members[-half:]
        try:
            write_case_narrative.delay(case_key, trimmed, fingerprint)
            queued += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not queue narrative for %s: %s", case_key[:12], exc)
    return queued
