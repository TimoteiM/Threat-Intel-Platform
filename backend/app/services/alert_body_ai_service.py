"""
AI assistant analysis for a pasted alert body.

The text the analyst pastes is sent through the existing AI Assistant
pipeline (`AssistantService`, alert_analysis mode), analysed, and the tokens
restored in the returned report.

**What "sanitised" means on this path, as of 2026-10-21.** This docstring
used to say that "hostnames, accounts, IPs and emails are tokenised before
the model sees them". That was true of four context-free classes and false of
six others: measured at the wire, **4.42 identifiers per alert reached the
model in the clear** — 1,353 distinct accounts and 734 distinct hostnames
across the corpus — because `assistant_sanitizer_service`'s keyed detectors
miss `key: value`, `key=\\"value\\"` and single-label hosts. See
`docs/measurements/corpus-identifier-leak.md`.

So the assembled text now goes through the identifier boundary here, in
`_protect_outbound`, before it ever reaches `AssistantService`. Two layers in
the fixed order this codebase uses everywhere:

1. **secrets first**, non-reversible, because a placeholder that cannot be
   undone must be in place before anything reversible is;
2. **identifiers second**, reversible, with the run's boundary — the *same*
   boundary the log digest was tokenised with, so one host is one token in
   both halves. A second map would make the alert's host and the log's host
   read as two different machines.

The raw body is still what is **stored**. Only what leaves for the provider
is tokenised, and `_restore_identifiers` puts the names back in the report.
Nothing about search, the entity graph, the dedup hash or any render site
changes — see §4d of `docs/design/context-gathering-stage.md` for why the
alternative (storing tokenised) is incoherent against the map's TTL.

**It fails closed.** No boundary, or a boundary that raises, means no model
call: the report comes back `status="failed"` with `withheld=True` and a
reason. An analysis is worth having; it is not worth sending identifiers in
the clear because a map could not be opened.
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


def _protect_outbound(text: str, *, boundary: Any) -> str:
    """Secrets out, identifiers tokenised, in that fixed order.

    One call over the **whole** assembled text rather than per part, which is
    safe because both layers are idempotent on text that has already been
    through them: `_is_real_secret` refuses a value that already starts with
    `<SECRET:`, and the boundary's detectors skip anything matching the token
    grammar. Measured on the gathering stage's already-tokenised records: a
    second pass mints nothing and changes nothing.

    That idempotence is what lets the log digest — tokenised earlier, with
    this same boundary — pass through here untouched instead of needing to be
    carved out and rejoined.

    Raises `BoundaryUnavailable`. There is no path through this function that
    returns text the boundary did not process.
    """
    from app.services import log_secret_sanitizer as secrets
    from app.services.alert_log_prompt import BoundaryUnavailable

    if boundary is None:
        raise BoundaryUnavailable(
            "no identifier boundary was supplied, so the alert text was not "
            "tokenised and nothing was sent to the model"
        )
    try:
        # Secrets first, and non-reversible by design: `restore` must never
        # be able to put a credential back, so these are HMAC placeholders
        # and not tokens. 6,023 occurrences across 18.1% of alerts in the
        # corpus, `session` being 14.7% of it on its own.
        redacted = secrets.sanitize_text(text).text
        # Identifiers second, reversible, scoped to this run.
        return boundary.tokenize(redacted)
    except Exception as exc:  # noqa: BLE001
        raise BoundaryUnavailable(
            f"the identifier boundary could not be applied to the alert text "
            f"({type(exc).__name__}: {exc}), so nothing was sent to the model"
        ) from exc


def run_alert_body_ai_analysis(
    *,
    alert_body: str,
    title: str,
    boundary: Any,
    context: str | None = None,
    model: str | None = None,
    schema_version: str = "1.0",
    findings_digest: str | None = None,
    log_context_digest: str | None = None,
) -> dict[str, Any]:
    """
    Analyse the alert body with the AI assistant. Never raises — a failed
    analysis is reported inside the returned block so the collector results
    still reach the analyst.

    `boundary` is required and has no default. A default would let a caller
    send an alert body to the provider untokenised by writing nothing at all,
    which is the failure this exists to close; a rule a caller has to
    remember is not a rule.
    """
    from app.services.alert_log_prompt import BoundaryUnavailable

    started = datetime.now(timezone.utc)
    t_start = time.perf_counter()
    withheld = False
    try:
        result = asyncio.run(
            _analyse(
                alert_body=alert_body,
                title=title,
                context=context,
                model=model,
                findings_digest=findings_digest,
                log_context_digest=log_context_digest,
                boundary=boundary,
            )
        )
        status = "completed"
        error = None
    except BoundaryUnavailable as exc:
        # Fail closed, and distinguishable from an analysis that ran and
        # broke. `status` stays "failed" because consumers already switch on
        # it; `withheld` is what says we declined to send rather than tried
        # and lost.
        logger.warning("Alert-body AI analysis withheld: %s", exc)
        result = {}
        status = "failed"
        withheld = True
        error = str(exc)
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
        # True only when nothing was sent. An analyst reading "failed" is
        # entitled to know which of the two happened.
        "withheld": withheld,
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
    log_context_digest: str | None = None,
    boundary: Any = None,
) -> dict[str, Any]:
    entry_text = alert_body
    if (context or "").strip():
        entry_text = f"{alert_body}\n\nANALYST CONTEXT:\n{context.strip()}"
    # The collectors have already run by the time we get here, so the model reads
    # the alert *and* what our sources actually found. Sanitisation happens after
    # this join, so a hostname is tokenised the same way in both halves.
    if (findings_digest or "").strip():
        entry_text = f"{entry_text}\n\n{findings_digest.strip()}"
    # Last, and fenced by its own builder: SIEM events are evidence the model
    # reads, never instructions it follows. Already sanitised server-side —
    # this join is the last point before the request is constructed.
    if (log_context_digest or "").strip():
        entry_text = f"{entry_text}\n\n{log_context_digest.strip()}"

    # **The boundary, over the whole join, and this is the only place it
    # happens on this path.** After this line nothing downstream has access
    # to an untokenised identifier or an unredacted credential: `add_entry`
    # stores what it is given, `run_session` sanitises again (harmlessly —
    # both layers are idempotent) and the prompt builder reads only
    # `sanitized_text`.
    #
    # Deliberately after the join, not before it, for the reason the comment
    # above the findings join already gives: one map over one string means a
    # host is the same token in the alert half and the gathered half. Two
    # calls over two strings with two maps was the defect to avoid.
    entry_text = _protect_outbound(entry_text, boundary=boundary)

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
            # Carried so a correlated-case narrative can read this analysis
            # without reading the identifiers it was careful to redact.
            "report_markdown_model_safe": completed.report_markdown_model_safe or "",
            "sanitization_summary": completed.sanitization_summary_json or {},
        }
