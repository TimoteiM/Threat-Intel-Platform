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


class PromptTooLarge(RuntimeError):
    """The assembled prompt cannot fit the model's context, so it was not sent.

    Distinct from a provider 400 for the same reason `withheld` is distinct
    from `failed`: this is a decision we made, cheaply, before spending the
    sanitisation. The 2026-08-31 instance spent 1,792 seconds first.
    """


# The implementation lives in `token_boundary`, because three other
# model-facing paths need it too — see `AssistantService.add_entry`. Kept as a
# module-level name here so the existing tests and callers still reach it.
from app.services.token_boundary import protect_outbound as _protect_outbound  # noqa: E402


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
    except PromptTooLarge as exc:
        # Same shape as a withheld send: nothing left, and the reason says
        # which. An analyst reading "failed" cannot tell a refusal from a
        # crash, and this is a refusal.
        logger.warning("Alert-body AI analysis withheld, prompt too large: %s", exc)
        result = {}
        status = "failed"
        withheld = True
        error = str(exc)
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
    # **The sender's provenance declaration goes in front of the evidence.**
    # 69 bodies are declared substitutes; without this the model reads a
    # reconstruction from event metadata as an observed log line, and the
    # report gives a reader no way to tell. The sender was honest and we were
    # dropping it at this boundary.
    from app.services import body_provenance

    provenance_note = body_provenance.note_for_model(alert_body)
    entry_text = f"{provenance_note}\n\n{alert_body}" if provenance_note else alert_body
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
    # **Checked before the boundary runs, not after.** Sanitising text we are
    # going to refuse is the 1,792 seconds that produced nothing on
    # 2026-08-31. The estimate is the platform's own
    # (`alert_log_selection.estimate_tokens`), so it is the same arithmetic
    # the log-digest budget already uses.
    from app.services.alert_log_selection import estimate_tokens

    ceiling = int(getattr(get_settings(), "alert_ai_max_prompt_tokens", 180_000))
    estimated = estimate_tokens(entry_text)
    if estimated > ceiling:
        raise PromptTooLarge(
            f"the assembled prompt is about {estimated:,} tokens against a "
            f"{ceiling:,} ceiling, so it was not sent; the provider's own "
            f"limit would have rejected it after the work was done"
        )

    entry_text = _protect_outbound(entry_text, boundary=boundary)

    # A dedicated, unpooled engine for this loop. Celery runs each task in a
    # worker thread and `asyncio.run()` builds a fresh event loop every time —
    # reusing the app-wide pooled engine hands asyncpg connections bound to a
    # previous loop to the new one ("Future attached to a different loop").
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        return await _run_assistant(
            session_factory, entry_text=entry_text, title=title,
            model=model, boundary=boundary,
        )
    finally:
        # Must be awaited on the loop that opened the connections.
        await engine.dispose()


async def _run_assistant(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    entry_text: str,
    title: str,
    model: str | None,
    boundary: Any,
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
            # The run's boundary, so `add_entry`'s own pass is a no-op over
            # text this path already protected, and so the map that reaches
            # `token_map_json` is the one that minted these tokens. A fresh
            # boundary there would mint nothing (cross-map tokenisation is
            # inert, measured) and would therefore persist an EMPTY map,
            # leaving the restore with nothing to resolve.
            boundary=boundary,
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
