"""
Analyst Orchestrator — calls the LLM and handles follow-up iterations.

Flow:
1. Build prompt from evidence
2. Call the configured Claude model (primary)
3. Fallback to GPT-5 Mini when primary fails or returns empty
4. Parse response
5. If analyst requests more data → return with data_needed
6. Caller (task) collects additional data and re-invokes
"""

from __future__ import annotations

import logging
from typing import Optional

import anthropic
from openai import AsyncOpenAI

from app.analyst.prompt_builder import build_messages
from app.analyst.response_parser import parse_response
from app.config import get_settings
from app.models.enums import InvestigationState
from app.models.schemas import AnalystReport, CollectedEvidence

logger = logging.getLogger(__name__)

DEFAULT_PRIMARY_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_FALLBACK_MODEL = "gpt-5-mini"
PRIMARY_MODEL = DEFAULT_PRIMARY_MODEL
FALLBACK_MODEL = DEFAULT_FALLBACK_MODEL


async def run_analyst(
    evidence: CollectedEvidence,
    iteration: int = 0,
    max_iterations: int = 3,
    previous_response: Optional[str] = None,
) -> tuple[AnalystReport, str]:
    """
    Call the configured LLM with evidence and return a structured report.

    Always tries the configured Claude model first; falls back to GPT-5 Mini on any
    failure or empty response.

    Args:
        evidence: Collected evidence object
        iteration: Current follow-up iteration (0 = first pass)
        max_iterations: Maximum follow-up rounds
        previous_response: Previous model response (for follow-ups)

    Returns:
        (AnalystReport, actual_model_id) — report plus the model that produced it
    """
    settings = get_settings()

    system, messages = build_messages(
        evidence=evidence,
        iteration=iteration,
        max_iterations=max_iterations,
        previous_response=previous_response,
    )
    message_chars = sum(
        len(str(message.get("content") or ""))
        for message in messages
        if isinstance(message, dict)
    )
    prompt_chars = len(system) + message_chars
    logger.info(
        "[%s] Analyst prompt size: chars=%s system_chars=%s message_chars=%s messages=%s",
        evidence.investigation_id,
        prompt_chars,
        len(system),
        message_chars,
        len(messages),
    )

    primary_model = (settings.anthropic_model or DEFAULT_PRIMARY_MODEL).strip() or DEFAULT_PRIMARY_MODEL
    fallback_model = (settings.openai_model or DEFAULT_FALLBACK_MODEL).strip() or DEFAULT_FALLBACK_MODEL
    max_output_tokens = max(1024, int(getattr(settings, "analyst_max_output_tokens", 8192) or 8192))

    raw_text = ""
    actual_model = primary_model

    # ── Primary: Claude ──────────────────────────────────────────────────────
    if settings.anthropic_api_key:
        try:
            logger.info(
                f"[{evidence.investigation_id}] Calling primary analyst "
                f"(iteration {iteration}/{max_iterations}, model={primary_model}, max_output_tokens={max_output_tokens})"
            )
            raw_text = await _call_claude(
                api_key=settings.anthropic_api_key,
                model=primary_model,
                system=system,
                messages=messages,
                max_tokens=max_output_tokens,
                investigation_id=str(evidence.investigation_id),
            )
            if raw_text.strip():
                logger.info(
                    f"[{evidence.investigation_id}] Claude response received, "
                    f"length={len(raw_text)}"
                )
            else:
                logger.warning(
                    f"[{evidence.investigation_id}] Claude returned empty output - "
                    "will fall back to GPT-5 Mini"
                )
                raw_text = ""
        except Exception as exc:
            logger.warning(
                f"[{evidence.investigation_id}] Claude call failed "
                f"({type(exc).__name__}: {exc}) - will fall back to GPT-5 Mini"
            )
            raw_text = ""
    else:
        logger.warning(
            f"[{evidence.investigation_id}] ANTHROPIC_API_KEY not set — "
            "skipping primary, using GPT-5 Mini directly"
        )

    # ── Fallback: GPT-5 Mini ─────────────────────────────────────────────────
    if not raw_text.strip():
        if not settings.openai_api_key:
            raise ValueError(
                "Both primary (Claude) and fallback (GPT-5 Mini) are unavailable: "
                "ANTHROPIC_API_KEY and OPENAI_API_KEY are both unset."
            )
        actual_model = fallback_model
        logger.info(
            f"[{evidence.investigation_id}] Calling fallback analyst "
            f"(iteration {iteration}/{max_iterations}, model={fallback_model}, max_output_tokens={max_output_tokens})"
        )
        raw_text = await _call_openai(
            api_key=settings.openai_api_key,
            model=fallback_model,
            system=system,
            messages=messages,
            max_output_tokens=max_output_tokens,
            investigation_id=str(evidence.investigation_id),
        )
        logger.info(
            f"[{evidence.investigation_id}] GPT-5 Mini response received, "
            f"length={len(raw_text)}"
        )

    logger.debug(f"[{evidence.investigation_id}] Analyst raw response length: {len(raw_text)}")

    # ── Parse response ────────────────────────────────────────────────────────
    report = parse_response(raw_text)

    logger.info(
        f"[{evidence.investigation_id}] Analyst result: "
        f"classification={report.classification.value}, "
        f"confidence={report.confidence.value}, "
        f"state={report.investigation_state.value}, "
        f"risk_score={report.risk_score}, "
        f"model={actual_model}"
    )

    # ── Handle follow-up requests ─────────────────────────────────────────────
    if (
        report.investigation_state == InvestigationState.INSUFFICIENT_DATA
        and report.data_needed
        and iteration < max_iterations
    ):
        logger.info(
            f"[{evidence.investigation_id}] Analyst requests additional data "
            f"(iteration {iteration + 1}): {report.data_needed}"
        )

    return report, actual_model


async def _call_claude(
    api_key: str,
    model: str,
    system: str,
    messages: list[dict],
    max_tokens: int,
    investigation_id: str = "",
) -> str:
    """Call Anthropic Claude."""
    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[*messages, {"role": "assistant", "content": "{"}],
    )
    usage = getattr(response, "usage", None)
    if usage is not None:
        logger.info(
            "[%s] Claude usage: model=%s input_tokens=%s output_tokens=%s cache_creation_input_tokens=%s cache_read_input_tokens=%s",
            investigation_id,
            model,
            getattr(usage, "input_tokens", None),
            getattr(usage, "output_tokens", None),
            getattr(usage, "cache_creation_input_tokens", None),
            getattr(usage, "cache_read_input_tokens", None),
        )
    text = response.content[0].text if response and response.content else ""
    stripped = text.lstrip()
    if not stripped:
        return ""
    return stripped if stripped.startswith("{") else "{" + stripped


async def _call_openai(
    api_key: str,
    model: str,
    system: str,
    messages: list[dict],
    max_output_tokens: int,
    investigation_id: str = "",
) -> str:
    """Call OpenAI Responses API."""
    client = AsyncOpenAI(api_key=api_key)
    input_messages = [{"role": "system", "content": system}] + messages
    response = await client.responses.create(
        model=model,
        input=input_messages,
        max_output_tokens=max_output_tokens,
    )
    usage = getattr(response, "usage", None)
    if usage is not None:
        logger.info(
            "[%s] OpenAI usage: model=%s input_tokens=%s output_tokens=%s total_tokens=%s",
            investigation_id,
            model,
            getattr(usage, "input_tokens", None),
            getattr(usage, "output_tokens", None),
            getattr(usage, "total_tokens", None),
        )

    raw_text = getattr(response, "output_text", None) or ""
    if raw_text:
        return raw_text

    # Defensive fallback for SDK format variations
    chunks: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            text = getattr(content, "text", None)
            if text:
                chunks.append(text)
    return "\n".join(chunks).strip()
