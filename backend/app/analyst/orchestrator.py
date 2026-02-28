"""
Analyst Orchestrator — calls the LLM and handles follow-up iterations.

Flow:
1. Build prompt from evidence
2. Call OpenAI Responses API (primary)
3. Fallback to Claude when primary fails
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


async def run_analyst(
    evidence: CollectedEvidence,
    iteration: int = 0,
    max_iterations: int = 3,
    previous_response: Optional[str] = None,
) -> AnalystReport:
    """
    Call the configured OpenAI model with evidence and return a structured report.

    Args:
        evidence: Collected evidence object
        iteration: Current follow-up iteration (0 = first pass)
        max_iterations: Maximum follow-up rounds
        previous_response: Previous model response (for follow-ups)

    Returns:
        AnalystReport with classification, findings, and narrative
    """
    settings = get_settings()

    system, messages = build_messages(
        evidence=evidence,
        iteration=iteration,
        max_iterations=max_iterations,
        previous_response=previous_response,
    )

    logger.info(
        f"[{evidence.investigation_id}] Calling analyst "
        f"(iteration {iteration}/{max_iterations}, model={settings.openai_model}, provider=openai)"
    )

    raw_text = ""
    try:
        raw_text = await _call_openai(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            system=system,
            messages=messages,
        )
    except Exception as openai_err:
        if settings.anthropic_api_key and settings.anthropic_model:
            logger.warning(
                f"[{evidence.investigation_id}] OpenAI analyst call failed "
                f"({type(openai_err).__name__}: {openai_err}). "
                f"Falling back to Claude model={settings.anthropic_model}."
            )
            raw_text = await _call_claude(
                api_key=settings.anthropic_api_key,
                model=settings.anthropic_model,
                system=system,
                messages=messages,
            )
        else:
            raise

    if not raw_text.strip() and settings.anthropic_api_key and settings.anthropic_model:
        logger.warning(
            f"[{evidence.investigation_id}] OpenAI returned empty analyst output. "
            f"Falling back to Claude model={settings.anthropic_model}."
        )
        raw_text = await _call_claude(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            system=system,
            messages=messages,
        )

    logger.debug(f"[{evidence.investigation_id}] Analyst raw response length: {len(raw_text)}")

    # ── Parse response ──
    report = parse_response(raw_text)

    # ── Log the result ──
    logger.info(
        f"[{evidence.investigation_id}] Analyst result: "
        f"classification={report.classification.value}, "
        f"confidence={report.confidence.value}, "
        f"state={report.investigation_state.value}, "
        f"risk_score={report.risk_score}"
    )

    # ── Handle follow-up requests ──
    if (
        report.investigation_state == InvestigationState.INSUFFICIENT_DATA
        and report.data_needed
        and iteration < max_iterations
    ):
        logger.info(
            f"[{evidence.investigation_id}] Analyst requests additional data "
            f"(iteration {iteration + 1}): {report.data_needed}"
        )
        # Return as-is — the caller (analysis task) decides whether to collect more

    return report


async def _call_openai(
    api_key: str,
    model: str,
    system: str,
    messages: list[dict],
) -> str:
    """Primary analyst call via OpenAI Responses API."""
    client = AsyncOpenAI(api_key=api_key)
    input_messages = [{"role": "system", "content": system}] + messages
    response = await client.responses.create(
        model=model,
        input=input_messages,
        max_output_tokens=8192,
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


async def _call_claude(
    api_key: str,
    model: str,
    system: str,
    messages: list[dict],
) -> str:
    """Fallback analyst call via Anthropic Claude."""
    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=messages,
    )
    return response.content[0].text if response and response.content else ""
