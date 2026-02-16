"""
Analyst Orchestrator — calls Claude and handles follow-up iterations.

Flow:
1. Build prompt from evidence
2. Call Claude API
3. Parse response
4. If analyst requests more data → return with data_needed
5. Caller (task) collects additional data and re-invokes
"""

from __future__ import annotations

import logging
from typing import Optional

import anthropic

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
    Call Claude with evidence and return a structured report.

    Args:
        evidence: Collected evidence object
        iteration: Current follow-up iteration (0 = first pass)
        max_iterations: Maximum follow-up rounds
        previous_response: Claude's previous response (for follow-ups)

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
        f"(iteration {iteration}/{max_iterations}, "
        f"model={settings.anthropic_model})"
    )

    # ── Call Claude ──
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    response = await client.messages.create(
        model=settings.anthropic_model,
        max_tokens=8192,
        system=system,
        messages=messages,
    )

    raw_text = response.content[0].text
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
