"""
Response Parser — extracts structured JSON and narrative sections from Claude's output.

Claude returns:
  1. A JSON block (```json ... ```)
  2. A human-readable report with ## headers

This module parses both into an AnalystReport.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from app.models.enums import Classification, Confidence, InvestigationState, SOCAction
from app.models.schemas import AnalystFinding, AnalystReport, IOC

logger = logging.getLogger(__name__)


def parse_response(raw_response: str) -> AnalystReport:
    """
    Parse Claude's raw text output into a structured AnalystReport.

    Strategy:
    1. Extract the JSON block
    2. Parse narrative sections from markdown headers
    3. Merge into AnalystReport
    """
    json_data = _extract_json(raw_response)
    if json_data is None:
        logger.error("Could not extract JSON from analyst response")
        return _fallback_report(raw_response)

    narrative = _extract_narrative_sections(raw_response)

    try:
        return _build_report(json_data, narrative)
    except Exception as e:
        logger.error(f"Failed to build report from parsed data: {e}")
        return _fallback_report(raw_response)


def _extract_json(text: str) -> dict | None:
    """Extract the first JSON block from the response."""

    # Try fenced code block first
    if "```json" in text:
        try:
            start = text.index("```json") + 7
            end = text.index("```", start)
            return json.loads(text[start:end].strip())
        except (ValueError, json.JSONDecodeError) as e:
            logger.debug(f"Fenced JSON parse failed: {e}")

    # Try bare JSON (find first complete {...} block)
    if "{" in text:
        start_idx = text.index("{")
        brace_count = 0
        for i in range(start_idx, len(text)):
            if text[i] == "{":
                brace_count += 1
            elif text[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    try:
                        return json.loads(text[start_idx:i + 1])
                    except json.JSONDecodeError:
                        continue

    return None


def _extract_narrative_sections(text: str) -> dict[str, str]:
    """Parse markdown ## headers into named sections."""
    sections: dict[str, str] = {}
    current_section: str | None = None
    current_lines: list[str] = []

    # Find where the narrative starts (after the JSON block)
    narrative_start = 0
    if "```json" in text:
        try:
            json_end = text.index("```", text.index("```json") + 7) + 3
            narrative_start = json_end
        except ValueError:
            pass

    for line in text[narrative_start:].split("\n"):
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = line[3:].strip()
            current_lines = []
        elif current_section:
            current_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections


def _build_report(data: dict, narrative: dict[str, str]) -> AnalystReport:
    """Construct an AnalystReport from parsed JSON + narrative."""

    # Parse findings
    findings = []
    for f in data.get("findings", []):
        findings.append(AnalystFinding(
            id=f.get("id", "unknown"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            severity=f.get("severity", "info"),
            evidence_refs=f.get("evidence_refs", []),
            ttp=f.get("ttp"),
        ))

    # Parse IOCs
    iocs = []
    for ioc in data.get("iocs", []):
        try:
            iocs.append(IOC(
                type=ioc.get("type", "domain"),
                value=ioc.get("value", ""),
                context=ioc.get("context", ""),
                confidence=Confidence(ioc.get("confidence", "low")),
            ))
        except ValueError:
            pass

    return AnalystReport(
        classification=Classification(data.get("classification", "inconclusive")),
        confidence=Confidence(data.get("confidence", "low")),
        investigation_state=InvestigationState(
            data.get("investigation_state", "concluded")
        ),
        primary_reasoning=data.get("primary_reasoning", ""),
        legitimate_explanation=data.get("legitimate_explanation", ""),
        malicious_explanation=data.get("malicious_explanation", ""),
        key_evidence=data.get("key_evidence", []),
        contradicting_evidence=data.get("contradicting_evidence", []),
        data_needed=data.get("data_needed", []),
        findings=findings,
        iocs=iocs,
        recommended_action=SOCAction(data.get("recommended_action", "monitor")),
        recommended_steps=data.get("recommended_steps", []),
        risk_score=data.get("risk_score"),
        risk_rationale=data.get("risk_rationale"),
        executive_summary=narrative.get("Executive Summary"),
        technical_narrative=narrative.get("Technical Evidence Analysis"),
        recommendations_narrative=narrative.get("Recommended Actions"),
    )


def _fallback_report(raw_response: str) -> AnalystReport:
    """When parsing fails, return a minimal report preserving raw text."""
    return AnalystReport(
        classification=Classification.INCONCLUSIVE,
        confidence=Confidence.LOW,
        investigation_state=InvestigationState.CONCLUDED,
        primary_reasoning="Analyst response could not be parsed into structured format.",
        legitimate_explanation="",
        malicious_explanation="",
        recommended_action=SOCAction.INVESTIGATE,
        recommended_steps=["Review raw analyst output manually"],
        executive_summary=raw_response[:3000],
    )
