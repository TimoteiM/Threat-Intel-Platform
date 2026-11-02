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
    for f in _as_list(data.get("findings")):
        if not isinstance(f, dict):
            text = str(f or "").strip()
            if not text:
                continue
            f = {
                "id": _slug_id(text, default="ai_finding"),
                "title": text[:120],
                "description": text,
                "severity": "info",
                "evidence_refs": [],
            }
        refs = f.get("evidence_refs", [])
        if isinstance(refs, str):
            refs = [refs]
        if not isinstance(refs, list):
            refs = []
        refs = [str(r) for r in refs if str(r).strip()]
        try:
            findings.append(AnalystFinding(
                id=str(f.get("id", "unknown")),
                title=str(f.get("title", "")),
                description=str(f.get("description", "")),
                severity=str(f.get("severity", "info")),
                evidence_refs=refs,
                ttp=str(f.get("ttp")) if f.get("ttp") is not None else None,
            ))
        except Exception:
            # Skip malformed finding records instead of discarding the whole report.
            continue

    # Parse IOCs
    iocs = []
    for ioc in _as_list(data.get("iocs")):
        if not isinstance(ioc, dict):
            value = str(ioc or "").strip()
            if not value:
                continue
            ioc = {
                "type": _infer_ioc_type(value),
                "value": value,
                "context": "AI analyst observed IOC",
                "confidence": "low",
            }
        value = str(ioc.get("value") or ioc.get("ioc") or ioc.get("indicator") or "").strip()
        if not value:
            continue
        confidence_value = str(ioc.get("confidence") or "low").lower()
        try:
            confidence = Confidence(confidence_value)
        except ValueError:
            confidence = Confidence.LOW
        try:
            iocs.append(IOC(
                type=ioc.get("type", _infer_ioc_type(value)),
                value=value,
                context=str(ioc.get("context") or ioc.get("source") or ""),
                confidence=confidence,
            ))
        except (TypeError, ValueError):
            pass

    classification_raw = str(data.get("classification", "inconclusive")).lower()
    confidence_raw = str(data.get("confidence", "low")).lower()
    state_raw = str(data.get("investigation_state", "concluded")).lower()
    action_raw = str(data.get("recommended_action", "monitor")).lower()
    try:
        classification = Classification(classification_raw)
    except Exception:
        classification = Classification.INCONCLUSIVE
    try:
        confidence = Confidence(confidence_raw)
    except Exception:
        confidence = Confidence.LOW
    try:
        investigation_state = InvestigationState(state_raw)
    except Exception:
        investigation_state = InvestigationState.CONCLUDED
    try:
        recommended_action = SOCAction(action_raw)
    except Exception:
        recommended_action = SOCAction.INVESTIGATE

    return AnalystReport(
        classification=classification,
        confidence=confidence,
        investigation_state=investigation_state,
        primary_reasoning=data.get("primary_reasoning", ""),
        legitimate_explanation=data.get("legitimate_explanation", ""),
        malicious_explanation=data.get("malicious_explanation", ""),
        key_evidence=[str(x) for x in _as_list(data.get("key_evidence")) if str(x).strip()],
        contradicting_evidence=[str(x) for x in _as_list(data.get("contradicting_evidence")) if str(x).strip()],
        data_needed=[str(x) for x in _as_list(data.get("data_needed")) if str(x).strip()],
        findings=findings,
        iocs=iocs,
        recommended_action=recommended_action,
        recommended_steps=[str(x) for x in _as_list(data.get("recommended_steps")) if str(x).strip()],
        risk_score=data.get("risk_score"),
        risk_rationale=data.get("risk_rationale"),
        executive_summary=(data.get("executive_summary") or narrative.get("Executive Summary")),
        technical_narrative=(data.get("technical_narrative") or narrative.get("Technical Evidence Analysis")),
        recommendations_narrative=(data.get("recommendations_narrative") or narrative.get("Recommended Actions")),
    )


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    return [value]


def _slug_id(value: str, *, default: str) -> str:
    import re

    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return (slug or default)[:80]


def _infer_ioc_type(value: str) -> str:
    text = value.strip().lower()
    if text.startswith(("http://", "https://")):
        return "url"
    if "@" in text and "." in text.rsplit("@", 1)[-1]:
        return "email"
    parts = text.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return "ip"
        except ValueError:
            pass
    hex_chars = set("0123456789abcdef")
    if len(text) in {32, 40, 64} and all(ch in hex_chars for ch in text):
        return "hash"
    return "domain"


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
