"""
Turning whatever the model produced into an `AnalystReport`.

Three tiers, tried in order:

1. `structured_response` — the model filled the schema through `response_format`.
2. `salvage_report`      — the model wrote the JSON in prose or a fenced block instead.
                           This is the brace-counting extractor and the permissive
                           coercion from the old `response_parser`, kept precisely
                           because it is the retry a local model needs.
3. `fallback_report`     — nothing parseable. Return an inconclusive report that
                           preserves the raw text rather than losing the run.

Why tier 2 is not deleted: `response_format=AnalystReport` is passed through to
`langchain.agents.create_agent`, which picks a strategy at request time from the model's
profile and, failing that, a regex list of known model names. A locally served
`qwen3:32b`-style name matches neither, so it gets `ToolStrategy` — a synthetic tool
carrying a strict 18-field schema — where hosted OpenAI models get native
`response_format`. Small models routinely fail that and write the JSON as prose instead.

None of these decide anything: the deterministic decision engine overwrites
classification, confidence, risk_score, recommended_action and risk_rationale
downstream.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.models.enums import Classification, Confidence, InvestigationState, SOCAction
from app.models.schemas import AnalystFinding, AnalystReport, IOC

logger = logging.getLogger(__name__)

MAX_RAW_PRESERVED = 3000


def extract_json(text: str) -> dict[str, Any] | None:
    """
    Pull the first JSON object out of free text.

    Handles a ```json fence, then falls back to brace counting from the first `{`, which
    survives prose before and after the object.
    """
    if not text:
        return None

    if "```json" in text:
        try:
            start = text.index("```json") + 7
            end = text.index("```", start)
            return json.loads(text[start:end].strip())
        except (ValueError, json.JSONDecodeError) as exc:
            logger.debug("Fenced JSON parse failed: %s", exc)

    # Scan for balanced {...} blocks, re-anchoring after each failure. The original in
    # response_parser.py only `continue`d without moving the start index, so once the
    # first candidate failed to parse, brace_count was already 0 and every later attempt
    # re-included the bad prefix — it could never succeed. This re-anchor is a real bug
    # fix, not a refactor.
    start_idx = text.find("{")
    while start_idx != -1:
        brace_count = 0
        for i in range(start_idx, len(text)):
            if text[i] == "{":
                brace_count += 1
            elif text[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    try:
                        return json.loads(text[start_idx : i + 1])
                    except json.JSONDecodeError:
                        break  # re-anchor at the next '{' past this one
        else:
            break  # ran out of text with braces still open
        start_idx = text.find("{", start_idx + 1)
    return None


def _extract_narrative_sections(text: str) -> dict[str, str]:
    """
    Parse markdown `## ` headers into named sections.

    Kept for the salvage tier: a model that writes prose alongside its JSON often puts
    the narrative under headers rather than in the JSON fields, and this is the only way
    to recover it. The three keys read downstream are "Executive Summary",
    "Technical Evidence Analysis" and "Recommended Actions".
    """
    sections: dict[str, str] = {}
    current_section: str | None = None
    current_lines: list[str] = []

    # Find where the narrative starts (after the JSON block), so `##` inside the JSON is
    # not harvested as a header.
    narrative_start = 0
    if "```json" in text:
        try:
            narrative_start = text.index("```", text.index("```json") + 7) + 3
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


def _build_report(data: dict, narrative: dict[str, str]) -> AnalystReport:
    """
    Construct an `AnalystReport` from parsed JSON plus any markdown narrative.

    Deliberately permissive, field by field rather than `model_validate`: a small local
    model that got `severity`, `ttp` or an IOC shape wrong should not cost us the
    reasoning it wrote. Bare strings are promoted where a list or an object was expected,
    malformed findings and IOCs are skipped individually, and every enum falls back to
    its safe value.
    """
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
        try:
            confidence = Confidence(str(ioc.get("confidence") or "low").lower())
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

    def _enum(enum_cls, raw: object, default):
        try:
            return enum_cls(str(raw).lower())
        except Exception:
            return default

    return AnalystReport(
        classification=_enum(Classification, data.get("classification", "inconclusive"),
                             Classification.INCONCLUSIVE),
        confidence=_enum(Confidence, data.get("confidence", "low"), Confidence.LOW),
        investigation_state=_enum(InvestigationState, data.get("investigation_state", "concluded"),
                                  InvestigationState.CONCLUDED),
        primary_reasoning=data.get("primary_reasoning", ""),
        legitimate_explanation=data.get("legitimate_explanation", ""),
        malicious_explanation=data.get("malicious_explanation", ""),
        key_evidence=[str(x) for x in _as_list(data.get("key_evidence")) if str(x).strip()],
        contradicting_evidence=[
            str(x) for x in _as_list(data.get("contradicting_evidence")) if str(x).strip()
        ],
        data_needed=[str(x) for x in _as_list(data.get("data_needed")) if str(x).strip()],
        findings=findings,
        iocs=iocs,
        # Note the asymmetry, preserved from response_parser.py: the JSON default read is
        # "monitor" but an unrecognised value falls back to "investigate". The decision
        # engine overwrites this field anyway.
        recommended_action=_enum(SOCAction, data.get("recommended_action", "monitor"),
                                 SOCAction.INVESTIGATE),
        recommended_steps=[
            str(x) for x in _as_list(data.get("recommended_steps")) if str(x).strip()
        ],
        risk_score=data.get("risk_score"),
        risk_rationale=data.get("risk_rationale"),
        executive_summary=(data.get("executive_summary") or narrative.get("Executive Summary")),
        technical_narrative=(
            data.get("technical_narrative") or narrative.get("Technical Evidence Analysis")
        ),
        recommendations_narrative=(
            data.get("recommendations_narrative") or narrative.get("Recommended Actions")
        ),
    )


def parse_response(raw_response: str) -> AnalystReport:
    """
    Parse raw model text into an `AnalystReport`, never raising.

    The tier-2 entry point, and the one place the whole chain is exercised from a plain
    string — which is how `scripts/` and the tests use it.
    """
    data = extract_json(raw_response)
    if data is None:
        logger.error("Could not extract JSON from analyst response")
        return fallback_report(raw_response)

    try:
        return _build_report(data, _extract_narrative_sections(raw_response))
    except Exception as exc:
        logger.error("Failed to build report from parsed data: %s", exc)
        return fallback_report(raw_response)


def _last_text(state: dict[str, Any]) -> str:
    """Text of the final assistant message, if any."""
    for message in reversed(state.get("messages") or []):
        # `.text` is a property on current langchain messages; older builds exposed it
        # as a method. The back-compat shim is a callable str, so test for str first or
        # calling it emits a deprecation warning.
        text = getattr(message, "text", None)
        if not isinstance(text, str) and callable(text):
            text = text()
        if not text:
            content = getattr(message, "content", None)
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = "".join(
                    block.get("text", "") for block in content if isinstance(block, dict)
                )
        if text and text.strip():
            return text
    return ""


def salvage_report(state: dict[str, Any]) -> AnalystReport | None:
    """Second attempt: the model wrote JSON as prose instead of a tool call."""
    raw = _last_text(state)
    data = extract_json(raw)
    if not data:
        return None
    try:
        return _build_report(data, _extract_narrative_sections(raw))
    except Exception as exc:
        logger.warning("Salvaged JSON could not be coerced into a report: %s", exc)
        return None


def fallback_report(raw_text: str = "", *, reason: str = "") -> AnalystReport:
    """
    Minimal report for when nothing parsed.

    Deliberately `inconclusive` / `low`: an unreadable model response is missing
    evidence, and missing evidence is never evidence of maliciousness.

    The `primary_reasoning` string is load-bearing — `_is_parser_fallback_report` in
    analysis_task.py matches "could not be parsed into structured format" and *also*
    requires empty findings, empty iocs and an inconclusive classification before it
    swaps in the rule-based report. All four hold here. Do not reword it without
    updating that detector.
    """
    detail = reason or "Analyst response could not be parsed into structured format."
    return AnalystReport(
        classification=Classification.INCONCLUSIVE,
        confidence=Confidence.LOW,
        investigation_state=InvestigationState.CONCLUDED,
        primary_reasoning=detail,
        legitimate_explanation="",
        malicious_explanation="",
        recommended_action=SOCAction.INVESTIGATE,
        recommended_steps=["Review raw analyst output manually"],
        data_needed=["A parseable analyst response"],
        executive_summary=raw_text[:MAX_RAW_PRESERVED],
    )


def report_from_state(state: dict[str, Any]) -> tuple[AnalystReport, str]:
    """
    Best available report from a finished agent run, plus how we got it.

    Returns `(report, source)` where source is "structured", "salvaged" or "fallback" —
    worth recording, because a run of salvages means the configured model is not holding
    up to the schema.
    """
    report = state.get("structured_response")
    if isinstance(report, AnalystReport):
        return report, "structured"

    if (salvaged := salvage_report(state)) is not None:
        logger.warning("Analyst structured output missing; salvaged JSON from the message text")
        return salvaged, "salvaged"

    logger.error("Analyst produced no usable report; falling back to inconclusive")
    return fallback_report(_last_text(state)), "fallback"
