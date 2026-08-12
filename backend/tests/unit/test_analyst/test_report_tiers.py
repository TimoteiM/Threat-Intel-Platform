"""
`report_from_state`'s three tiers.

A report always comes back. `source` records which tier produced it, because a run of
"salvaged" means the configured model is not holding the report schema — the single most
useful signal when a local model is underpowered.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from app.analyst.report import extract_json, fallback_report, report_from_state
from app.models.schemas import AnalystReport

GOOD_JSON = """{
  "classification": "malicious",
  "confidence": "high",
  "investigation_state": "concluded",
  "primary_reasoning": "Verified phishing feed hit plus a credential form.",
  "legitimate_explanation": "None fits.",
  "malicious_explanation": "Credential harvesting.",
  "recommended_action": "block"
}"""


def _state(text: str = "", *, structured=None) -> dict:
    return {
        "messages": [AIMessage(content=text)] if text else [],
        "structured_response": structured,
    }


def _report() -> AnalystReport:
    return AnalystReport(
        classification="suspicious",
        confidence="medium",
        investigation_state="concluded",
        primary_reasoning="Filled the schema.",
        legitimate_explanation="",
        malicious_explanation="",
        recommended_action="investigate",
    )


def test_tier1_structured_response():
    report, source = report_from_state(_state(structured=_report()))

    assert source == "structured"
    assert report.primary_reasoning == "Filled the schema."


def test_tier2_salvages_a_fenced_block():
    report, source = report_from_state(
        _state(f"Here is my analysis:\n```json\n{GOOD_JSON}\n```\nHope that helps.")
    )

    assert source == "salvaged"
    assert report.classification.value == "malicious"


def test_tier2_salvages_bare_json_with_prose_on_both_sides():
    report, source = report_from_state(
        _state(f"I reviewed the bundle.\n{GOOD_JSON}\nThat is my assessment.")
    )

    assert source == "salvaged"
    assert report.recommended_action.value == "block"


def test_tier2_reanchors_past_a_bad_first_candidate():
    """
    The re-anchor bug fix.

    The original scanner `continue`d without moving the start index, so once the first
    `{...}` candidate failed to parse, brace_count was already 0 and no later candidate
    could ever match. A model that emits a broken object before a good one used to cost
    the whole run.
    """
    text = f'Draft: {{"classification": "benign",}} — scratch that. Final:\n{GOOD_JSON}'

    assert extract_json(text) is not None
    report, source = report_from_state(_state(text))

    assert source == "salvaged"
    assert report.classification.value == "malicious"


def test_tier3_fallback_on_unparseable_output():
    report, source = report_from_state(_state("I cannot comply. @#$%"))

    assert source == "fallback"
    assert report.classification.value == "inconclusive"
    assert report.confidence.value == "low"
    # Raw text is preserved rather than lost.
    assert "I cannot comply" in (report.executive_summary or "")


def test_tier3_on_a_completely_empty_state():
    report, source = report_from_state({})

    assert source == "fallback"
    assert report.classification.value == "inconclusive"


def test_fallback_report_satisfies_every_condition_of_the_parser_fallback_detector():
    """
    `_is_parser_fallback_report` requires all four: the sentinel substring, no findings,
    no iocs, and an inconclusive classification. Reword any of it and the rule-based swap
    in analysis_task silently stops firing.
    """
    from app.tasks.analysis_task import _is_parser_fallback_report

    report = fallback_report("raw babble")

    assert "could not be parsed into structured format" in report.primary_reasoning.lower()
    assert report.findings == []
    assert report.iocs == []
    assert report.classification.value == "inconclusive"
    assert _is_parser_fallback_report(report.model_dump(mode="json"))


@pytest.mark.parametrize("text", ["", "no braces at all", "{unclosed", '{"a": '])
def test_extract_json_returns_none_rather_than_raising(text):
    assert extract_json(text) is None
