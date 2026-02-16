"""Tests for analyst response parser."""

import pytest

from app.analyst.response_parser import parse_response, _extract_json, _extract_narrative_sections


class TestExtractJson:

    def test_fenced_json(self):
        text = '''Here is my analysis:
```json
{"classification": "benign", "confidence": "high"}
```
And here is the report.'''
        result = _extract_json(text)
        assert result is not None
        assert result["classification"] == "benign"

    def test_bare_json(self):
        text = '{"classification": "suspicious", "confidence": "medium"}'
        result = _extract_json(text)
        assert result is not None
        assert result["classification"] == "suspicious"

    def test_no_json(self):
        text = "This is just text with no JSON."
        result = _extract_json(text)
        assert result is None

    def test_nested_json(self):
        text = '''```json
{
  "classification": "malicious",
  "findings": [{"id": "f1", "title": "test"}]
}
```'''
        result = _extract_json(text)
        assert result["classification"] == "malicious"
        assert len(result["findings"]) == 1


class TestExtractNarrative:

    def test_extracts_sections(self):
        text = '''```json
{"classification": "benign"}
```

## Executive Summary
This domain is benign.

## Technical Evidence Analysis
DNS resolves to expected IPs.

## Recommended Actions
Monitor only.'''

        sections = _extract_narrative_sections(text)
        assert "Executive Summary" in sections
        assert "benign" in sections["Executive Summary"]
        assert "Technical Evidence Analysis" in sections
        assert "Recommended Actions" in sections

    def test_empty_text(self):
        sections = _extract_narrative_sections("")
        assert isinstance(sections, dict)


class TestParseResponse:

    def test_full_parse(self):
        text = '''```json
{
  "classification": "suspicious",
  "confidence": "medium",
  "investigation_state": "concluded",
  "primary_reasoning": "Test reasoning",
  "legitimate_explanation": "Could be legit",
  "malicious_explanation": "Could be bad",
  "key_evidence": ["dns.a"],
  "contradicting_evidence": [],
  "data_needed": [],
  "findings": [],
  "iocs": [],
  "recommended_action": "investigate",
  "recommended_steps": ["Check further"],
  "risk_score": 55,
  "risk_rationale": "Medium risk"
}
```

## Executive Summary
A suspicious domain that needs investigation.'''

        report = parse_response(text)
        assert report.classification.value == "suspicious"
        assert report.confidence.value == "medium"
        assert report.risk_score == 55
        assert report.recommended_action.value == "investigate"
        assert "suspicious" in (report.executive_summary or "").lower()

    def test_fallback_on_garbage(self):
        """Should return inconclusive fallback, not crash."""
        report = parse_response("This is not valid at all @#$%")
        assert report.classification.value == "inconclusive"
        assert report.confidence.value == "low"

    def test_handles_missing_fields(self):
        text = '''```json
{
  "classification": "benign",
  "confidence": "high",
  "investigation_state": "concluded",
  "primary_reasoning": "All good",
  "legitimate_explanation": "Normal site",
  "malicious_explanation": "Nothing bad",
  "recommended_action": "monitor"
}
```'''
        report = parse_response(text)
        assert report.classification.value == "benign"
        assert report.findings == []
        assert report.iocs == []
