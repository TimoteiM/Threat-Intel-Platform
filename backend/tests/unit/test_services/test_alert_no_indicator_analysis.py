"""
An alert without extractable indicators must still be analysed.

The API used to answer 422 "Nothing to investigate" whenever no URL, domain, IP
or hash could be extracted and no endpoint event fields were recognised. That
discarded the part of an alert an analyst reads first — the raw log line, the
host, the user, the file, the signature name — and returned a refusal instead of
an assessment for exactly the cases that need one: a generic AV detection on a
signed OS binary, or a connection between two internal addresses.

Only a genuinely empty payload is still refused, and that check lives in
_validated_alert_body.
"""

from __future__ import annotations

import re

from app.services.assistant_prompt_service import ALERT_ANALYSIS_SYSTEM_PROMPT


def _prompt() -> str:
    """Whitespace-normalised, so a line wrap cannot break a phrase assertion."""
    return re.sub(r"\s+", " ", ALERT_ANALYSIS_SYSTEM_PROMPT).lower()


def test_prompt_forbids_declining_when_no_indicators_exist():
    prompt = _prompt()
    assert "never decline" in prompt
    assert "nothing to analyse" in prompt
    # Absence of indicators is a fact about the alert, not a reason to stop.
    assert "absence of network or file indicators is a fact" in prompt


def test_prompt_requires_an_explicit_verdict_with_reasoning():
    prompt = _prompt()
    assert "benign, suspicious or malicious" in prompt
    assert "reasoning" in prompt
    # The four things the interpretation must always carry.
    for required in ("what triggered the alert", "asset, user or file", "raw log"):
        assert required in prompt, f"prompt no longer requires: {required}"


def test_prompt_covers_the_generic_detection_false_positive_pattern():
    prompt = _prompt()
    for marker in ("generic", "heur", "false-positive pattern", "signed system binary"):
        assert marker in prompt, f"prompt no longer covers: {marker}"


def test_prompt_covers_internal_only_activity():
    prompt = _prompt()
    assert "private or internal addresses" in prompt
    assert "exfiltration or command-and-control" in prompt
    # Scope finding, never a reason to skip.
    assert "never a reason to skip" in prompt


def test_api_no_longer_rejects_indicator_free_alerts():
    """
    The rejection is gone from the ingest path entirely.

    Asserted against the source because the check was a raise buried in the
    request handler: if someone reinstates it, every indicator-free alert goes
    back to being refused and no other test would notice.
    """
    from pathlib import Path

    source = Path(__file__).resolve().parents[3] / "app" / "api" / "alert_investigations.py"
    text = source.read_text(encoding="utf-8")
    assert "Nothing to investigate" not in text, (
        "the indicator-free rejection is back — indicator-free alerts are valid alerts"
    )
    # The genuinely empty case is still refused, and still in the right place.
    assert "Alert body cannot be empty." in text
