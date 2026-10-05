"""Scoring a submitted file: collectors first, then the analyst."""

from app.services.decision_engine import apply_decision_to_report, build_decision_report

NO_VT = {"vt": {"found": False, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 0}}


def _decide(**evidence):
    return build_decision_report({**NO_VT, **evidence}, "hash")


def test_a_file_virustotal_has_never_seen_is_still_scored():
    """VirusTotal not holding a hash is not evidence about the file.

    It is the normal answer for anything not yet seen in the wild, which is
    exactly what a targeted sample looks like. This used to end the assessment
    at "inconclusive, risk undetermined" while the sandbox had returned a
    verdict and the bytes had been measured.
    """
    decision = _decide(
        hybrid_analysis={"items": [{"checked": True, "verdict": "suspicious"}]},
        attachment_analysis={"items": [{"risk_level": "medium",
                                        "suspicious_apis": ["frombase64string"]}]},
        file_content={"files": [{"path": "test_sample.ps1"}]},
        final_risk={"risk_score": 13},
    )

    assert decision["classification"] == "suspicious"
    assert decision["risk_score"] == 45
    assert any("Sandbox verdict" in e for e in decision["key_evidence"])
    assert any("Static analysis" in e for e in decision["key_evidence"])


def test_the_ladder_runs_from_execution_down_to_reading():
    """A sandbox that watched it run outranks a static read of its bytes,
    which outranks having merely opened the file."""
    assert _decide(cape={"verdict": "malicious"})["risk_score"] == 75
    assert _decide(
        hybrid_analysis={"items": [{"checked": True, "verdict": "suspicious"}]}
    )["risk_score"] == 45
    assert _decide(attachment_analysis={"items": [{"risk_level": "medium"}]})["risk_score"] == 30
    assert _decide(file_content={"files": [{"path": "a.js"}]})["risk_score"] == 10


def test_a_composite_can_raise_a_floor_but_never_lower_it():
    """aggregate_risk mixes measured and inferred components. It may add to a
    sandbox verdict; it must not talk one down."""
    high_composite = _decide(cape={"verdict": "malicious"}, final_risk={"risk_score": 92})
    low_composite = _decide(cape={"verdict": "malicious"}, final_risk={"risk_score": 4})

    assert high_composite["risk_score"] == 92
    assert low_composite["risk_score"] == 75


def test_nothing_having_run_is_still_inconclusive():
    """The one honest use of the word. "Nothing was found" and "nothing
    looked" are different answers and must not share a verdict."""
    decision = _decide()

    assert decision["classification"] == "inconclusive"
    assert decision["risk_score"] is None


# --- then the analyst -------------------------------------------------------


def test_the_analyst_decides_only_when_no_collector_did():
    collectors_silent = _decide()
    analyst = {"classification": "benign", "confidence": "medium", "risk_score": None}

    merged = apply_decision_to_report(analyst, collectors_silent)

    assert merged["classification"] == "benign"
    assert merged["risk_score"] == 10
    assert merged["decision_engine"]["source"] == "analyst_fallback"


def test_a_collector_verdict_outranks_the_analyst():
    """The priority, stated as a test. The collectors measured something; the
    analyst read it."""
    sandbox_says_malicious = _decide(cape={"verdict": "malicious"})
    analyst_says_benign = {"classification": "benign", "confidence": "high", "risk_score": 5}

    merged = apply_decision_to_report(analyst_says_benign, sandbox_says_malicious)

    assert merged["classification"] == "malicious"
    assert merged["risk_score"] == 75
    assert merged["decision_engine"].get("source") != "analyst_fallback"


def test_an_analyst_verdict_is_never_recorded_as_high_confidence():
    """One reading, with nothing corroborating it."""
    merged = apply_decision_to_report(
        {"classification": "malicious", "confidence": "high", "risk_score": None},
        _decide(),
    )

    assert merged["classification"] == "malicious"
    assert merged["confidence"] == "medium"
    assert merged["risk_score"] == 70


def test_an_inconclusive_analyst_does_not_override_anything():
    merged = apply_decision_to_report(
        {"classification": "inconclusive", "confidence": "low"}, _decide()
    )

    assert merged["classification"] == "inconclusive"
    assert merged["risk_score"] is None
