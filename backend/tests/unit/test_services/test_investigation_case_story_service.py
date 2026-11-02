from app.services.investigation_case_story_service import (
    build_recomputed_case_summary,
    build_saved_case_story,
)


def test_deferred_anyrun_summary_is_analyst_facing_and_explains_form_gap():
    summary = build_recomputed_case_summary(
        observable="https://parking-example.test/ro",
        reason="deferred_anyrun_completed",
        evidence={
            "hybrid_analysis": {
                "items": [{
                    "verdict": "clean",
                    "raw_summary": {
                        "source": "anyrun",
                        "mode": "sandbox",
                        "sensitive_form_detection": {
                            "detected": True,
                            "categories": ["vehicle_identifier"],
                        },
                    },
                }],
            },
        },
        report={
            "classification": "suspicious",
            "confidence": "low",
            "risk_score": 34,
            "key_evidence": [
                "AnyRun sandbox verdict: CLEAN with incomplete form interaction",
                "Rendered data-entry form detected (vehicle identifier)",
                "VirusTotal: 1 malicious, 1 suspicious of 92",
                "Domain was registered this week",
            ],
        },
    )

    assert "deferred_anyrun_completed" not in summary
    assert "Deterministic report recomputed" not in summary
    assert "visible form requesting vehicle identifier" in summary
    assert "not proof that the form is safe" in summary
    assert "remains SUSPICIOUS with a risk score of 34/100 at low confidence" in summary


def test_saved_story_treats_clean_anyrun_as_contradiction_not_decisive_evidence():
    story = build_saved_case_story(
        model="Automated report synthesis",
        context={
            "canonical": {
                "observable": "https://parking-example.test/ro",
                "verdict": "suspicious",
                "risk_score": 34,
                "confidence": "low",
            },
            "report": {
                "primary_reasoning": "A rendered form was detected and requires interaction review.",
                "findings": [
                    {
                        "id": "anyrun_verdict",
                        "title": "AnyRun sandbox verdict: CLEAN",
                        "description": "The provider returned clean, but did not submit the form.",
                        "severity": "info",
                        "evidence_refs": ["hybrid_analysis.items"],
                    },
                    {
                        "id": "sensitive_data_entry_form",
                        "title": "Rendered data-entry form requires interaction review",
                        "description": "A vehicle identifier form was visible but not submitted.",
                        "severity": "medium",
                        "evidence_refs": ["hybrid_analysis.items.0.raw_summary.sensitive_form_detection"],
                    },
                ],
            },
            "derived_intelligence": {},
            "evidence": {},
        },
    )

    assert story.strongest_evidence[0].title == "Rendered data-entry form requires interaction review"
    assert story.contradicting_evidence[0].title == "AnyRun sandbox verdict: CLEAN"
    assert story.visual_assessment.performed is True
    assert "interaction-dependent blind spot" in story.why_it_matters


def test_heuristic_reclassification_summary_explains_benign_controls():
    summary = build_recomputed_case_summary(
        observable="proda.ai",
        reason="anyrun_heuristic_reclassified",
        evidence={
            "hybrid_analysis": {
                "items": [{
                    "verdict": "clean",
                    "raw_summary": {"source": "anyrun", "mode": "sandbox"},
                }],
            },
        },
        report={
            "classification": "benign",
            "confidence": "medium",
            "risk_score": 14,
            "key_evidence": [
                "AnyRun sandbox verdict: CLEAN via Residential Proxy BE",
                "AnyRun heuristic observation: JavaScript Obfuscation (ParseInt)",
                "VirusTotal: 0 malicious, 0 suspicious of 91",
                "Established domain: approximately 2,995 days old",
                "Static HTTP input/brand observations were treated as contextual because no independent suspicious-domain signal was present",
            ],
        },
    )

    assert "separating the provider verdict from heuristic observations" in summary
    assert "ANY.RUN returned CLEAN" in summary
    assert "is now BENIGN with a risk score of 14/100" in summary
    assert "VirusTotal: 0 malicious, 0 suspicious of 91" in summary
