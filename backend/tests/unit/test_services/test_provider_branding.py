from app.services.provider_branding import normalize_anyrun_branding


def test_normalizes_legacy_anyrun_names_recursively():
    report = {
        "primary_reasoning": "Hybrid Analysis returned suspicious.",
        "findings": [{"evidence_refs": ["hybrid_analysis_digest.items[0].verdict"]}],
    }
    normalized = normalize_anyrun_branding(report)
    assert normalized["primary_reasoning"] == "AnyRun returned suspicious."
    assert normalized["findings"][0]["evidence_refs"] == ["anyrun.items[0].verdict"]
