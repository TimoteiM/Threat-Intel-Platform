from app.analyst.prompt_builder import build_messages
from app.models.schemas import CollectedEvidence


def test_build_messages_includes_analyst_digest_block():
    evidence = CollectedEvidence(
        domain="example.com",
        investigation_id="inv-1",
        timestamps={},
        analyst_digest={
            "associated_with": "Appears associated with a login-themed PayPal lure.",
            "association_basis": ["HTTP title references PayPal", "Brave OSINT hit mentions phishing lure"],
        },
    )

    _, messages = build_messages(evidence, iteration=0, max_iterations=1)

    content = messages[0]["content"]
    assert "<analyst_digest>" in content
    assert "Appears associated with a login-themed PayPal lure." in content


def test_anyrun_digest_is_not_exposed_as_hybrid_analysis_provider():
    evidence = CollectedEvidence(
        domain="example.com",
        investigation_id="inv-2",
        timestamps={},
        analyst_digest={
            "collector_summaries": {
                "hybrid_analysis": {"items": [{"verdict": "suspicious"}]},
            },
        },
    )

    _, messages = build_messages(evidence, iteration=0, max_iterations=1)
    content = messages[0]["content"]
    assert '"anyrun"' in content
    assert "hybrid_analysis_digest" not in content
