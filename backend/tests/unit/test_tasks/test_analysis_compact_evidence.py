from app.tasks.analysis_task import _build_analyst_input_evidence


def test_compact_evidence_trims_large_lists_for_llm():
    evidence = {
        "domain": "example.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-09T00:00:00Z"},
        "intel": {"related_urls": [f"https://a{i}.example.com" for i in range(120)]},
        "js_analysis": {"captured_requests": [{"url": f"https://r{i}.example.com"} for i in range(80)]},
        "signals": [{"id": str(i)} for i in range(90)],
    }

    compact = _build_analyst_input_evidence(evidence)

    assert len(compact["intel"]["related_urls"]) == 30
    assert len(compact["js_analysis"]["captured_requests"]) == 25
    assert len(compact["signals"]) == 40


def test_compact_evidence_truncates_long_strings():
    long_text = "A" * 5000
    evidence = {
        "domain": "example.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-09T00:00:00Z"},
        "http": {"title": long_text},
    }
    compact = _build_analyst_input_evidence(evidence)
    assert compact["http"]["title"].endswith("...[truncated]")
    assert len(compact["http"]["title"]) <= 2015
