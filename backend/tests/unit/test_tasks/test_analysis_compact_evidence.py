from app.tasks.analysis_task import (
    _build_analyst_input_evidence,
    _build_iocs_from_evidence,
    _ensure_report_completeness,
)


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


def test_ensure_report_completeness_backfills_sparse_ai_output():
    evidence = {
        "domain": "example.com",
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 94},
        "http": {"final_url": "https://example.com"},
    }
    sparse_report = {
        "classification": "benign",
        "confidence": "medium",
        "investigation_state": "concluded",
        "primary_reasoning": "",
        "legitimate_explanation": "",
        "malicious_explanation": "",
        "findings": [],
        "iocs": [],
        "recommended_action": "monitor",
        "recommended_steps": [],
    }

    normalized = _ensure_report_completeness(sparse_report, evidence, "domain")

    assert normalized["primary_reasoning"]
    assert len(normalized["findings"]) > 0
    assert len(normalized["iocs"]) > 0


def test_build_iocs_from_evidence_includes_domain_url_and_ip_pivots():
    evidence = {
        "domain": "example.com",
        "http": {
            "final_url": "https://example.com/login",
            "redirect_chain": [{"url": "http://example.com"}],
        },
        "dns": {"a": ["93.184.216.34"]},
        "hosting": {"ip": "93.184.216.34"},
    }

    iocs = _build_iocs_from_evidence(evidence, "domain")
    ioc_pairs = {(ioc["type"], ioc["value"]) for ioc in iocs}

    assert ("domain", "example.com") in ioc_pairs
    assert ("url", "https://example.com/login") in ioc_pairs
    assert ("ip", "93.184.216.34") in ioc_pairs
