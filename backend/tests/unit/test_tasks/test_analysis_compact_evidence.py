from app.tasks.analysis_task import (
    _build_analyst_input_evidence,
    _build_iocs_from_evidence,
    _ensure_report_completeness,
    _inject_lexical_contribution,
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


def test_ensure_report_completeness_simplifies_overly_verbose_reasoning():
    evidence = {
        "domain": "adidas-samba.de",
        "vt": {"found": True, "malicious_count": 15, "suspicious_count": 1, "total_vendors": 94},
    }
    verbose_reasoning = (
        "Multiple independent signals indicate maliciousness: (1) signal one; "
        "(2) signal two; (3) signal three; satisfying the attacker-necessity test."
    )
    report = {
        "classification": "malicious",
        "confidence": "high",
        "investigation_state": "concluded",
        "primary_reasoning": verbose_reasoning,
        "legitimate_explanation": "",
        "malicious_explanation": "",
        "findings": [{"id": "f1", "title": "x", "description": "y", "severity": "high", "evidence_refs": []}],
        "iocs": [{"type": "domain", "value": "adidas-samba.de", "context": "Investigated domain", "confidence": "high"}],
        "recommended_action": "block",
        "recommended_steps": ["Block immediately"],
        "risk_score": 90,
    }

    normalized = _ensure_report_completeness(report, evidence, "domain")

    assert "attacker-necessity" not in normalized["primary_reasoning"].lower()
    assert normalized["primary_reasoning"].startswith("Automated analysis for DOMAIN")


def test_lexical_contribution_applies_trusted_external_floor():
    report = {
        "classification": "suspicious",
        "confidence": "medium",
        "recommended_action": "investigate",
        "risk_score": 60,
        "findings": [],
        "key_evidence": [],
        "risk_rationale": "",
    }
    evidence = {
        "url_lexical_ml": {
            "score": 0.01,
            "raw_score": 0.01,
            "label": "low",
            "top_features": ["url_length"],
            "model_source": "lightgbm",
            "calibration_applied": True,
        },
        "vt": {"malicious_count": 15, "suspicious_count": 1},
        "urlscan": {"verdict": "benign", "score": 0},
        "hybrid_analysis": {"verdict": "malicious", "score": 76},
    }

    _inject_lexical_contribution(report, evidence)

    assert report["risk_score"] >= 80
    assert any("Trusted external intelligence floor applied" in line for line in report["key_evidence"])
