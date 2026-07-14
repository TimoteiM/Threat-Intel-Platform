import pytest

from app.tasks.analysis_task import (
    _annotate_compact_analyst_report,
    _generate_automated_report,
    _build_prompt_too_long_fallback_report,
    _build_analyst_input_evidence,
    _build_iocs_from_evidence,
    _ensure_report_completeness,
    _inject_lexical_contribution,
    _is_prompt_too_long_error,
    _run_analyst_with_compaction,
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

    assert len(compact["intel"]["related_urls"]) == 80
    assert len(compact["js_analysis"]["captured_requests"]) == 80
    assert len(compact["signals"]) == 80


def test_compact_evidence_digest_tier_reduces_large_sections_more_aggressively():
    evidence = {
        "domain": "example.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-09T00:00:00Z"},
        "intel": {"related_urls": [f"https://a{i}.example.com" for i in range(120)]},
        "js_analysis": {
            "captured_requests": [{"url": f"https://r{i}.example.com"} for i in range(80)],
            "tracking_pixels": [f"https://t{i}.example.com/pixel" for i in range(40)],
        },
        "signals": [{"id": str(i)} for i in range(90)],
    }

    standard = _build_analyst_input_evidence(evidence, tier="standard")
    compact = _build_analyst_input_evidence(evidence, tier="compact")
    digest = _build_analyst_input_evidence(evidence, tier="digest")

    assert len(standard["intel"]["related_urls"]) == 80
    assert len(standard["js_analysis"]["captured_requests"]) == 80
    assert len(digest["intel"]["related_urls"]) < len(compact["intel"]["related_urls"])
    assert len(digest["js_analysis"]["captured_requests"]) < len(compact["js_analysis"]["captured_requests"])
    assert len(digest["signals"]) < len(compact["signals"])
    assert len(digest["js_analysis"]["tracking_pixels"]) < len(compact["js_analysis"]["tracking_pixels"])


def test_analyst_input_includes_grounded_associated_with_digest():
    evidence = {
        "domain": "paypal-account-help.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-09T00:00:00Z"},
        "whois": {"registrant_org": "Domains By Proxy", "domain_age_days": 5},
        "http": {
            "title": "PayPal - Account Security Verification",
            "brand_indicators": ["PayPal"],
            "phishing_indicators": ["Credential collection"],
            "final_url": "https://paypal-account-help.com/login",
        },
        "urlscan": {"page_title": "PayPal Account Verification", "page_url": "https://paypal-account-help.com/login"},
        "brave_osint": {
            "summary": "Search results discuss PayPal phishing lure.",
            "top_hits": [
                {
                    "title": "PayPal phishing campaign using account-help domain",
                    "url": "https://example.com/paypal-phish",
                    "description": "This lure imitates PayPal verification.",
                    "source": "blog",
                    "matched_keywords": ["paypal", "phishing"],
                    "score": 91,
                }
            ],
        },
    }

    compact = _build_analyst_input_evidence(evidence, tier="standard")
    digest = compact["analyst_digest"]

    assert "paypal" in digest["associated_with"].lower()
    assert any("title" in basis.lower() or "osint" in basis.lower() for basis in digest["association_basis"])


def test_automated_report_does_not_escalate_contextual_http_inputs_without_suspicious_domain_context():
    report = _generate_automated_report(
        {
            "domain": "expertware.net",
            "observable_type": "domain",
            "http": {
                "reachable": True,
                "has_login_form": True,
                "phishing_indicators": [
                    "Email-only input form observed",
                    "Credential or account input fields observed (email/username/password/card)",
                    "Third-party brand reference: 'microsoft' on non-microsoft domain",
                ],
            },
            "vt": {
                "found": True,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 91,
            },
            "urlscan": {"verdict": "benign", "score": 0},
            "hybrid_analysis": {"verdict": "clean", "score": 0},
            "whois": {"domain_age_days": 5000},
            "threat_feeds": {},
            "intel": {"blocklist_hits": []},
        },
        "domain",
    )

    assert report["classification"] == "benign"
    assert report["risk_score"] == 15
    finding = next(f for f in report["findings"] if f["id"] == "static_http_phishing")
    assert finding["severity"] == "low"
    assert "were not used to raise risk" in finding["description"]


def test_digest_mode_summarizes_heavyweight_collectors():
    evidence = {
        "domain": "example.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-09T00:00:00Z"},
        "vt": {
            "malicious_count": 7,
            "suspicious_count": 1,
            "total_vendors": 94,
            "vendor_results": [
                {"vendor": f"Vendor{i}", "category": "malicious", "result": "Phishing", "method": "ai"}
                for i in range(30)
            ],
            "tags": [f"tag{i}" for i in range(20)],
        },
        "brave_osint": {
            "top_hits": [
                {
                    "title": f"Finding {i}",
                    "url": f"https://example.com/{i}",
                    "description": "desc" * 40,
                    "source": "blog",
                    "matched_keywords": ["scam"],
                    "score": 70,
                }
                for i in range(8)
            ],
            "observed_results": [{"title": f"Obs {i}", "url": "https://obs", "description": "x", "source": "blog"} for i in range(20)],
            "all_results": [{"title": f"All {i}", "url": "https://all", "description": "x", "source": "blog"} for i in range(20)],
            "summary": "summary" * 80,
        },
        "hybrid_analysis": {
            "items": [
                {
                    "checked": True,
                    "indicator_type": "url",
                    "verdict": "malicious",
                    "analysis_id": "ha-1",
                    "threat_score": 95,
                    "dynamic_io_summary": {
                        "contacted_domains": [f"d{i}.example.com" for i in range(30)],
                        "contacted_ips": [f"1.1.1.{i}" for i in range(30)],
                    },
                    "raw_summary": {"huge": "X" * 4000},
                }
            ]
        },
        "intel": {
            "related_subdomains": [f"s{i}.example.com" for i in range(100)],
            "cert_entries_raw": [{"serial": str(i), "subject": "example"} for i in range(100)],
        },
    }

    digest = _build_analyst_input_evidence(evidence, tier="digest")

    assert len(digest["vt"]["vendor_results"]) <= 5
    assert len(digest["brave_osint"]["top_hits"]) <= 3
    assert digest["brave_osint"]["observed_results"] == []
    assert digest["brave_osint"]["all_results"] == []
    assert len(digest["hybrid_analysis"]["items"][0]["dynamic_io_summary"]["contacted_domains"]) <= 5
    assert len(digest["intel"]["cert_entries_raw"]) == 0
    assert "collector_summaries" in digest["analyst_digest"]


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
    assert len(compact["http"]["title"]) <= 4015


def test_is_prompt_too_long_error_only_matches_prompt_overflow():
    assert _is_prompt_too_long_error(
        RuntimeError(
            "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
            "'message': 'prompt is too long: 205366 tokens > 200000 maximum'}}"
        )
    )
    assert not _is_prompt_too_long_error(RuntimeError("Error code: 429 - rate limited"))


def test_run_analyst_with_compaction_retries_prompt_too_long(monkeypatch):
    calls = []

    def fake_run_analyst_sync(evidence_data, max_iterations, timeout_seconds):
        calls.append(evidence_data["_analyst_compaction_tier"])
        if len(calls) == 1:
            raise RuntimeError(
                "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
                "'message': 'prompt is too long: 205366 tokens > 200000 maximum'}}"
            )
        return (
            {"classification": "benign", "primary_reasoning": "Reasoning", "executive_summary": "Summary"},
            "claude-haiku-4-5-20251001",
        )

    monkeypatch.setattr("app.tasks.analysis_task._run_analyst_sync", fake_run_analyst_sync)

    report, tier, actual_model = _run_analyst_with_compaction(
        {"domain": "example.com", "investigation_id": "x", "timestamps": {}},
        max_iterations=3,
        timeout_seconds=120,
    )

    assert calls == ["standard", "compact"]
    assert tier == "compact"
    assert actual_model == "claude-haiku-4-5-20251001"
    assert report["classification"] == "benign"


def test_run_analyst_with_compaction_does_not_retry_non_size_errors(monkeypatch):
    calls = []

    def fake_run_analyst_sync(evidence_data, max_iterations, timeout_seconds):
        calls.append(evidence_data["_analyst_compaction_tier"])
        raise RuntimeError("Error code: 429 - rate limited")

    monkeypatch.setattr("app.tasks.analysis_task._run_analyst_sync", fake_run_analyst_sync)

    with pytest.raises(RuntimeError, match="rate limited"):
        _run_analyst_with_compaction(
            {"domain": "example.com", "investigation_id": "x", "timestamps": {}},
            max_iterations=3,
            timeout_seconds=120,
        )

    assert calls == ["standard"]


def test_annotate_compact_analyst_report_adds_note_for_non_standard_tier():
    report = {"classification": "benign", "primary_reasoning": "Reasoning", "executive_summary": "Summary"}

    annotated = _annotate_compact_analyst_report(report, used_tier="digest")

    assert annotated["primary_reasoning"].startswith("Analyst used compact evidence")
    assert annotated["executive_summary"].startswith("Analyst used compact evidence")


def test_build_prompt_too_long_fallback_report_uses_automated_report_text():
    automated_report = {
        "classification": "benign",
        "confidence": "medium",
        "investigation_state": "concluded",
        "primary_reasoning": "Base reasoning",
        "executive_summary": "Automated summary",
        "technical_narrative": "Automated technical narrative",
    }

    fallback = _build_prompt_too_long_fallback_report(
        automated_report,
        prompt_error=RuntimeError(
            "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
            "'message': 'prompt is too long: 202696 tokens > 200000 maximum'}}"
        ),
    )

    assert fallback["classification"] == "benign"
    assert fallback["primary_reasoning"].startswith("Analyst prompt exceeded model limits")
    assert "Fallback automated analysis applied." in fallback["primary_reasoning"]
    assert "Analyst error:" not in fallback["primary_reasoning"]


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


def test_ensure_report_completeness_uses_ai_summary_before_automated_primary():
    evidence = {
        "domain": "activelyintimate.com",
        "observable_type": "domain",
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 3, "total_vendors": 91},
        "http": {},
        "threat_feeds": {},
        "intel": {"blocklist_hits": []},
    }
    sparse_report = {
        "classification": "suspicious",
        "confidence": "low",
        "investigation_state": "concluded",
        "primary_reasoning": "",
        "executive_summary": "AI analyst summary with concrete evidence.",
        "recommended_action": "investigate",
    }

    normalized = _ensure_report_completeness(sparse_report, evidence, "domain")

    assert normalized["primary_reasoning"] == "AI analyst summary with concrete evidence."
    assert "Automated analysis" not in normalized["primary_reasoning"]


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


def test_build_iocs_from_evidence_bounds_long_anyrun_urls_and_noise():
    long_url = "https://region1.analytics.google.com/g/collect?" + ("x" * 900)
    evidence = {
        "domain": "lists.com",
        "hybrid_analysis": {
            "items": [
                {
                    "sandbox_intelligence": {
                        "extracted_iocs": [
                            {"type": "url", "value": long_url, "confidence": "medium"}
                        ]
                    },
                    "raw_summary": {
                        "iocs": [
                            {"category": "url", "ioc": f"https://telemetry.example/{idx}"}
                            for idx in range(80)
                        ]
                    },
                }
            ]
        },
    }

    iocs = _build_iocs_from_evidence(evidence, "domain")
    url_iocs = [ioc for ioc in iocs if ioc["type"] == "url"]

    assert all(len(ioc["value"]) <= 512 for ioc in iocs)
    assert any(ioc["value"].endswith("...") for ioc in url_iocs)
    assert len([ioc for ioc in url_iocs if "telemetry.example" in ioc["value"]]) <= 25


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


def test_ensure_report_completeness_keeps_richer_reasoning_for_domain_url_email():
    evidence = {
        "domain": "revantage.eu",
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 94},
    }
    richer_reasoning = (
        "Revantage appears to be a real estate and workplace services brand operating a corporate web presence. "
        "Based on the collected evidence, the domain appears benign because it redirects to a legitimate corporate destination, "
        "shows no meaningful malicious detections, and aligns with an established business use case."
    )
    report = {
        "classification": "benign",
        "confidence": "high",
        "investigation_state": "concluded",
        "primary_reasoning": richer_reasoning,
        "legitimate_explanation": "",
        "malicious_explanation": "",
        "findings": [{"id": "f1", "title": "x", "description": "y", "severity": "low", "evidence_refs": []}],
        "iocs": [{"type": "domain", "value": "revantage.eu", "context": "Investigated domain", "confidence": "high"}],
        "recommended_action": "monitor",
        "recommended_steps": ["Monitor for changes"],
        "risk_score": 15,
    }

    normalized = _ensure_report_completeness(report, evidence, "domain")

    assert normalized["primary_reasoning"] == richer_reasoning


def test_ensure_report_completeness_does_not_flatten_detailed_domain_reasoning():
    evidence = {
        "domain": "example-brand-login.com",
        "vt": {"found": True, "malicious_count": 3, "suspicious_count": 2, "total_vendors": 94},
    }
    detailed_reasoning = (
        "This domain appears to impersonate a consumer login portal rather than a legitimate standalone business service, "
        "because the observed branding and stated purpose are oriented around account access rather than a distinct corporate presence. "
        "Based on the collected evidence, it is likely malicious because multiple vendors flag it for phishing, the infrastructure presents a credential-oriented use case, "
        "and the observed behavior is more consistent with attacker-controlled impersonation than with a legitimate login workflow."
    )
    report = {
        "classification": "malicious",
        "confidence": "high",
        "investigation_state": "concluded",
        "primary_reasoning": detailed_reasoning,
        "legitimate_explanation": "",
        "malicious_explanation": "",
        "findings": [{"id": "f1", "title": "x", "description": "y", "severity": "high", "evidence_refs": []}],
        "iocs": [{"type": "domain", "value": "example-brand-login.com", "context": "Investigated domain", "confidence": "high"}],
        "recommended_action": "block",
        "recommended_steps": ["Block immediately"],
        "risk_score": 88,
    }

    normalized = _ensure_report_completeness(report, evidence, "domain")

    assert normalized["primary_reasoning"] == detailed_reasoning


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
