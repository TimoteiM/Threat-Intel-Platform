from app.tasks.analysis_task import (
    _annotate_compact_analyst_report,
    _generate_automated_report,
    _build_prompt_too_long_fallback_report,
    _build_analyst_evidence_digest,
    _build_iocs_from_evidence,
    _ensure_report_completeness,
    _inject_lexical_contribution,
    _is_prompt_too_long_error,
)


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

    digest = _build_analyst_evidence_digest(evidence, tier="standard")

    assert "paypal" in digest["associated_with"].lower()
    assert any("title" in basis.lower() or "osint" in basis.lower() for basis in digest["association_basis"])


def test_analyst_input_accepts_non_ascii_association_candidates():
    evidence = {
        "domain": "weblinks.ru",
        "investigation_id": "x",
        "timestamps": {"started": "2026-07-20T00:00:00Z"},
        "http": {"title": "Веблинкс — Каталог сайтов"},
    }

    digest = _build_analyst_evidence_digest(evidence, tier="standard")

    assert "Веблинкс" in digest["associated_with"]


def test_analyst_input_ignores_punctuation_only_association_candidates():
    evidence = {
        "domain": "example.test",
        "investigation_id": "x",
        "timestamps": {"started": "2026-07-20T00:00:00Z"},
        "http": {"title": "———"},
    }

    digest = _build_analyst_evidence_digest(evidence, tier="standard")

    assert digest["associated_with"] == ""


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


def test_is_prompt_too_long_error_only_matches_prompt_overflow():
    assert _is_prompt_too_long_error(
        RuntimeError(
            "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
            "'message': 'prompt is too long: 205366 tokens > 200000 maximum'}}"
        )
    )
    assert not _is_prompt_too_long_error(RuntimeError("Error code: 429 - rate limited"))


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


# ── Score/label consistency ───────────────────────────────────────────────────

def test_the_score_stays_inside_the_bands_of_its_own_label():
    """
    A blended score must not contradict the verdict it belongs to.

    Blending reputation with the lexical model used to produce "suspicious, risk
    34" — a score the platform's own thresholds read as benign.
    """
    from app.tasks.analysis_task import _score_within_classification_band

    assert _score_within_classification_band(34, {"classification": "suspicious"}) == 35
    assert _score_within_classification_band(64, {"classification": "malicious"}) == 70
    assert _score_within_classification_band(40, {"classification": "benign"}) == 34
    # Inside its band, a score is left exactly as computed.
    assert _score_within_classification_band(52, {"classification": "suspicious"}) == 52
    assert _score_within_classification_band(90, {"classification": "malicious"}) == 90
    # Inconclusive carries no band.
    assert _score_within_classification_band(41, {"classification": "inconclusive"}) == 41
