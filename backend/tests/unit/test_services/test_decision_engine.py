from app.services.decision_engine import apply_decision_to_report, build_decision_report


def test_decision_engine_overrides_ai_verdict_for_contextual_http_only():
    evidence = {
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
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
        "hybrid_analysis": {"verdict": "clean", "score": 0},
        "whois": {"domain_age_days": 5000},
        "threat_feeds": {},
        "intel": {"blocklist_hits": []},
    }
    decision = build_decision_report(evidence, "domain")
    ai_report = {
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 95,
        "recommended_action": "block",
        "primary_reasoning": "AI overreacted to an input field.",
    }

    merged = apply_decision_to_report(ai_report, decision)

    assert merged["classification"] == "benign"
    assert merged["risk_score"] == 15
    assert merged["recommended_action"] == "monitor"
    assert merged["primary_reasoning"] == "AI overreacted to an input field."
    assert merged["decision_engine"]["source"] == "deterministic"


def test_decision_engine_flags_anyrun_malicious_without_ai():
    decision = build_decision_report(
        {
            "domain": "bad.example",
            "observable_type": "domain",
            "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
            "hybrid_analysis": {
                "items": [{"verdict": "malicious", "threat_names": ["phishing"]}],
            },
            "threat_feeds": {},
            "intel": {"blocklist_hits": []},
            "whois": {"domain_age_days": 400},
        },
        "domain",
    )

    assert decision["classification"] == "malicious"
    assert decision["recommended_action"] == "block"
    assert decision["risk_score"] == 90


def test_decision_engine_flags_anyrun_clickfix_tags_as_malicious():
    decision = build_decision_report(
        {
            "domain": "apnsolar.com",
            "observable_type": "domain",
            "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
            "hybrid_analysis": {
                "items": [
                    {
                        "verdict": "clean",
                        "raw_summary": {
                            "summary": {
                                "tags": [
                                    "clickfix",
                                    "phishing",
                                    "exploit-kit",
                                    "tds",
                                    "obfuscated-js",
                                    "etherhiding",
                                    "clearfake",
                                ],
                                "tracker": "ClickFix",
                            }
                        },
                    }
                ],
            },
            "threat_feeds": {},
            "intel": {"blocklist_hits": []},
            "whois": {"domain_age_days": 3204},
        },
        "domain",
    )

    assert decision["classification"] == "malicious"
    assert decision["confidence"] == "high"
    assert decision["recommended_action"] == "block"
    assert any("ClickFix" in item or "clickfix" in item for item in decision["key_evidence"])


def test_decision_engine_does_not_treat_generic_clean_anyrun_tags_as_malicious():
    decision = build_decision_report(
        {
            "domain": "example.com",
            "observable_type": "domain",
            "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
            "hybrid_analysis": {
                "items": [
                    {
                        "verdict": "clean",
                        "raw_summary": {
                            "summary": {
                                "tags": ["credential", "tds"],
                            }
                        },
                    },
                    {
                        "verdict": "clean",
                        "raw_summary": {"tags": ["credential", "tds"]},
                    },
                ],
            },
            "threat_feeds": {},
            "intel": {"blocklist_hits": []},
            "whois": {"domain_age_days": 3204},
        },
        "domain",
    )

    assert decision["classification"] == "benign"
    assert decision["risk_score"] == 15
    assert decision["recommended_action"] == "monitor"


def test_decision_engine_flags_domain_weak_signal_cluster_as_suspicious():
    decision = build_decision_report(
        {
            "domain": "secure-louise.cole.activelyintimate.com",
            "observable_type": "domain",
            "http": {
                "reachable": True,
                "has_login_form": False,
                "phishing_indicators": ["Third-party brand reference: 'meta' on non-meta domain"],
            },
            "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
            "threat_feeds": {"openphish_listed": False, "threatfox_matches": [], "phishtank": {"verified": False}},
            "intel": {"blocklist_hits": []},
            "whois": {"domain_age_days": 2612},
            "hybrid_analysis": {"items": [{"verdict": "clean"}]},
            "url_lexical_ml": {
                "label": "medium",
                "score": 0.4824,
                "top_features": ["has_sensitive_keyword", "entropy", "subdomain_depth"],
            },
            "email_security": {"spoofability_score": "high"},
            "infrastructure_pivot": {
                "shared_hosting_detected": True,
                "registrant_pivots": [{"domains": ["getnumrahqagents.com"]}],
            },
        },
        "domain",
    )

    assert decision["classification"] == "suspicious"
    assert decision["confidence"] == "medium"
    assert decision["risk_score"] == 50
    assert any(f["id"] == "weak_signal_cluster" for f in decision["findings"])
