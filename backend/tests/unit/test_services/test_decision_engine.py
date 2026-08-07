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
    assert decision["confidence"] == "high"
    assert decision["recommended_action"] == "block"
    assert decision["risk_score"] == 90


def test_decision_engine_summary_prioritizes_anyrun_residential_sandbox():
    decision = build_decision_report(
        {
            "domain": "apnsolar.com",
            "observable_type": "domain",
            "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
            "http": {"phishing_indicators": ["Third-party brand reference: 'google' on non-google domain"]},
            "email_security": {"spoofability_score": "high"},
            "hybrid_analysis": {
                "items": [
                    {
                        "verdict": "malicious",
                        "threat_score": 100,
                        "threat_names": ["phishing"],
                        "raw_summary": {
                            "mode": "sandbox",
                            "network_profile": {
                                "use_residential_proxy": True,
                                "proxy_country": "US",
                                "anyrun_residential_proxy": True,
                            },
                        },
                    }
                ],
            },
            "threat_feeds": {},
            "intel": {"blocklist_hits": []},
        },
        "domain",
    )

    reasoning = decision["primary_reasoning"]
    assert "AnyRun sandbox verdict: MALICIOUS score 100 via Residential Proxy US" in reasoning
    assert "VirusTotal: 0 malicious" not in reasoning
    assert "High email spoofability" not in reasoning
    assert "Third-party brand reference" not in reasoning


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


def test_clean_anyrun_with_visible_form_reports_incomplete_interaction():
    decision = build_decision_report(
        {
            "domain": "parking-example.test",
            "observable_type": "url",
            "vt": {
                "found": True,
                "malicious_count": 1,
                "suspicious_count": 1,
                "total_vendors": 92,
            },
            "hybrid_analysis": {
                "items": [
                    {
                        "verdict": "clean",
                        "raw_summary": {
                            "source": "anyrun",
                            "mode": "sandbox",
                            "network_profile": {
                                "use_residential_proxy": True,
                                "proxy_country": "RO",
                            },
                            "sensitive_form_detection": {
                                "detected": True,
                                "categories": ["vehicle_identifier"],
                                "interaction_required": True,
                            },
                        },
                    },
                    {
                        "verdict": "clean",
                        "threat_score": 0,
                        "raw_summary": {"source": "anyrun", "mode": "lookup"},
                    },
                ],
            },
        },
        "url",
    )

    assert any(
        "Rendered data-entry form detected (vehicle identifier)" in item
        for item in decision["key_evidence"]
    )
    assert "incomplete form interaction" in decision["primary_reasoning"]
    assert "AnyRun sandbox verdict: CLEAN via Residential Proxy RO" in decision["primary_reasoning"]
    finding = next(
        item for item in decision["findings"]
        if item["id"] == "sensitive_data_entry_form"
    )
    assert "clean sandbox verdict does not cover behavior triggered after submission" in finding["description"]


def test_parseint_obfuscation_heuristic_does_not_override_clean_anyrun_verdict():
    decision = build_decision_report(
        {
            "domain": "established-software.example",
            "observable_type": "domain",
            "vt": {
                "found": True,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 91,
            },
            "whois": {"domain_age_days": 2995},
            "hybrid_analysis": {
                "items": [{
                    "verdict": "clean",
                    "tags": ["obfuscated-js"],
                    "raw_summary": {
                        "source": "anyrun",
                        "mode": "sandbox",
                        "tags": ["obfuscated-js"],
                        "behavior_details": {
                            "network_threats": [{
                                "msg": "SUSPICIOUS [ANY.RUN] JavaScript Obfuscation (ParseInt)",
                                "class": "Misc activity",
                                "priority": 3,
                            }],
                        },
                    },
                }],
            },
        },
        "domain",
    )

    assert decision["classification"] == "benign"
    assert decision["risk_score"] == 15
    assert "verdict: CLEAN" in decision["primary_reasoning"]
    assert "JavaScript Obfuscation (ParseInt)" in decision["primary_reasoning"]
    assert not any(
        "verdict: MALICIOUS" in item
        for item in decision["key_evidence"]
    )
    heuristic = next(
        item for item in decision["findings"]
        if item["id"] == "anyrun_heuristic_observation"
    )
    assert heuristic["severity"] == "low"
    assert "does not override a CLEAN provider verdict" in heuristic["description"]
    assert "Established domain: approximately 2,995 days old" in decision["key_evidence"]


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


# ── Weak-signal scoring: what may and may not make a domain suspicious ────────

def _clean_business_site(**overrides) -> dict:
    """A legitimate 14-year-old company site with a customer login page."""
    evidence = {
        "domain": "expertware.net",
        "target_domain": "expertware.net",
        "observable_type": "domain",
        "http": {
            "reachable": True,
            "has_login_form": True,
            "phishing_indicators": [
                "Credential or account input fields observed (email/username/password/card)",
                "Third-party brand reference: 'microsoft' on non-microsoft domain",
            ],
        },
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
        "whois": {"domain_age_days": 5246},
        "threat_feeds": {},
        "url_lexical_ml": {"label": "low", "score": 0.1466},
        "email_security": {"spoofability_score": "low"},
        "infrastructure_pivot": {
            "shared_hosting_detected": True,
            # A pivot that reaches only the investigated domain: the domain
            # looking at itself, not corroboration.
            "registrant_pivots": [{"domains": ["expertware.net"], "registrar": "Ascio"}],
        },
    }
    evidence.update(overrides)
    return evidence


def test_a_clean_business_site_with_a_login_page_is_benign():
    """The benign path used to be unreachable for any site with a login form."""
    decision = build_decision_report(_clean_business_site(), "domain")
    assert decision["classification"] == "benign"


def test_a_self_referential_registrant_pivot_does_not_score():
    from app.services.decision_engine import _domain_weak_signal_score

    score, reasons = _domain_weak_signal_score(_clean_business_site())
    assert not any("pivot links" in reason for reason in reasons), reasons
    assert score < 3


def test_a_pivot_to_other_domains_still_scores():
    evidence = _clean_business_site(
        infrastructure_pivot={
            "shared_hosting_detected": False,
            "registrant_pivots": [{"domains": ["expertware.net", "lookalike-expertware.com"]}],
        }
    )
    from app.services.decision_engine import _domain_weak_signal_score

    _score, reasons = _domain_weak_signal_score(evidence)
    assert any("pivot links" in reason for reason in reasons), reasons


def test_shared_hosting_alone_does_not_score():
    """Most of the legitimate web is on shared infrastructure."""
    from app.services.decision_engine import _domain_weak_signal_score

    evidence = _clean_business_site(
        infrastructure_pivot={"shared_hosting_detected": True, "registrant_pivots": []},
        url_lexical_ml={"label": "low", "score": 0.1},
        email_security={"spoofability_score": "low"},
    )
    score, reasons = _domain_weak_signal_score(evidence)
    assert score == 0
    assert any("not scored on its own" in reason for reason in reasons)


def test_shared_hosting_corroborates_a_real_signal():
    from app.services.decision_engine import _domain_weak_signal_score

    evidence = _clean_business_site(
        infrastructure_pivot={"shared_hosting_detected": True, "registrant_pivots": []},
        url_lexical_ml={"label": "high", "score": 0.8},
    )
    score, reasons = _domain_weak_signal_score(evidence)
    assert score == 3  # lexical high (2) + shared hosting (1)
    assert any("Shared hosting or crowded" in reason for reason in reasons)


def test_a_sandbox_that_never_ran_does_not_block_a_clean_verdict():
    decision = build_decision_report(_clean_business_site(hybrid_analysis={}), "domain")
    assert decision["classification"] == "benign"


def test_real_signals_still_reach_suspicious_and_malicious():
    """The fixes must not blunt genuine detections."""
    flagged = _clean_business_site(
        vt={"found": True, "malicious_count": 9, "suspicious_count": 0, "total_vendors": 91}
    )
    assert build_decision_report(flagged, "domain")["classification"] == "malicious"

    listed = _clean_business_site(threat_feeds={"openphish_listed": True})
    assert build_decision_report(listed, "domain")["classification"] == "malicious"

    weak_but_real = _clean_business_site(
        url_lexical_ml={"label": "high", "score": 0.82, "top_features": ["has_sensitive_keyword"]},
        email_security={"spoofability_score": "high"},
        infrastructure_pivot={
            "shared_hosting_detected": True,
            "registrant_pivots": [{"domains": ["expertware.net", "other-investigated.com"]}],
        },
    )
    assert build_decision_report(weak_but_real, "domain")["classification"] == "suspicious"


def test_missing_spf_and_dmarc_alone_does_not_make_a_domain_suspicious():
    """A hygiene gap is not an indicator — plenty of real organisations have none."""
    from app.services.decision_engine import _domain_weak_signal_score

    evidence = _clean_business_site(
        email_security={"spoofability_score": "high"},
        infrastructure_pivot={"shared_hosting_detected": True, "registrant_pivots": []},
        url_lexical_ml={"label": "low", "score": 0.1},
    )
    score, reasons = _domain_weak_signal_score(evidence)
    assert score == 0
    assert sum("not scored on its own" in reason for reason in reasons) == 2
    assert build_decision_report(evidence, "domain")["classification"] == "benign"


def test_spoofability_still_corroborates_a_real_signal():
    from app.services.decision_engine import _domain_weak_signal_score

    evidence = _clean_business_site(
        email_security={"spoofability_score": "high"},
        infrastructure_pivot={"shared_hosting_detected": False, "registrant_pivots": []},
        url_lexical_ml={"label": "high", "score": 0.8},
    )
    score, _reasons = _domain_weak_signal_score(evidence)
    assert score == 3  # lexical high (2) + spoofability corroborating (1)


# ── Sources that were collected but never consulted ───────────────────────────

def test_urlscan_malicious_reaches_a_malicious_verdict():
    """
    URLScan was collected, printed in every report, and ignored by the verdict.

    A real case: VirusTotal was rate-limited, URLScan returned malicious with
    score 100 and a phishing tag, and the investigation concluded "benign".
    """
    evidence = _clean_business_site(
        vt={"found": False, "meta": {"status": "failed", "error": "rate limit exceeded"}},
        urlscan={"verdict": "malicious", "score": 100, "tags": ["phishing"]},
    )
    decision = build_decision_report(evidence, "domain")
    assert decision["classification"] == "malicious"
    assert any("URLScan verdict: malicious" in line for line in decision["key_evidence"])


def test_urlscan_suspicious_reaches_a_suspicious_verdict():
    evidence = _clean_business_site(urlscan={"verdict": "suspicious", "score": 40})
    assert build_decision_report(evidence, "domain")["classification"] == "suspicious"


def test_a_failed_reputation_lookup_is_not_a_clean_bill_of_health():
    """A collector outage must never read as 'nothing found, therefore benign'."""
    evidence = _clean_business_site(
        vt={"found": False, "meta": {"status": "failed", "error": "rate limit exceeded"}},
        urlscan={},
        threat_feeds={},
        http={},
        infrastructure_pivot={},
    )
    decision = build_decision_report(evidence, "domain")
    assert decision["classification"] == "inconclusive"
    assert decision["data_needed"], "the report must say what is missing"


def test_a_successful_lookup_that_found_nothing_is_still_clean():
    evidence = _clean_business_site(
        vt={"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 94,
            "meta": {"status": "completed"}},
        threat_feeds={"feeds_checked": ["openphish", "phishtank"]},
    )
    assert build_decision_report(evidence, "domain")["classification"] == "benign"


# ── Domain age ────────────────────────────────────────────────────────────────

def test_a_newly_registered_domain_is_suspicious_even_when_nothing_flagged_it():
    """Clean reputation on a two-week-old domain means nobody has reported it yet."""
    evidence = _clean_business_site(whois={"domain_age_days": 22}, http={})
    decision = build_decision_report(evidence, "domain")
    assert decision["classification"] == "suspicious"
    assert decision["risk_score"] == 50
    assert any("Newly registered domain" in line for line in decision["key_evidence"])


def test_a_recently_registered_domain_counts_as_a_weak_signal():
    from app.services.decision_engine import _domain_weak_signal_score

    score, reasons = _domain_weak_signal_score(_clean_business_site(whois={"domain_age_days": 60}))
    assert any("Recently registered domain" in reason for reason in reasons)
    assert score >= 1


def test_an_established_domain_gains_no_age_signal():
    from app.services.decision_engine import _domain_weak_signal_score

    _score, reasons = _domain_weak_signal_score(_clean_business_site(whois={"domain_age_days": 5246}))
    assert not any("registered domain" in reason for reason in reasons)
