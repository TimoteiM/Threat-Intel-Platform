from app.services.anyrun_scope import apply_anyrun_scope_guard, task_matches_domain
from app.services.decision_engine import build_decision_report
from app.services.risk_aggregator import aggregate_risk


def _task(url: str, threat_level: int, *tags: str) -> dict:
    return {
        "mainObject": {"type": "url", "name": url},
        "threatLevel": threat_level,
        "tags": list(tags),
    }


def test_domain_scope_uses_url_host_not_victim_email_in_fragment():
    phishing_url = (
        "https://www.google.com/url?q=https%3A%2F%2Fphish.trycloudflare.com"
        "#services@telenetgroup.be"
    )

    assert task_matches_domain(_task(phishing_url, 3), "telenetgroup.be") is False
    assert task_matches_domain(_task("https://mail.telenetgroup.be/login", 0), "telenetgroup.be") is True


def test_scope_guard_recomputes_lookup_from_matching_domain_tasks_only():
    evidence = {
        "domain": "telenetgroup.be",
        "observable_type": "domain",
        "hybrid_analysis": {
            "items": [
                {
                    "mode": "lookup",
                    "verdict": "malicious",
                    "threat_score": 100,
                    "tags": ["phishing", "logokit"],
                    "raw_summary": {
                        "mode": "lookup",
                        "threatName": ["phishing", "logokit"],
                        "summary": {"tags": ["phishing", "logokit"], "tracker": "Logokit"},
                        "relatedTasks": [
                            _task("https://www.google.com/url?q=phish#services@telenetgroup.be", 3, "phishing"),
                            _task("https://one.trycloudflare.com/#services@telenetgroup.be", 3, "phishing"),
                            _task("https://two.trycloudflare.com/#services@telenetgroup.be", 3, "phishing"),
                            _task("https://telenetgroup.be/", 0),
                            _task("https://www.telenetgroup.be/about", 0),
                        ],
                    },
                },
                {"mode": "sandbox", "verdict": "clean", "threat_score": 0},
            ]
        },
        "vt": {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91},
        "threat_feeds": {},
        "intel": {"blocklist_hits": []},
        "whois": {"domain_age_days": 3873},
        "http": {
            "has_login_form": False,
            "phishing_indicators": ["Third-party brand reference: 'google' on non-google domain"],
        },
        "url_lexical_ml": {"score": 0.5528, "label": "medium"},
        "infrastructure_pivot": {"shared_hosting_detected": True},
    }

    apply_anyrun_scope_guard(evidence)
    lookup = evidence["hybrid_analysis"]["items"][0]

    assert lookup["provider_verdict"] == "malicious"
    assert lookup["verdict"] == "clean"
    assert lookup["threat_score"] == 0
    assert lookup["tags"] == []
    assert lookup["scope_validation"]["matched_tasks"] == 2
    assert lookup["scope_validation"]["excluded_tasks"] == 3
    assert lookup["raw_summary"]["summary"]["tags"] == []

    decision = build_decision_report(evidence, "domain")
    assert decision["classification"] == "benign"
    assert decision["risk_score"] == 15
    assert any(f["id"] == "anyrun_scope_exclusions" for f in decision["findings"])
    assert any(f["id"] == "weak_signals_overridden_by_clean_controls" for f in decision["findings"])

    risk = aggregate_risk(evidence)
    assert risk["components"]["sandbox_score"] == 0.1


def test_scope_guard_makes_text_only_lookup_unknown_and_non_scoring():
    evidence = {
        "domain": "telenetgroup.be",
        "observable_type": "domain",
        "hybrid_analysis": {
            "items": [{
                "mode": "lookup",
                "verdict": "malicious",
                "raw_summary": {
                    "mode": "lookup",
                    "relatedTasks": [_task("https://phish.example/#admin@telenetgroup.be", 3, "phishing")],
                },
            }],
        },
    }

    apply_anyrun_scope_guard(evidence)
    lookup = evidence["hybrid_analysis"]["items"][0]

    assert lookup["verdict"] == "unknown"
    assert lookup["scope_validation"]["scope_match"] is False
    assert aggregate_risk(evidence)["components"]["sandbox_score"] == 0.0
