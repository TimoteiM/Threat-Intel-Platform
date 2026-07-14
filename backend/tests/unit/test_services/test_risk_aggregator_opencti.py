from __future__ import annotations

from app.services import risk_aggregator as svc


def test_aggregate_risk_exposes_zero_opencti_score_when_missing() -> None:
    out = svc.aggregate_risk({})

    assert out["components"]["opencti_score"] == 0.0
    assert all("OpenCTI" not in item for item in out["rationale"])


def test_aggregate_risk_uses_opencti_as_weighted_component() -> None:
    evidence = {
        "opencti": {
            "found": True,
            "score": 60,
            "reports": [{"id": "r1"}],
            "threat_actors": [],
            "malware_families": [],
            "attack_patterns": [],
            "campaigns": [],
            "intrusion_sets": [],
            "indicators": [],
        }
    }

    out = svc.aggregate_risk(evidence)

    assert out["components"]["opencti_score"] > 0.55
    assert out["risk_score"] >= 35
    assert out["risk_level"] == "medium"
    assert any("OpenCTI" in item for item in out["rationale"])


def test_aggregate_risk_applies_medium_floor_for_trusted_opencti_signal() -> None:
    evidence = {
        "opencti": {
            "found": True,
            "score": 52,
            "reports": [{"id": "r1"}],
            "threat_actors": [{"id": "ta1"}],
            "malware_families": [],
            "attack_patterns": [],
            "campaigns": [],
            "intrusion_sets": [],
            "indicators": [],
        }
    }

    out = svc.aggregate_risk(evidence)

    assert out["risk_level"] == "medium"
    assert out["risk_score"] >= 35
    assert any("risk floor raised to medium" in item.lower() for item in out["rationale"])


def test_aggregate_risk_applies_high_floor_for_strong_opencti_signal() -> None:
    evidence = {
        "opencti": {
            "found": True,
            "score": 95,
            "reports": [{"id": "r1"}],
            "threat_actors": [{"id": "ta1"}],
            "malware_families": [{"id": "mw1"}],
            "attack_patterns": [{"id": "ap1"}],
            "campaigns": ["camp-1"],
            "intrusion_sets": ["set-1"],
            "indicators": [{"id": "i1"}],
        }
    }

    out = svc.aggregate_risk(evidence)

    assert out["components"]["opencti_score"] >= 0.85
    assert out["risk_level"] == "high"
    assert out["risk_score"] >= 70
    assert any("risk floor raised to high" in item.lower() for item in out["rationale"])


def test_aggregate_risk_does_not_floor_for_historical_account_compromise_context() -> None:
    evidence = {
        "opencti": {
            "found": True,
            "score": 95,
            "labels": ["compromised user"],
            "notes": ["Historical account compromise involving an expertware user."],
            "reports": [
                {
                    "id": "r1",
                    "name": "Historical compromised account",
                    "description": "A user account was compromised in the past.",
                }
            ],
            "threat_actors": [],
            "malware_families": [],
            "attack_patterns": [],
            "campaigns": [],
            "intrusion_sets": [],
            "indicators": [],
        }
    }

    out = svc.aggregate_risk(evidence)

    assert out["components"]["opencti_score"] == 0.35
    assert out["risk_score"] < 35
    assert out["risk_level"] == "low"
    assert not any("risk floor raised" in item.lower() for item in out["rationale"])
