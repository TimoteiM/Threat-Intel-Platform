from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.services import indicator_history_service as svc


def _row(**overrides):
    base = {
        "id": uuid4(),
        "domain": "evil-corp.net",
        "observable_type": "domain",
        "state": "concluded",
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 88,
        "recommended_action": "block",
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
        "concluded_at": datetime.now(timezone.utc) - timedelta(days=1),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_history_key_is_case_insensitive():
    assert svc.history_key("Domain", "EVIL-corp.NET") == "domain:evil-corp.net"


def test_summarize_keeps_the_newest_row_per_indicator():
    newest = _row(created_at=datetime.now(timezone.utc) - timedelta(days=1), risk_score=88)
    older = _row(created_at=datetime.now(timezone.utc) - timedelta(days=30), risk_score=10)

    summaries = svc._summarize([newest, older])  # rows arrive newest-first

    entry = summaries["domain:evil-corp.net"]
    assert entry["investigation_id"] == str(newest.id)
    assert entry["risk_score"] == 88
    assert entry["total_investigations"] == 2
    assert 0.9 < entry["age_days"] < 1.1


def test_only_recent_concluded_investigations_are_reusable():
    fresh = {"state": "concluded", "classification": "malicious", "age_days": 2.0}
    assert svc.is_reusable(fresh, max_age_days=7) is True

    assert svc.is_reusable({**fresh, "age_days": 30.0}, max_age_days=7) is False
    assert svc.is_reusable({**fresh, "state": "gathering"}, max_age_days=7) is False
    assert svc.is_reusable({**fresh, "classification": None}, max_age_days=7) is False
    assert svc.is_reusable(None) is False


def test_a_benign_verdict_goes_stale_long_before_a_malicious_one():
    """The direction that hurts is benign → malicious, so benign expires first."""
    def prior(classification, age, confidence="high"):
        return {
            "state": "concluded",
            "classification": classification,
            "confidence": confidence,
            "age_days": age,
        }

    # Five days on: the malicious verdict still stands in, the benign one does not.
    assert svc.is_reusable(prior("malicious", 5.0), max_age_days=7) is True
    assert svc.is_reusable(prior("benign", 5.0), max_age_days=7) is False
    assert svc.is_reusable(prior("suspicious", 5.0), max_age_days=7) is False

    # Within its own window a benign verdict is still reused — this is what keeps
    # the corporate domains in every alert off the collectors.
    assert svc.is_reusable(prior("benign", 2.0), max_age_days=7) is True

    # A verdict the engine was unsure of expires far sooner than a confident one.
    assert svc.is_reusable(prior("benign", 2.0, confidence="low"), max_age_days=7) is False
    assert svc.is_reusable(prior("benign", 0.5, confidence="low"), max_age_days=7) is True


def test_an_inconclusive_verdict_is_never_reused():
    """Reusing "we could not tell" saves a lookup and answers nothing."""
    prior = {"state": "concluded", "classification": "inconclusive", "age_days": 0.1}
    assert svc.is_reusable(prior, max_age_days=7) is False
    assert svc.reuse_ceiling_days(prior, max_age_days=7) == 0.0


def test_annotate_tags_matching_indicators_only():
    indicators = [
        {"type": "domain", "value": "evil-corp.net", "investigable": True},
        {"type": "domain", "value": "clean.example", "investigable": True},
    ]
    history = {
        "domain:evil-corp.net": {
            "investigation_id": "abc",
            "state": "concluded",
            "classification": "malicious",
            "age_days": 1.0,
        }
    }

    svc.annotate_indicators(indicators, history, max_age_days=7)

    assert indicators[0]["prior_investigation"]["investigation_id"] == "abc"
    assert indicators[0]["prior_investigation"]["reusable"] is True
    assert "prior_investigation" not in indicators[1]


def test_pairs_skip_indicators_that_are_not_investigated():
    pairs = svc.pairs_from_indicators(
        [
            {"type": "domain", "value": "evil-corp.net", "investigable": True},
            {"type": "email", "value": "a@evil-corp.net", "investigable": False},
            {"type": "ip", "value": "10.0.0.1", "investigable": False},
        ]
    )
    assert pairs == [("domain", "evil-corp.net")]


def test_empty_input_never_builds_a_query():
    assert svc._statement([]) is None
    assert svc.find_prior_investigations_sync([]) == {}
