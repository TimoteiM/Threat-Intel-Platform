import asyncio
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import detection_quality_service as svc


def _run(rule_id="100002", verdict="benign", **overrides):
    """
    One row as the query now returns it.

    The service used to select whole entities and dig into `result_json`; it
    now selects the stored generated columns that hold those sub-objects, so
    these rows carry them the same way a real row does. `result_json` averaged
    14 KB and the rollup read about 2.8 KB of it.
    """
    payload = {
        "summary": {"indicators_investigated": 2},
        "extraction": {},
        "attack_assessment": overrides.pop("attack_assessment", None),
    }
    payload.update(overrides.pop("payload", {}))
    return SimpleNamespace(
        id=uuid4(),
        detection_rule_id=rule_id,
        detection_rule_name=overrides.pop("rule_name", "Suspicious process"),
        overall_verdict=verdict,
        highest_risk_score=overrides.pop("risk", 10),
        created_at=datetime.now(timezone.utc) - timedelta(hours=1),
        result_summary=payload.get("summary"),
        result_extraction=payload.get("extraction"),
        result_attack_assessment=payload.get("attack_assessment"),
        result_overall_verdict=payload.get("overall_verdict"),
        **overrides,
    )


class _DB:
    """AsyncSession stand-in: first execute() returns runs, then feedback, then a count."""

    def __init__(self, runs, feedback_rows=(), unattributed=0):
        self._responses = [runs, list(feedback_rows), unattributed]
        self._calls = 0

    async def execute(self, _statement):
        response = self._responses[min(self._calls, len(self._responses) - 1)]
        self._calls += 1

        class _Result:
            def scalars(self_inner):
                return SimpleNamespace(all=lambda: response)

            def all(self_inner):
                return response

            def scalar(self_inner):
                return response

        return _Result()


def _quality(runs, feedback_rows=(), unattributed=0, **kwargs):
    return asyncio.run(svc.detection_quality(_DB(runs, feedback_rows, unattributed), **kwargs))


def test_a_rule_whose_alerts_all_conclude_benign_is_flagged_as_noise():
    result = _quality([_run() for _ in range(10)])

    rule = result["rules"][0]
    assert rule["alerts"] == 10
    assert rule["noise_rate"] == 1.0
    assert rule["actionable_rate"] == 0.0
    assert "tuning candidate" in rule["assessment"]


def test_a_rule_with_too_few_alerts_gets_counts_but_no_rate():
    """A proportion from two alerts is not a rate, and pretending otherwise misleads."""
    result = _quality([_run(), _run()])

    rule = result["rules"][0]
    assert rule["alerts"] == 2
    assert rule["scored"] is False
    assert rule["noise_rate"] is None
    assert rule["actionable_rate"] is None
    assert "too few to judge" in rule["assessment"]


def test_an_actionable_rule_reads_as_actionable():
    result = _quality([_run(verdict="malicious", risk=85) for _ in range(6)])

    rule = result["rules"][0]
    assert rule["noise_rate"] == 0.0
    assert rule["actionable_rate"] == 1.0
    assert rule["highest_risk_score"] == 85
    assert "100% concluded malicious or suspicious" in rule["assessment"]


def test_alerts_containing_only_excluded_indicators_are_counted_as_waste():
    runs = [
        _run(payload={"extraction": {"excluded_total": 3}, "summary": {"indicators_investigated": 0}})
        for _ in range(5)
    ]

    rule = _quality(runs)["rules"][0]
    assert rule["fully_excluded_alerts"] == 5
    assert "nothing but excluded indicators" in rule["assessment"]


def test_an_attack_mapping_the_evidence_never_confirms_is_reported():
    assessment = {
        "techniques": [
            {"id": "T1552.002", "status": "not_corroborated"},
            {"id": "T1489", "status": "not_corroborated"},
        ],
        "additional_techniques": [{"id": "T1490"}],
    }
    runs = [_run(attack_assessment=assessment) for _ in range(5)]

    rule = _quality(runs)["rules"][0]
    assert rule["attack_claims"] == 10
    assert rule["attack_confirmed"] == 0
    assert rule["attack_uncorroborated"] == 10
    assert rule["attack_confirm_rate"] == 0.0
    assert rule["attack_additional"] == 5
    assert "corroborated its ATT&CK mapping in only 0%" in rule["assessment"]


def test_rules_are_ordered_worst_signal_to_noise_first():
    runs = [_run(rule_id="noisy") for _ in range(6)]
    runs += [_run(rule_id="useful", verdict="malicious", risk=90) for _ in range(6)]

    result = _quality(runs)
    assert [rule["rule_id"] for rule in result["rules"]] == ["noisy", "useful"]


def test_analyst_feedback_is_folded_in_per_rule():
    runs = [_run(rule_id="100002") for _ in range(6)]
    feedback = [("100002", "false_positive", 4), ("100002", "true_positive", 1)]

    rule = _quality(runs, feedback_rows=feedback)["rules"][0]
    assert rule["analyst_feedback"]["false_positive"] == 4
    assert rule["analyst_feedback"]["false_positive_rate"] == 0.8
    assert "analysts marked 80% of judged alerts false positive" in rule["assessment"]


def test_alerts_without_a_rule_id_are_reported_rather_than_hidden():
    """The totals must visibly not add up to everything."""
    result = _quality([_run() for _ in range(3)], unattributed=17)
    assert result["unattributed_alerts"] == 17
