import os

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import reverdict_service as svc


# ── What counts as a change worth telling somebody about ──────────────────────


@pytest.mark.parametrize(
    "previous,current,expected",
    [
        ("benign", "malicious", True),        # the case the whole feature exists for
        ("benign", "suspicious", True),
        ("malicious", "benign", True),        # a retraction matters too
        ("suspicious", "malicious", True),    # worsening between actionable states
        ("benign", "inconclusive", False),    # both mean "nothing to do"
        ("inconclusive", "benign", False),
        ("malicious", "malicious", False),    # agreement is silence
        (None, "benign", False),
        ("benign", None, False),
    ],
)
def test_only_meaningful_verdict_changes_notify(previous, current, expected):
    assert svc._is_meaningful_change(previous, current) is expected


def test_a_change_notifies_every_sender_that_reported_the_old_verdict(monkeypatch):
    dispatched = []

    monkeypatch.setattr(
        svc,
        "_runs_reporting",
        lambda domain: [
            ("run-1", "http://soc.internal/hook", "ALERT-1"),
            ("run-2", "http://other.internal/hook", "ALERT-2"),
        ],
    )

    class _Task:
        @staticmethod
        def delay(run_id, **kwargs):
            dispatched.append((run_id, kwargs))

    import app.tasks.alert_callback_task as callback_task

    monkeypatch.setattr(callback_task, "deliver_alert_callback", _Task)

    sent = svc.notify_verdict_change(
        "evil-corp.net",
        previous_classification="benign",
        current_classification="malicious",
        investigation_id="inv-9",
        risk_score=85,
    )

    assert sent == 2
    run_id, kwargs = dispatched[0]
    assert run_id == "run-1"
    assert kwargs["event"] == "alert.updated"
    assert kwargs["override_url"] == "http://soc.internal/hook"
    update = kwargs["extra"]
    assert update["reason"] == "indicator_verdict_changed"
    assert update["indicator"] == "evil-corp.net"
    assert update["previous_classification"] == "benign"
    assert update["current_classification"] == "malicious"
    assert "has since been re-assessed as malicious" in update["message"]


def test_no_notification_when_the_verdict_did_not_meaningfully_change(monkeypatch):
    def explode(_domain):
        raise AssertionError("must not even look for runs when nothing changed")

    monkeypatch.setattr(svc, "_runs_reporting", explode)

    assert svc.notify_verdict_change(
        "evil-corp.net",
        previous_classification="benign",
        current_classification="inconclusive",
        investigation_id="inv-9",
    ) == 0


def test_re_notification_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(
        svc, "get_settings", lambda: type("S", (), {"alert_reverdict_notify": False})()
    )
    assert svc.notify_verdict_change(
        "evil-corp.net",
        previous_classification="benign",
        current_classification="malicious",
        investigation_id="inv-9",
    ) == 0


# ── Auto-enrolment ────────────────────────────────────────────────────────────


def _settings(**overrides):
    base = {
        "alert_watchlist_autoenrol": True,
        "alert_watchlist_autoenrol_min_risk": 40,
        "alert_watchlist_autoenrol_interval": "weekly",
    }
    base.update(overrides)
    return type("S", (), base)()


def _report(value, kind="domain", status="completed", risk=80, classification="malicious"):
    return {
        "status": status,
        "indicator": {"type": kind, "value": value},
        "verdict": {"classification": classification, "risk_score": risk},
    }


def test_only_risky_investigated_domains_are_enrolled(monkeypatch):
    added = []

    class _Session:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def execute(self, _statement):
            from types import SimpleNamespace

            return SimpleNamespace(scalar_one_or_none=lambda: None)

        def add(self, row):
            added.append(row)

        def commit(self):
            pass

    monkeypatch.setattr(svc, "Session", _Session)
    monkeypatch.setattr(svc, "get_settings", lambda: _settings())

    enrolled = svc.enrol_indicators(
        [
            _report("evil-corp.net"),                                  # enrolled
            _report("low-risk.example", risk=5),                       # below threshold
            _report("excluded.example", status="excluded"),            # never investigated
            _report("reused.example", status="reused"),                # already known
            _report("8.8.8.8", kind="ip"),                             # nothing re-checks an IP
            _report("a" * 64, kind="hash"),                            # nor a hash
        ],
        run_id="run-1",
    )

    assert enrolled == 1
    assert added[0].domain == "evil-corp.net"
    assert added[0].added_by == "alert-ingest"
    assert added[0].schedule_interval == "weekly"
    assert added[0].status == "active"
    assert "run-1" in added[0].notes


def test_auto_enrolment_never_overrides_an_existing_entry(monkeypatch):
    added = []

    class _Session:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def execute(self, _statement):
            from types import SimpleNamespace

            return SimpleNamespace(scalar_one_or_none=lambda: object())   # already watched

        def add(self, row):
            added.append(row)

        def commit(self):
            pass

    monkeypatch.setattr(svc, "Session", _Session)
    monkeypatch.setattr(svc, "get_settings", lambda: _settings())

    assert svc.enrol_indicators([_report("evil-corp.net")], run_id="run-1") == 0
    assert added == []


def test_auto_enrolment_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(svc, "get_settings", lambda: _settings(alert_watchlist_autoenrol=False))
    assert svc.enrol_indicators([_report("evil-corp.net")]) == 0
