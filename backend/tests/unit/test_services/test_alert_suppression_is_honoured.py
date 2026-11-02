"""An alert suppression has to reach the worker, not just the ingest record.

The bug: the API matched the suppression, marked every indicator
non-investigable and wrote that on the run — then the Celery task rebuilt the
indicator list from the stored alert body and inherited none of it. The run
said "suppressed" and investigated anyway: 653 of 664 runs, 3,828 indicator
reports and 186 spawned investigations after the analyst had called the rule
noise.

The indicator-level exclusions were already re-applied in the worker for
exactly this reason. The alert-level one was not.
"""

from __future__ import annotations

import app.services.alert_body_investigation_service as svc


class _Matcher:
    """Matches one alert predicate, and nothing at indicator level."""

    def __init__(self, conditions: dict[str, str] | None):
        self._conditions = conditions

    def match_alert(self, fields):
        if not self._conditions:
            return None
        if all(str(fields.get(k)) == v for k, v in self._conditions.items()):
            return {"id": "excl-1", "reason": "noise", "match_fields": self._conditions}
        return None

    def match(self, *_args, **_kwargs):
        return None


ALERT_BODY = (
    "Alert: Fortigate: URL belongs to an allowed category.\n"
    "Rule: 81640\n"
    "srcip=172.20.20.5 dstip=10.10.30.18 hostname=www.delicitate.ro\n"
    "url=http://www.delicitate.ro/tmp/phpinfo.php\n"
)
FIELDS = {"rule_id": "81640", "rule_name": "Fortigate: URL belongs to an allowed category."}


def _run(monkeypatch, matcher, alert_fields):
    """Drive the pipeline far enough to see what it decided to investigate."""
    captured: dict = {}

    monkeypatch.setattr(svc, "load_exclusion_matcher_sync", lambda: matcher)
    monkeypatch.setattr(svc, "record_exclusion_hits_sync", lambda ids: captured.setdefault("hits", list(ids)))
    # Stop after the decision — everything past it costs collectors.
    monkeypatch.setattr(
        svc, "parse_endpoint_events", lambda body: captured.setdefault("stop", _Stop())
    )

    class _Stop(Exception):
        pass

    try:
        svc.run_alert_body_investigation(
            alert_body=ALERT_BODY, run_id="t", alert_fields=alert_fields, run_ai=False
        )
    except Exception:
        pass
    return captured


def test_a_matching_suppression_makes_every_indicator_uninvestigable(monkeypatch):
    seen: dict = {}

    def _capture(body, max_indicators=30):
        extraction = {
            "indicators": [
                {"value": "www.delicitate.ro", "type": "domain", "investigable": True},
                {"value": "10.10.30.18", "type": "ip", "investigable": True},
            ],
            "total": 2, "investigable_total": 2, "counts": {}, "truncated": False,
            "truncated_count": 0, "characters": len(body),
        }
        seen["extraction"] = extraction
        return extraction

    monkeypatch.setattr(svc, "extract_alert_indicators", _capture)
    captured = _run(monkeypatch, _Matcher(FIELDS), FIELDS)

    extraction = seen["extraction"]
    assert extraction["investigable_total"] == 0
    assert [i["investigable"] for i in extraction["indicators"]] == [False, False]
    # Counted, so the exclusion list can show the rule working.
    assert captured.get("hits") == ["excl-1"]


def test_without_a_match_the_indicators_are_left_alone(monkeypatch):
    seen: dict = {}

    def _capture(body, max_indicators=30):
        extraction = {
            "indicators": [{"value": "www.delicitate.ro", "type": "domain", "investigable": True}],
            "total": 1, "investigable_total": 1, "counts": {}, "truncated": False,
            "truncated_count": 0, "characters": len(body),
        }
        seen["extraction"] = extraction
        return extraction

    monkeypatch.setattr(svc, "extract_alert_indicators", _capture)
    _run(monkeypatch, _Matcher({"rule_id": "99999"}), FIELDS)
    assert seen["extraction"]["indicators"][0]["investigable"] is True


def test_missing_alert_fields_cannot_suppress(monkeypatch):
    """A run with no recorded fields must not be silenced by accident."""
    seen: dict = {}

    def _capture(body, max_indicators=30):
        extraction = {
            "indicators": [{"value": "www.delicitate.ro", "type": "domain", "investigable": True}],
            "total": 1, "investigable_total": 1, "counts": {}, "truncated": False,
            "truncated_count": 0, "characters": len(body),
        }
        seen["extraction"] = extraction
        return extraction

    monkeypatch.setattr(svc, "extract_alert_indicators", _capture)
    _run(monkeypatch, _Matcher(FIELDS), None)
    assert seen["extraction"]["indicators"][0]["investigable"] is True
