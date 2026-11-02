"""A SIEM context that was never read must not report as a real negative.

`collect_for_alert` has five statuses. Three mean it read the store —
`collected`, `empty`, `partial` — and two do not: `skipped` (the alert named
nothing queryable) and `unavailable` (the store could not be reached).

The first version of `SiemSource` raised only on `unavailable`/`failed` and
let `skipped` fall through to `logs or []`. The loop records an empty list as
`empty` — "the source answered with no matching events" — so "nobody looked"
became a real negative. Found on live data within minutes: cases #61 and #892
carry `NT AUTHORITY\\SYSTEM` as the principal, which the collector refuses to
query on.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.context_gathering import siem_source as ss
from app.services.context_gathering.mock_source import SourceUnavailable

WHEN = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


class _Ctx:
    def __init__(self, status, logs=None, reason=None):
        self.status, self.logs, self.reason = status, logs or [], reason


def _source(monkeypatch, ctx):
    """Patch the MODULE OBJECT, not a dotted string.

    `monkeypatch.setattr("app.services.alert_log_context_service.collect_for_alert", …)`
    passes in isolation and fails inside the full suite with
    `AttributeError: 'module' object at app.services has no attribute
    'services'` — monkeypatch's string resolution walking the dotted path
    against an already-imported package. This codebase has hit it before;
    the module-object form is the fix.
    """
    from app.services import alert_log_context_service as mod

    monkeypatch.setattr(mod, "collect_for_alert", lambda **_kw: ctx)
    return ss.SiemSource(tenant_id="c00", alert_time=WHEN)


@pytest.mark.parametrize("status,reason", [
    ("skipped", "the alert named neither a device nor an account"),
    ("unavailable", "the CA bundle does not exist"),
    ("failed", "boom"),
    ("", None),
    ("something_new", None),
])
def test_a_status_that_did_not_read_the_store_raises(monkeypatch, status, reason):
    """Anything outside the three read statuses is a refusal, not a negative.

    Parametrised over an unknown status too: a status nobody has seen yet
    must fail closed rather than fall through to an empty list, which is how
    `skipped` got through the first version.
    """
    src = _source(monkeypatch, _Ctx(status, logs=[], reason=reason))
    with pytest.raises(SourceUnavailable) as caught:
        src.query("user_risk_timeline", {"user": "INT\\jdoe"})
    assert "did not read the store" in str(caught.value)
    if reason:
        assert reason.split()[0] in str(caught.value)


@pytest.mark.parametrize("status", ["collected", "empty", "partial"])
def test_a_status_that_did_read_the_store_returns_its_events(monkeypatch, status):
    """The positive control.

    Without it, a fix that raised on every status would pass the test above
    and make the SIEM source permanently useless — the RLS lesson, where six
    refusal tests were green while the feature denied every read.
    """
    events = [{"event_id": "4624", "agent": {"name": "H"}}]
    src = _source(monkeypatch, _Ctx(status, logs=events))
    assert src.query("user_risk_timeline", {"user": "INT\\jdoe"}) == events


def test_an_empty_read_is_still_a_real_negative(monkeypatch):
    """`empty` must pass through as [], because it IS looked-and-found-nothing.

    The distinction this file exists for only means something if the real
    negative survives it.
    """
    src = _source(monkeypatch, _Ctx("empty", logs=[]))
    assert src.query("user_risk_timeline", {"user": "INT\\jdoe"}) == []


def test_the_ip_keyed_template_is_declined_with_its_measurement(monkeypatch):
    """`network.src_ip` is absent on all 100,381 stored events measured."""
    src = _source(monkeypatch, _Ctx("collected", logs=[{"a": 1}]))
    with pytest.raises(SourceUnavailable) as caught:
        src.query("source_address_logons", {"ip": "203.0.113.9"})
    assert "network.src_ip is absent" in str(caught.value)


def test_host_logons_filters_to_the_logon_family(monkeypatch):
    events = [{"event_id": "4624"}, {"event_id": "4688"}, {"event_id": "4672"}]
    src = _source(monkeypatch, _Ctx("collected", logs=events))
    got = src.query("host_logons", {"host": "H1"})
    assert [e["event_id"] for e in got] == ["4624", "4672"]
