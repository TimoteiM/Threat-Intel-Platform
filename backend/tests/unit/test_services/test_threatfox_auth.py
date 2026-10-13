"""ThreatFox authentication: the header, the guard, and the key not leaking.

Every one of the 6,376 lookups stored before 2026-10-12 recorded
`ThreatFox: HTTPError` with `threatfox_count` 0. The cause was not the feed:
the request sent `API-KEY: ""` where abuse.ch documents `Auth-Key`, and there
was no setting anywhere to put a key into. Both halves are pinned here, along
with the thing that matters more than either — that a configured key reaches
exactly one place and appears in nothing that is logged, stored or returned.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services import ip_lookup_service

SECRET = "test-only-not-a-real-key-7f3a"


class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _settings(key: str = "", *, enabled: bool = True) -> SimpleNamespace:
    """Settings for the ThreatFox request path.

    `threatfox_enabled=True` by default here, and the platform default is
    False as of 2026-10-13 — these tests assert how the *request* behaves,
    which is still the required behaviour and the thing that has to be right
    before the feed can be turned back on. The switch has its own tests.
    """
    return SimpleNamespace(abusech_auth_key=key, threatfox_enabled=enabled)


@pytest.fixture
def no_abuseipdb():
    """AbuseIPDB out of the way; these tests are about the other feed."""
    with patch.object(ip_lookup_service, "configured_abuseipdb_api_keys",
                      return_value=[]):
        yield


def test_without_a_key_no_request_is_made(no_abuseipdb) -> None:
    """A call with no key can only 401, and a round trip to earn a 401 is how
    a missing credential spent a month looking like a feed outage."""
    with patch.object(ip_lookup_service, "get_settings", return_value=_settings()), \
         patch.object(ip_lookup_service, "requests") as req:
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")
    req.post.assert_not_called()

    status = result["threatfox_status"]
    assert status["absent"] is True
    assert status["kind"] == "check_failed"
    assert status["raw"] == "no_auth_key"
    assert "ABUSECH_AUTH_KEY" in status["reason"]


def test_the_missing_key_is_not_reported_as_an_outage(no_abuseipdb) -> None:
    """'Not reachable' sends someone to check the network. It is a credential."""
    with patch.object(ip_lookup_service, "get_settings", return_value=_settings()), \
         patch.object(ip_lookup_service, "requests"):
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    reason = result["threatfox_status"]["reason"].lower()
    assert "missing credential" in reason
    assert "not a feed outage" in reason


def test_a_configured_key_is_sent_as_the_documented_header(no_abuseipdb) -> None:
    """abuse.ch documents `Auth-Key`. The code sent `API-KEY`, which 401s."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": "ok", "data": []})
        ip_lookup_service.perform_ip_lookup("8.8.8.8")

    headers = req.post.call_args.kwargs["headers"]
    assert headers == {"Auth-Key": SECRET}
    assert "API-KEY" not in headers


def test_the_key_never_reaches_the_stored_row(no_abuseipdb) -> None:
    """`result_json` is persisted to Postgres and read back by the panel."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": "ok", "data": []})
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert SECRET not in repr(result)
    record = ip_lookup_service.build_ip_lookup_record(result)
    assert SECRET not in repr(record.result_json)


def test_the_key_never_reaches_the_log_or_the_error_list(
    no_abuseipdb, caplog
) -> None:
    """The failure path formats the exception; an exception can carry a URL or
    a header, so what gets logged is the type name and nothing else."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.side_effect = RuntimeError(f"boom Auth-Key: {SECRET}")
        with caplog.at_level(logging.WARNING):
            result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert SECRET not in caplog.text
    assert SECRET not in repr(result)
    assert "ThreatFox: RuntimeError" in result["errors"]
    assert not any(SECRET in e for e in result["errors"])


def test_a_refusal_and_an_exception_are_both_failures_but_not_the_same_one(
    no_abuseipdb,
) -> None:
    """abuse.ch refusing a query and the request never completing are both
    `check_failed`, and `raw` has to keep them apart — one is a thing the feed
    said, the other is a thing that happened to us."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": "unknown_operation"})
        refused = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.side_effect = RuntimeError("connection reset")
        threw = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert refused["threatfox_status"]["kind"] == "check_failed"
    assert threw["threatfox_status"]["kind"] == "check_failed"
    assert refused["threatfox_status"]["raw"] == "unknown_operation"
    assert threw["threatfox_status"]["raw"] == "RuntimeError"


def test_the_panel_prefers_the_stored_reason(no_abuseipdb) -> None:
    """'No key configured' and 'feed unreachable' name different owners."""
    from app.services.indicator_enrichment_service import _threatfox

    shown = _threatfox({
        "errors": ["ThreatFox: no abuse.ch Auth-Key configured"],
        "threatfox_status": {
            "absent": True, "kind": "check_failed", "raw": "no_auth_key",
            "reason": "ThreatFox was not asked about this address: no "
                      "abuse.ch Auth-Key is configured.",
        },
    })
    assert shown["raw"] == "no_auth_key"
    assert "not asked" in shown["reason"]


def test_an_old_row_still_reports_an_absence(no_abuseipdb) -> None:
    """6,376 rows predate threatfox_status and must not read as 'no hits'."""
    from app.services.indicator_enrichment_service import _threatfox

    shown = _threatfox({"errors": ["ThreatFox: HTTPError"], "threatfox": []})
    assert shown.kind == "check_failed"
    assert shown.raw == "ThreatFox: HTTPError"


# --- the status vocabulary, measured against the live API 2026-10-12 --------
#
# abuse.ch does not document these. Probed deliberately: a listed tag gave
# `ok`; an unlisted address and a malformed term both gave `no_result` at 200;
# a bad query verb gave `unknown_operation`; a wrong key gave 403
# `unknown_auth_key`; an empty key gave a bare 401, which is the HTTPError
# every one of the 6,376 historical rows recorded.


def test_not_listed_is_a_real_negative_not_a_failed_check(no_abuseipdb) -> None:
    """The bug this module exists to prevent, running the other way.

    `no_result` was being reported as "declined the query", so once
    authentication started working every unlisted address — which is most of
    them — would have shown an analyst a failed check instead of "no hits".
    """
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": "no_result"})
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert "threatfox_status" not in result
    assert result["threatfox"] == []
    assert not any("threatfox" in e.lower() for e in result["errors"])


def test_not_listed_counts_as_the_feed_working(no_abuseipdb) -> None:
    """Otherwise the health monitor reads 'broken' from correct answers."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req, \
         patch.object(ip_lookup_service.health, "record") as rec:
        req.post.return_value = _Resp({"query_status": "no_result"})
        ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert rec.call_args.kwargs["ok"] is True


@pytest.mark.parametrize("status", ["unknown_operation", "unknown_auth_key"])
def test_a_refused_query_is_still_a_failed_check(no_abuseipdb, status) -> None:
    """Nothing was checked, so nothing is known — and it is not 'no hits'."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": status})
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert result["threatfox_status"]["kind"] == "check_failed"
    assert result["threatfox_status"]["raw"] == status
    assert "not a 'no hits' result" in result["threatfox_status"]["reason"]


def test_a_real_negative_and_a_sentinel_zero_are_distinguishable() -> None:
    """Both live in `ip_lookups` now, and the count cannot tell them apart."""
    from app.services.indicator_enrichment_service import _threatfox

    real_negative = _threatfox({"errors": [], "threatfox": []})
    assert real_negative == []

    sentinel = _threatfox({"errors": ["ThreatFox: HTTPError"], "threatfox": []})
    assert sentinel.kind == "check_failed"


def test_an_unseen_status_says_so_rather_than_picking_a_side(
    no_abuseipdb,
) -> None:
    """The vocabulary was measured, not documented, so it can grow.

    An unrecognised value must not land in `ok`, in `no_result`, or in
    `check_failed`. The first two would fabricate a result; the third asserts
    "the check did not run", which a future status for a rate limit, a partial
    result or a deprecated endpoint would make false.
    """
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req:
        req.post.return_value = _Resp({"query_status": "rate_limited_soon"})
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    status = result["threatfox_status"]
    assert status["kind"] == "unrecognised_absence"
    assert status["raw"] == "rate_limited_soon"
    assert result["threatfox"] == []
    assert "does not recognise" in status["reason"]


def test_an_unseen_status_counts_against_feed_health(no_abuseipdb) -> None:
    """Unknown resolves toward alarm, not toward reassurance. A monitor that
    reads silence as success is a tracked defect class in this project."""
    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings(SECRET)), \
         patch.object(ip_lookup_service, "requests") as req, \
         patch.object(ip_lookup_service.health, "record") as rec:
        req.post.return_value = _Resp({"query_status": "rate_limited_soon"})
        ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert rec.call_args.kwargs["ok"] is False


def test_the_refusal_set_holds_only_what_was_observed() -> None:
    """A set documented as measured containing a guess is how an unrecognised
    status becomes a confident claim without anyone deciding to make one."""
    assert ip_lookup_service.THREATFOX_REFUSALS == {
        "unknown_operation", "unknown_auth_key",
    }
    assert "no_result" not in ip_lookup_service.THREATFOX_REFUSALS


def test_the_panel_shows_an_unrecognised_status_as_an_absence() -> None:
    from app.services.indicator_enrichment_service import _threatfox

    shown = _threatfox({
        "errors": [],
        "threatfox_status": {
            "absent": True, "kind": "unrecognised_absence",
            "raw": "rate_limited_soon", "reason": "... does not recognise ...",
        },
    })
    assert shown["kind"] == "unrecognised_absence"


# --- the second caller, missed for a day -----------------------------------
#
# `threat_feeds_collector._query_threatfox` carried the identical two defects
# and was not fixed when `ip_lookup_service` was. "Found the bug" and "found
# every instance of the bug" are different claims; only the first was made
# good on, and the collector went on 401ing in the log for another day.

def test_both_threatfox_callers_send_the_documented_header() -> None:
    """A grep assertion on purpose: the defect was a second call site, so the
    guard has to be about call sites rather than about one function."""
    import pathlib

    root = pathlib.Path(ip_lookup_service.__file__).resolve().parents[1]
    callers = [
        p for p in root.rglob("*.py")
        if "threatfox-api.abuse.ch" in p.read_text(encoding="utf-8")
    ]
    assert len(callers) >= 2, "expected both known callers to be found"
    for path in callers:
        body = path.read_text(encoding="utf-8")
        assert '"API-KEY"' not in body, f"{path.name} still sends the wrong header"
        assert "Auth-Key" in body, f"{path.name} does not send Auth-Key"


def test_the_collector_distinguishes_no_result_from_not_asked(monkeypatch) -> None:
    """`query_status != "ok" -> []` reads downstream as "not in ThreatFox".
    That is true for `no_result` and false for every other status."""
    from app.collectors import threat_feeds_collector as mod

    collector = mod.ThreatFeedsCollector.__new__(mod.ThreatFeedsCollector)
    collector.timeout = 5

    # The collector imports get_settings inside the function, so it resolves
    # from app.config at call time — patch there, not on the module.
    import app.config as config_mod

    # `threatfox_enabled=True`: this test is about the request path, which
    # still has to be right before the feed can be turned back on.
    monkeypatch.setattr(config_mod, "get_settings",
                        lambda: _settings(SECRET))
    monkeypatch.setattr(mod, "record_provider_request", lambda *_: None)

    monkeypatch.setattr(mod, "requests", type("R", (), {
        "post": staticmethod(lambda *a, **k: _Resp({"query_status": "no_result"}))
    }))
    assert collector._query_threatfox("example.com") == []

    monkeypatch.setattr(mod, "requests", type("R", (), {
        "post": staticmethod(lambda *a, **k: _Resp({"query_status": "unknown_auth_key"}))
    }))
    with pytest.raises(RuntimeError, match="not a 'no hits' result"):
        collector._query_threatfox("example.com")


def test_the_collector_refuses_to_query_without_a_key(monkeypatch) -> None:
    from app.collectors import threat_feeds_collector as mod

    collector = mod.ThreatFeedsCollector.__new__(mod.ThreatFeedsCollector)
    collector.timeout = 5
    import app.config as config_mod

    monkeypatch.setattr(config_mod, "get_settings",
                        lambda: SimpleNamespace(abusech_auth_key=""))
    with pytest.raises(RuntimeError, match="missing credential"):
        collector._query_threatfox("example.com")


# ─── the switch itself ────────────────────────────────────────────────────

def test_the_switch_stops_the_request_without_faking_a_clean_result():
    """Off by default platform-wide as of 2026-10-13. The dangerous direction
    is a disabled feed reading as a feed that answered and found nothing, so
    the absence is what is asserted — not merely that no request was made."""
    from app.services.absence import is_absent

    with patch.object(ip_lookup_service, "get_settings",
                      return_value=_settings("a-key", enabled=False)), \
         patch.object(ip_lookup_service.requests, "post") as post:
        result = ip_lookup_service.perform_ip_lookup("8.8.8.8")

    assert not post.called, "a request was sent while the feed is switched off"
    status = result.get("threatfox_status") if isinstance(result, dict) else None
    assert is_absent(status), (
        "a switched-off feed did not record an absence, so an empty match "
        "list reads as 'asked and nothing listed'"
    )


def test_the_collector_refuses_rather_than_returning_empty():
    """`threat_feeds_collector` raises, so the caller records a feed that did
    not answer. Returning `[]` would be the seven-month ThreatFox shape."""
    from app.collectors.threat_feeds_collector import ThreatFeedsCollector

    c = ThreatFeedsCollector(
        domain="office.com",
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=10,
    )
    with patch("app.collectors.threat_feeds_collector.get_settings",
               return_value=_settings("a-key", enabled=False)):
        with pytest.raises(RuntimeError, match="switched off"):
            c._query_threatfox("office.com")
