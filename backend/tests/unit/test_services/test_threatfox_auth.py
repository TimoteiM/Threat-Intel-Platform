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


def _settings(key: str = "") -> SimpleNamespace:
    return SimpleNamespace(abusech_auth_key=key)


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
