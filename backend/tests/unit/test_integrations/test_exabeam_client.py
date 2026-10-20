"""The Exabeam search connector, against the documented contract.

The API reference states: `POST {base_url}/search/v2/events`, OAuth2 with an
`Authorization: Bearer` header, and a body of `fields`, `startTime`,
`endTime`, `filter` required with `limit`, `groupBy`, `orderBy`, `distinct`
optional. These assert that contract and the two things that must never
happen: a credential in an error, and customer log events in one.

No network. Every test substitutes the transport, because a test that calls a
customer's Exabeam is not a unit test and because the one thing worse than an
unverified connector is one that is verified by spending somebody's quota.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.integrations import exabeam_client as ex

TOKEN = "tok-THIS-MUST-NEVER-APPEAR"
BASE = "https://api.eu.exabeam.cloud"


class _Capture:
    """Stands in for httpx.post and records what was sent."""

    def __init__(self, status=200, json_body=None):
        self.status = status
        self.json_body = json_body if json_body is not None else {"rows": []}
        self.url = None
        self.payload = None
        self.headers = None

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.url, self.payload, self.headers = url, json, headers
        request = httpx.Request("POST", url)
        return httpx.Response(self.status, json=self.json_body, request=request)


def _verify(monkeypatch, capture):
    monkeypatch.setattr(ex.httpx, "post", capture)
    return ex.verify(config={"base_url": BASE}, secrets={"token": TOKEN})


# ── the documented request ───────────────────────────────────────────────


def test_the_request_matches_the_documented_contract(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(ex.httpx, "post", cap)
    start = datetime(2026, 4, 1, tzinfo=timezone.utc)
    end = datetime(2026, 4, 8, tzinfo=timezone.utc)

    ex.search(token=TOKEN, base_url=BASE, filter_expression='product:"Audit Log"',
              fields=["id", "activity"], start_time=start, end_time=end)

    assert cap.url == f"{BASE}/search/v2/events"
    assert cap.headers["Authorization"] == f"Bearer {TOKEN}"
    assert cap.headers["content-type"] == "application/json"
    body = cap.payload
    for required in ("fields", "startTime", "endTime", "filter"):
        assert required in body, f"{required} is documented as required"
    assert body["fields"] == ["id", "activity"]
    assert body["startTime"].startswith("2026-04-01T00:00:00")
    assert body["limit"] == ex.DEFAULT_LIMIT == 3000


def test_optional_arrays_are_omitted_rather_than_sent_empty(monkeypatch):
    """The documented defaults are `[]`. Sending an explicit empty list
    asserts a choice nobody made, and a future change to their default would
    then be silently overridden by ours."""
    cap = _Capture()
    monkeypatch.setattr(ex.httpx, "post", cap)
    ex.search(token=TOKEN, base_url=BASE, filter_expression="*", fields=["id"],
              start_time=datetime.now(timezone.utc) - timedelta(minutes=1),
              end_time=datetime.now(timezone.utc))
    assert "groupBy" not in cap.payload
    assert "orderBy" not in cap.payload
    # `distinct` IS sent: it is a boolean with a documented default of false,
    # and false is a value rather than an absence.
    assert cap.payload["distinct"] is False


def test_group_and_order_are_sent_when_asked_for(monkeypatch):
    cap = _Capture()
    monkeypatch.setattr(ex.httpx, "post", cap)
    ex.search(token=TOKEN, base_url=BASE, filter_expression="*", fields=["id"],
              start_time=datetime.now(timezone.utc), end_time=datetime.now(timezone.utc),
              group_by=["user"], order_by=["time DESC"], distinct=True)
    assert cap.payload["groupBy"] == ["user"]
    assert cap.payload["orderBy"] == ["time DESC"]
    assert cap.payload["distinct"] is True


# ── verification is cheap on purpose ─────────────────────────────────────


def test_verification_asks_for_one_row_over_one_minute(monkeypatch):
    """A verification proves the credential works; it does not retrieve
    anything. A wide search over years of logs is slow and rude to the
    customer's cluster."""
    cap = _Capture()
    _verify(monkeypatch, cap)
    assert cap.payload["limit"] == 1
    start = datetime.fromisoformat(cap.payload["startTime"])
    end = datetime.fromisoformat(cap.payload["endTime"])
    assert timedelta(seconds=0) < (end - start) <= timedelta(minutes=2)


def test_a_successful_verification_is_verified_ok(monkeypatch):
    from app.services import integration_status_service as status

    out = _verify(monkeypatch, _Capture(200, {"rows": []}))
    assert out["state"] == status.VERIFIED_OK
    assert out["direction"] == status.INGEST


# ── what must never reach a log, a page or an audit row ──────────────────


@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_no_failure_reason_contains_the_token(monkeypatch, status_code):
    """The reason is stored in `tenant_integrations.health`, rendered on the
    page and written to the audit row. A credential in it is a credential in
    three places that are read back."""
    out = _verify(monkeypatch, _Capture(status_code))
    assert out["state"] != "verified_ok"
    # The token VALUE. The word "Bearer" appearing in an explanation of how
    # the header is built is not a leak — the first version of this test
    # conflated the two and failed on its own explanatory copy.
    assert TOKEN not in out["reason"]
    assert TOKEN[4:] not in out["reason"], "a substring of the token escaped"


def test_a_failure_does_not_echo_the_response_body(monkeypatch):
    """A search response carries customer log events. The HTTP code is the
    diagnosis; the body is somebody's data."""
    secret_event = "user=jdoe host=EXPDC001 process=mimikatz.exe"
    out = _verify(monkeypatch, _Capture(500, {"events": [secret_event]}))
    assert secret_event not in out["reason"]
    assert "jdoe" not in out["reason"]
    assert "500" in out["reason"]


def test_a_successful_verification_does_not_report_what_it_found(monkeypatch):
    """Not even a count. How many events a one-minute window happened to hold
    tells nobody anything and the rows are customer log data."""
    out = _verify(monkeypatch, _Capture(200, {"rows": [
        {"id": "1", "user": "jdoe"}, {"id": "2", "user": "asmith"}]}))
    assert "jdoe" not in out["reason"] and "asmith" not in out["reason"]
    assert "2" not in out["reason"].replace("v2", "").replace("/search/", "")


# ── failures an operator can act on ──────────────────────────────────────


def test_an_unauthorised_answer_names_the_two_possible_causes(monkeypatch):
    """401/403 has two fixes and they are different: a wrong or expired
    token, or a key/secret that must be exchanged for a bearer first. This
    platform sends the token straight through, so the second is a missing
    step rather than a bad credential — and an operator cannot tell which
    from 'unauthorised'."""
    out = _verify(monkeypatch, _Capture(401))
    assert out["failure_kind"] == "unauthorised"
    assert "exchange" in out["reason"]


def test_a_404_says_the_host_is_probably_wrong(monkeypatch):
    """The mistake this will actually catch: the Advanced Analytics web
    address entered where the API host belongs. One operator did exactly
    that, because the field description used to say so."""
    out = _verify(monkeypatch, _Capture(404))
    assert out["failure_kind"] == "wrong_host"
    assert "api.<region>.exabeam.cloud" in out["reason"]


def test_a_network_failure_is_not_reported_as_a_credential_failure(monkeypatch):
    def _boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(ex.httpx, "post", _boom)
    out = ex.verify(config={"base_url": BASE}, secrets={"token": TOKEN})
    assert out["failure_kind"] == "unreachable"
    assert "not a credential one" in out["reason"]


@pytest.mark.parametrize("config,secrets,missing", [
    ({}, {"token": TOKEN}, "base_url"),
    ({"base_url": BASE}, {}, "token"),
])
def test_a_missing_field_is_named(monkeypatch, config, secrets, missing):
    def _never(*a, **k):  # pragma: no cover - must not be reached
        raise AssertionError("called Exabeam with an incomplete credential")

    monkeypatch.setattr(ex.httpx, "post", _never)
    out = ex.verify(config=config, secrets=secrets)
    assert out["failure_kind"] == "not_configured"
    assert missing in out["reason"]
