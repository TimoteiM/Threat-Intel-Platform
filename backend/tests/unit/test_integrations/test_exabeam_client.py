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
KEY_ID = "key-id-SECRET-TOO"
KEY_SECRET = "key-secret-MUST-NOT-LEAK"
BASE = "https://api.eu.exabeam.cloud"


@pytest.fixture(autouse=True)
def _no_cached_token():
    """Every test starts with an empty token cache.

    Without this the first test to exchange a token would satisfy the rest,
    and the caching tests would pass by accident.
    """
    ex.clear_token_cache()
    yield
    ex.clear_token_cache()


class _Exchange:
    """Stands in for httpx.post across BOTH endpoints.

    `verify()` now makes two calls — the token exchange, then the search — so
    a stub that answers only one of them tests the wrong thing.
    """

    def __init__(self, token_status=200, search_status=200,
                 token_body=None, search_body=None):
        self.token_status = token_status
        self.search_status = search_status
        self.token_body = token_body if token_body is not None else {
            "access_token": TOKEN, "expires_in": 14400}
        self.search_body = search_body if search_body is not None else {"rows": []}
        self.calls: list[tuple[str, dict, dict]] = []

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.calls.append((url, json or {}, headers or {}))
        request = httpx.Request("POST", url)
        if url.endswith(ex.TOKEN_PATH):
            return httpx.Response(self.token_status, json=self.token_body,
                                  request=request)
        return httpx.Response(self.search_status, json=self.search_body,
                              request=request)

    @property
    def token_calls(self):
        return [c for c in self.calls if c[0].endswith(ex.TOKEN_PATH)]

    @property
    def search_calls(self):
        return [c for c in self.calls if c[0].endswith(ex.SEARCH_PATH)]


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
    return ex.verify(config={"base_url": BASE},
                     secrets={"client_id": KEY_ID, "client_secret": KEY_SECRET})


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
    cap = _Exchange()
    _verify(monkeypatch, cap)
    assert len(cap.token_calls) == 1, "one exchange, then one search"
    assert len(cap.search_calls) == 1
    payload = cap.search_calls[0][1]
    assert payload["limit"] == 1
    start = datetime.fromisoformat(payload["startTime"])
    end = datetime.fromisoformat(payload["endTime"])
    assert timedelta(seconds=0) < (end - start) <= timedelta(minutes=2)


def test_a_successful_verification_is_verified_ok(monkeypatch):
    from app.services import integration_status_service as status

    out = _verify(monkeypatch, _Exchange())
    assert out["state"] == status.VERIFIED_OK
    assert out["direction"] == status.INGEST


# ── what must never reach a log, a page or an audit row ──────────────────


@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_no_failure_reason_contains_the_token(monkeypatch, status_code):
    """The reason is stored in `tenant_integrations.health`, rendered on the
    page and written to the audit row. A credential in it is a credential in
    three places that are read back."""
    out = _verify(monkeypatch, _Exchange(search_status=status_code))
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
    out = _verify(monkeypatch, _Exchange(search_status=500, search_body={"events": [secret_event]}))
    assert secret_event not in out["reason"]
    assert "jdoe" not in out["reason"]
    assert "500" in out["reason"]


def test_a_successful_verification_does_not_report_what_it_found(monkeypatch):
    """Not even a count. How many events a one-minute window happened to hold
    tells nobody anything and the rows are customer log data."""
    out = _verify(monkeypatch, _Exchange(search_body={"rows": [
        {"id": "1", "user": "jdoe"}, {"id": "2", "user": "asmith"}]}))
    assert "jdoe" not in out["reason"] and "asmith" not in out["reason"]
    assert "2" not in out["reason"].replace("v2", "").replace("/search/", "")


# ── failures an operator can act on ──────────────────────────────────────


def test_a_rejected_key_points_at_where_the_key_comes_from(monkeypatch):
    """A refusal at the EXCHANGE is about the API key itself, and an operator
    needs to know where that key lives: Settings > API Keys, with the Secret
    shown in full only once."""
    out = _verify(monkeypatch, _Exchange(token_status=401))
    assert out["failure_kind"] == "unauthorised"
    assert "Settings > API Keys" in out["reason"]
    assert KEY_SECRET not in out["reason"] and KEY_ID not in out["reason"]


def test_a_refusal_after_a_successful_exchange_is_about_permissions(monkeypatch):
    """The control for the test above, and the distinction that matters: the
    token was issued a moment ago, so a 403 on the search is about what the
    key is ALLOWED to do, not whether it is valid."""
    out = _verify(monkeypatch, _Exchange(search_status=403))
    assert out["failure_kind"] == "forbidden"
    assert "permission set" in out["reason"]


def test_a_token_is_reused_rather_than_fetched_per_call(monkeypatch):
    """Exabeam issues 4-hour tokens and asks for no more than about six token
    requests a day — "do not request a token on every API call". Fetching one
    per search would breach that within a working morning."""
    cap = _Exchange()
    monkeypatch.setattr(ex.httpx, "post", cap)
    for _ in range(5):
        ex.bearer_token(base_url=BASE, client_id=KEY_ID, client_secret=KEY_SECRET)
    assert len(cap.token_calls) == 1, (
        f"{len(cap.token_calls)} token requests for 5 calls; the cache is not "
        f"holding and Exabeam's rate guidance would be breached"
    )


def test_an_expired_token_is_refetched(monkeypatch):
    """The control for the caching test: a cache that never refreshes would
    also make exactly one request, and would hand out a dead token after four
    hours."""
    cap = _Exchange(token_body={"access_token": TOKEN, "expires_in": 1})
    monkeypatch.setattr(ex.httpx, "post", cap)
    ex.bearer_token(base_url=BASE, client_id=KEY_ID, client_secret=KEY_SECRET)
    ex.bearer_token(base_url=BASE, client_id=KEY_ID, client_secret=KEY_SECRET)
    assert len(cap.token_calls) == 2, "a near-expired token was reused"


def test_one_tenants_token_is_never_handed_to_another(monkeypatch):
    """The cache is keyed by host and key, so two clients on the same Exabeam
    region cannot share a token. A cache keyed by base_url alone would do
    exactly that, and it is the one bug in a token cache that matters."""
    cap = _Exchange()
    monkeypatch.setattr(ex.httpx, "post", cap)
    ex.bearer_token(base_url=BASE, client_id="client-a", client_secret="s")
    ex.bearer_token(base_url=BASE, client_id="client-b", client_secret="s")
    assert len(cap.token_calls) == 2


def test_the_cache_key_does_not_hold_the_key_id_in_clear():
    """A cache dump, a debugger or a repr must not show it."""
    key = ex._cache_key(BASE, KEY_ID)
    assert KEY_ID not in "".join(str(part) for part in key)


def test_a_success_with_no_token_is_not_treated_as_success(monkeypatch):
    """A 2xx carrying no `access_token` would otherwise put an empty Bearer
    header on the next call and produce a confusing 401 from the search
    endpoint one step later."""
    cap = _Exchange(token_body={"token_type": "Bearer"})
    monkeypatch.setattr(ex.httpx, "post", cap)
    with pytest.raises(ValueError, match="no access_token"):
        ex.bearer_token(base_url=BASE, client_id=KEY_ID, client_secret=KEY_SECRET)


def test_the_exchange_sends_what_the_documentation_states(monkeypatch):
    cap = _Exchange()
    monkeypatch.setattr(ex.httpx, "post", cap)
    ex.bearer_token(base_url=BASE, client_id=KEY_ID, client_secret=KEY_SECRET)
    url, body, _ = cap.token_calls[0]
    assert url == f"{BASE}{ex.TOKEN_PATH}"
    assert body["grant_type"] == "client_credentials"
    assert body["client_id"] == KEY_ID
    assert body["client_secret"] == KEY_SECRET


def test_a_404_says_the_host_is_probably_wrong(monkeypatch):
    """The mistake this will actually catch: the Advanced Analytics web
    address entered where the API host belongs. One operator did exactly
    that, because the field description used to say so."""
    out = _verify(monkeypatch, _Exchange(search_status=404))
    assert out["failure_kind"] == "wrong_host"
    assert "api.<region>.exabeam.cloud" in out["reason"]


def test_a_network_failure_is_not_reported_as_a_credential_failure(monkeypatch):
    def _boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(ex.httpx, "post", _boom)
    out = ex.verify(config={"base_url": BASE},
                    secrets={"client_id": KEY_ID, "client_secret": KEY_SECRET})
    assert out["failure_kind"] == "unreachable"
    assert "not a credential one" in out["reason"]


@pytest.mark.parametrize("config,secrets,missing", [
    ({}, {"client_id": KEY_ID, "client_secret": KEY_SECRET}, "base_url"),
    ({"base_url": BASE}, {"client_secret": KEY_SECRET}, "client_id"),
    ({"base_url": BASE}, {"client_id": KEY_ID}, "client_secret"),
    ({"base_url": BASE}, {}, "client_id"),
])
def test_a_missing_field_is_named(monkeypatch, config, secrets, missing):
    def _never(*a, **k):  # pragma: no cover - must not be reached
        raise AssertionError("called Exabeam with an incomplete credential")

    monkeypatch.setattr(ex.httpx, "post", _never)
    out = ex.verify(config=config, secrets=secrets)
    assert out["failure_kind"] == "not_configured"
    assert missing in out["reason"]


# ── a bounded read is a sample unless it carries its total ───────────────


def test_a_search_reports_its_total_and_whether_it_is_complete(monkeypatch):
    """`limit` without a total is a claim about what you did not see.

    Exabeam answers with `totalRows`, so the honest form costs nothing. A
    caller reporting "50 events" when there were 4,000 is the failure this
    exists for.
    """
    cap = _Exchange(search_body={
        "rows": [{"time": "t1"}, {"time": "t2"}], "totalRows": 4000})
    monkeypatch.setattr(ex.httpx, "post", cap)
    out = ex.search(token=TOKEN, base_url=BASE, filter_expression="",
                    fields=["time"], start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc), limit=2)
    assert len(out.rows) == 2
    assert out.total == 4000
    assert out.complete is False


def test_a_search_that_returned_everything_says_so(monkeypatch):
    cap = _Exchange(search_body={"rows": [{"time": "t1"}], "totalRows": 1})
    monkeypatch.setattr(ex.httpx, "post", cap)
    out = ex.search(token=TOKEN, base_url=BASE, filter_expression="",
                    fields=["time"], start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc))
    assert out.complete is True and out.total == 1


def test_a_missing_total_is_not_read_as_completeness(monkeypatch):
    """No total means we cannot say whether these are all of them, and the
    safe answer to that is "no" — not `len(rows)`, which would quietly assert
    completeness from the sample itself."""
    cap = _Exchange(search_body={"rows": [{"time": "t1"}]})
    monkeypatch.setattr(ex.httpx, "post", cap)
    out = ex.search(token=TOKEN, base_url=BASE, filter_expression="",
                    fields=["time"], start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc))
    assert out.complete is False


def test_the_verify_query_uses_values_exabeam_documents(monkeypatch):
    """`filter="*"` was sent first and refused: `Invalid filter value *`. The
    wildcard is documented for `fields`, not for `filter`. These two values
    come from Exabeam's own examples."""
    cap = _Exchange()
    _verify(monkeypatch, cap)
    payload = cap.search_calls[0][1]
    assert payload["filter"] == ex.VERIFY_FILTER == ""
    assert payload["fields"] == list(ex.VERIFY_FIELDS) == ["time"]
    assert "*" not in payload["filter"]


def test_a_rejected_query_carries_exabeams_own_complaint(monkeypatch):
    """A 400 means the request failed validation before it ran, so the body is
    Exabeam's message about OUR query rather than anybody's log data.

    Suppressing it cost a round trip: "Exabeam answered HTTP 400 to a
    one-minute search" is true, useless, and left an operator with nothing to
    act on while the answer was sitting in the response.
    """
    cap = _Exchange(search_status=400, search_body={
        "errors": [{"code": "AAA_ESA_1000_400", "message": "Invalid filter value *"}]})
    out = _verify(monkeypatch, cap)
    assert out["failure_kind"] == "bad_request"
    assert "Invalid filter value" in out["reason"]
    assert "not the credential" in out["reason"]


def test_the_complaint_is_bounded_and_scrubbed(monkeypatch):
    """Defensive: a validation message is about our request, but if one ever
    quoted the headers it received, the token must not travel with it."""
    cap = _Exchange(search_status=400,
                    search_body={"echo": f"Bearer {TOKEN}", "pad": "x" * 2000})
    out = _verify(monkeypatch, cap)
    assert TOKEN not in out["reason"]
    assert len(out["reason"]) < 800


def test_a_server_error_still_withholds_the_body(monkeypatch):
    """The control for the two tests above: 4xx is a complaint about our
    request, 5xx may carry anything, and only the first is safe to echo."""
    secret_event = "user=jdoe host=EXPDC001"
    out = _verify(monkeypatch, _Exchange(search_status=503,
                                         search_body={"events": [secret_event]}))
    assert "jdoe" not in out["reason"]
    assert out["failure_kind"] == "http_error"
