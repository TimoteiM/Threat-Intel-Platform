"""The CAPE client, against a fake CAPE.

No live server, no real sample, no network. Every response here is fabricated
and every "file" is a harmless fixture — detonating something real to test a
client would be an odd way to prove it works.

The cases that matter most are the unhappy ones. A sandbox client that gets
the happy path right and mishandles a 401, a redirect or an ambiguous POST is
a client that loses samples or leaks a credential.
"""

from __future__ import annotations

import io
import ssl

import httpx
import pytest

from app.services import cape_client as cape

TOKEN = "cape-token-not-a-real-one"
BASE = "https://cape.internal.test/apiv2"


class FakeSettings:
    """Only what the client reads. A stub, so a real .env cannot leak in."""

    cape_enabled = True
    cape_api_base_url = BASE
    cape_api_token = TOKEN
    cape_verify_tls = True
    cape_ca_bundle = ""
    cape_connect_timeout_seconds = 5
    cape_request_timeout_seconds = 20
    cape_analysis_timeout_seconds = 180
    cape_poll_interval_seconds = 1
    cape_max_poll_duration_seconds = 60
    cape_route = "internet"
    cape_reuse_existing_analysis = True
    cape_report_formats = "json,lite"
    cape_max_report_bytes = 1024 * 1024
    cape_max_upload_bytes = 10 * 1024 * 1024

    cape_configured = True
    cape_base_url = BASE
    cape_tls_verify = True
    cape_report_format_list = ["json", "lite"]


def build(handler, settings=None) -> cape.CapeClient:
    """A client whose transport is ours, with the real headers preserved."""
    settings = settings or FakeSettings()
    client = cape.CapeClient(settings=settings)
    client._session = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers=dict(client._session.headers),
        follow_redirects=False,
    )
    return client


def ok(payload, **kwargs) -> httpx.Response:
    return httpx.Response(200, json=payload, **kwargs)


# ── Configuration ────────────────────────────────────────────────────────────


def test_an_unconfigured_deployment_refuses_to_build_a_client(monkeypatch):
    """Off is off. Nothing half-configured may reach the network."""

    class Off(FakeSettings):
        cape_configured = False

    with pytest.raises(cape.CapeNotConfigured):
        cape.CapeClient(settings=Off())


def test_a_missing_token_is_not_configured():
    from app.config import Settings

    settings = Settings(cape_enabled=True, cape_api_base_url=BASE, cape_api_token="")
    assert settings.cape_configured is False


def test_all_three_present_is_configured():
    from app.config import Settings

    settings = Settings(cape_enabled=True, cape_api_base_url=BASE, cape_api_token="x")
    assert settings.cape_configured is True
    assert settings.cape_base_url == BASE  # no trailing slash


def test_a_ca_bundle_becomes_the_verify_argument():
    """Every field is set explicitly: Settings reads .env, so a test that omits
    one asserts against whatever the deployment happens to be configured with.
    This exact test passed until CAPE_CA_BUNDLE was filled in for real."""
    from app.config import Settings

    assert Settings(cape_ca_bundle="/etc/ssl/internal.pem").cape_tls_verify == "/etc/ssl/internal.pem"
    assert Settings(cape_verify_tls=True, cape_ca_bundle="").cape_tls_verify is True
    assert Settings(cape_verify_tls=False, cape_ca_bundle="").cape_tls_verify is False


def test_tls_verification_is_on_by_default():
    """The field's own default, independent of what this deployment sets."""
    from app.config import Settings

    assert Settings.model_fields["cape_verify_tls"].default is True


def test_disabling_tls_verification_warns(monkeypatch, caplog):
    """A development-only setting has to be loud about itself."""

    class Insecure(FakeSettings):
        cape_verify_tls = False
        cape_tls_verify = False

    with caplog.at_level("WARNING"):
        cape.CapeClient(settings=Insecure()).close()
    assert any("TLS verification is DISABLED" in r.message for r in caplog.records)


# ── The token never escapes ──────────────────────────────────────────────────


def test_the_token_is_sent_as_a_token_header():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Authorization")
        return ok({"error": False, "data": {"version": "2.5"}})

    build(handler).status()
    assert seen["auth"] == f"Token {TOKEN}"


def test_the_token_is_scrubbed_from_any_message(monkeypatch):
    monkeypatch.setattr(cape, "get_settings", lambda: FakeSettings())
    assert TOKEN not in cape.redact(f"failed with Authorization: Token {TOKEN}")
    assert TOKEN not in cape.redact(f"the token is {TOKEN} by the way")
    assert "[REDACTED]" in cape.redact(f"Authorization: Token {TOKEN}")


def test_an_authorization_header_is_scrubbed_even_when_the_token_is_unknown(monkeypatch):
    """Covers the messages we never see coming — a traceback, a proxy echo."""

    class NoToken(FakeSettings):
        cape_api_token = ""

    monkeypatch.setattr(cape, "get_settings", lambda: NoToken())
    assert "hunter2" not in cape.redact("Authorization: Token hunter2")


def test_headers_are_masked_for_traces():
    masked = cape.safe_headers({"Authorization": f"Token {TOKEN}", "X-API-Key": "k", "Accept": "application/json"})
    assert masked["Authorization"] == "[REDACTED]"
    assert masked["X-API-Key"] == "[REDACTED]"
    assert masked["Accept"] == "application/json"


def test_an_error_body_echoing_the_token_does_not_reach_the_exception(monkeypatch):
    monkeypatch.setattr(cape, "get_settings", lambda: FakeSettings())

    def handler(request):
        return httpx.Response(400, text=f"bad request with Authorization: Token {TOKEN}")

    with pytest.raises(cape.CapeValidationError) as caught:
        build(handler).status()
    assert TOKEN not in str(caught.value)


# ── Status ───────────────────────────────────────────────────────────────────


def test_a_successful_status_reports_the_machine_pool():
    def handler(request):
        assert request.url.path.endswith("/cuckoo/status/")
        return ok({"error": False, "data": {
            "version": "2.5", "tasks": {"pending": 2, "running": 1},
            "machines": {"total": 6, "available": 6}}})

    status = build(handler).status()
    assert status.reachable is True
    assert status.version == "2.5"
    assert (status.machines_total, status.machines_available) == (6, 6)


# ── Failure modes ────────────────────────────────────────────────────────────


def test_401_is_an_authentication_error():
    with pytest.raises(cape.CapeAuthError):
        build(lambda r: httpx.Response(401, json={"detail": "no"})).status()


def test_403_is_distinct_from_401():
    with pytest.raises(cape.CapeForbidden):
        build(lambda r: httpx.Response(403, json={"detail": "disabled"})).status()


def test_a_connection_failure_is_reported_as_one():
    def handler(request):
        raise httpx.ConnectError("no route to host")

    with pytest.raises(cape.CapeConnectionError):
        build(handler).status()


def test_a_timeout_is_reported_as_a_timeout():
    def handler(request):
        raise httpx.ConnectTimeout("too slow")

    with pytest.raises(cape.CapeTimeout):
        build(handler).status()


def test_a_tls_failure_is_its_own_error_because_the_remedy_differs():
    """A certificate problem needs a CA bundle, not a network route."""

    def handler(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")

    with pytest.raises(cape.CapeTLSError):
        build(handler).status()


def test_a_wrapped_ssl_error_is_also_a_tls_failure():
    def handler(request):
        raise httpx.ConnectError("connect failed") from ssl.SSLError("boom")

    with pytest.raises(cape.CapeTLSError):
        build(handler).status()


def test_a_server_error_is_retried_then_raised(monkeypatch):
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503, text="unavailable")

    with pytest.raises(cape.CapeServerError):
        build(handler).status()
    assert calls["n"] == 3, "a safe GET should be retried"


def test_rate_limiting_honours_retry_after(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(cape.time, "sleep", lambda s: slept.append(s))
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, text="slow down")
        return ok({"error": False, "data": {"version": "2.5"}})

    assert build(handler).status().version == "2.5"
    assert slept == [7.0], "Retry-After must be obeyed, not replaced by a backoff"


def test_a_persistent_429_raises_with_the_retry_hint(monkeypatch):
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    with pytest.raises(cape.CapeRateLimited) as caught:
        build(lambda r: httpx.Response(429, headers={"Retry-After": "3"})).status()
    assert caught.value.retry_after == 3.0


def test_an_absurd_retry_after_is_capped(monkeypatch):
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    with pytest.raises(cape.CapeRateLimited) as caught:
        build(lambda r: httpx.Response(429, headers={"Retry-After": "999999"})).status()
    assert caught.value.retry_after == 120


def test_a_non_json_response_is_refused_rather_than_guessed():
    def handler(request):
        return httpx.Response(200, text="<html>login page</html>", headers={"Content-Type": "text/html"})

    with pytest.raises(cape.CapeValidationError):
        build(handler).status()


def test_the_cape_error_envelope_becomes_an_exception():
    def handler(request):
        return ok({"error": True, "error_value": "machine pool exhausted"})

    with pytest.raises(cape.CapeValidationError) as caught:
        build(handler).status()
    assert "machine pool exhausted" in str(caught.value)


def test_a_redirect_is_refused_not_followed():
    """Following a Location to an arbitrary host is the SSRF this prevents."""

    def handler(request):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    with pytest.raises(cape.CapeValidationError) as caught:
        build(handler).status()
    assert "redirect" in str(caught.value).lower()


# ── Hash search ──────────────────────────────────────────────────────────────


def test_a_hash_with_an_existing_analysis_comes_back():
    def handler(request):
        assert "/tasks/search/sha256/" in request.url.path
        return ok({"error": False, "data": [
            {"id": 11, "status": "reported"}, {"id": 12, "status": "running"}]})

    tasks = build(handler).search_by_sha256("a" * 64)
    assert [(t.task_id, t.status) for t in tasks] == [(11, "reported"), (12, "running")]
    assert tasks[0].is_reported and not tasks[1].is_terminal


def test_a_hash_with_no_analysis_is_an_empty_list_not_an_error():
    assert build(lambda r: ok({"error": False, "data": []})).search_by_sha256("b" * 64) == []


def test_a_404_on_search_means_nothing_found(monkeypatch):
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    assert build(lambda r: httpx.Response(404, json={"detail": "not found"})).search_by_sha256("c" * 64) == []


def test_a_non_sha256_is_rejected_before_any_request():
    def handler(request):
        raise AssertionError("must not reach the network")

    with pytest.raises(cape.CapeValidationError):
        build(handler).search_by_sha256("not-a-hash")


# ── Submission ───────────────────────────────────────────────────────────────


def test_a_submission_sends_the_required_fields_and_no_machine():
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        captured["path"] = request.url.path
        return ok({"error": False, "data": {"task_ids": [501]}})

    submission = build(handler).submit_file(
        file_obj=io.BytesIO(b"harmless fixture bytes"), filename="invoice.doc"
    )
    body = captured["body"]
    assert submission.task_id == 501
    assert captured["path"].endswith("/tasks/create/file/")
    assert b'name="route"' in body and b"internet" in body
    assert b'name="enforce_timeout"' in body and b"1" in body
    assert b'name="timeout"' in body
    # CAPE schedules across its own pool; pinning one of six would serialise us.
    assert b'name="machine"' not in body
    assert b"harmless fixture bytes" in body


def test_a_submitted_filename_cannot_traverse():
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        return ok({"error": False, "data": {"task_ids": [1]}})

    build(handler).submit_file(file_obj=io.BytesIO(b"x"), filename="../../etc/passwd")
    assert b"/etc/passwd" not in captured["body"]


def test_an_ambiguous_submission_is_never_resent_automatically():
    """The sample may already be detonating. Resending runs it twice."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ReadTimeout("no answer")

    with pytest.raises(cape.CapeAmbiguousSubmission):
        build(handler).submit_file(file_obj=io.BytesIO(b"x"), filename="s.bin")
    assert calls["n"] == 1, "a POST must not be retried"


def test_a_submission_that_names_no_task_is_an_error():
    with pytest.raises(cape.CapeValidationError):
        build(lambda r: ok({"error": False, "data": {}})).submit_file(
            file_obj=io.BytesIO(b"x"), filename="s.bin"
        )


def test_several_task_id_shapes_are_understood():
    for payload, expected in (
        ({"error": False, "data": {"task_ids": [9]}}, 9),
        ({"error": False, "data": {"task_id": 8}}, 8),
        ({"error": False, "data": 7}, 7),
    ):
        got = build(lambda r, p=payload: ok(p)).submit_file(
            file_obj=io.BytesIO(b"x"), filename="s.bin"
        )
        assert got.task_id == expected


# ── Task view and report ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cape_status,terminal,failed",
    [("pending", False, False), ("running", False, False), ("completed", False, False),
     ("reported", True, False), ("failed_analysis", True, True), ("failed_processing", True, True)],
)
def test_task_states_are_classified(cape_status, terminal, failed):
    task = build(lambda r: ok({"error": False, "data": {"id": 3, "status": cape_status}})).view_task(3)
    assert task.is_terminal is terminal
    assert task.is_failed is failed


def test_a_task_id_must_be_numeric():
    def handler(request):
        raise AssertionError("must not reach the network")

    with pytest.raises(cape.CapeValidationError):
        build(handler).view_task("3; DROP TABLE tasks")


def test_the_report_is_fetched_and_returned_whole():
    def handler(request):
        assert "/tasks/get/report/" in request.url.path
        return httpx.Response(200, json={"error": False, "data": {"malscore": 8.5, "info": {"id": 4}}},
                              headers={"Content-Type": "application/json"})

    report = build(handler).fetch_report(4)
    assert report.payload["malscore"] == 8.5
    assert report.fmt == "json"


def test_the_next_report_format_is_tried_when_the_first_is_unavailable():
    seen: list[str] = []

    def handler(request):
        fmt = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        seen.append(fmt)
        if fmt == "json":
            return httpx.Response(404, json={"detail": "json report not enabled"})
        return httpx.Response(200, json={"error": False, "data": {"info": {"id": 5}}},
                              headers={"Content-Type": "application/json"})

    assert build(handler).fetch_report(5).fmt == "lite"
    assert seen == ["json", "lite"]


def test_an_oversized_report_is_refused_rather_than_buffered():
    class Tiny(FakeSettings):
        cape_max_report_bytes = 64

    def handler(request):
        return httpx.Response(200, content=b"{\"x\":\"" + b"A" * 5000 + b"\"}",
                              headers={"Content-Type": "application/json"})

    with pytest.raises(cape.CapeResponseTooLarge):
        build(handler, settings=Tiny()).fetch_report(6)


def test_no_usable_report_format_is_an_error(monkeypatch):
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    with pytest.raises(cape.CapeValidationError):
        build(lambda r: httpx.Response(404, json={"detail": "nope"})).fetch_report(7)


# ── Searching by something other than a hash ─────────────────────────────────
#
# GET /tasks/search/ accepts only md5, sha1 and sha256 — /tasks/search/domain/
# returns 404 on the live instance — so "which analyses contacted this host"
# goes through POST /tasks/extendedsearch/.


def test_an_indicator_search_returns_report_shaped_matches():
    """CAPE answers with {info, target, network, malscore} per match, which is
    the substance of a report — so the caller needs no second request."""
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        captured["body"] = request.read()
        return ok({"error": False, "data": [
            {"info": {"id": 4, "started": "..."}, "malscore": 6.0,
             "target": {"file": {"name": "x.exe"}}, "network": {"domains": [{"domain": "c2.test"}]}}
        ]})

    hits = build(handler).search_reports("domain", "c2.test")
    assert captured["path"].endswith("/tasks/extendedsearch/")
    assert b"domain" in captured["body"] and b"c2.test" in captured["body"]
    assert len(hits) == 1 and hits[0]["info"]["id"] == 4


def test_no_matches_is_an_empty_list_not_an_error():
    """CAPE signals a miss with the same envelope it uses for a failure."""
    def handler(request):
        return ok({"error": True, "error_value": "Unable to retrieve records"})

    assert build(handler).search_reports("domain", "google.com") == []


def test_a_genuine_search_failure_still_raises():
    def handler(request):
        return ok({"error": True, "error_value": "database connection refused"})

    with pytest.raises(cape.CapeValidationError):
        build(handler).search_reports("domain", "x.test")


def test_the_search_option_cannot_be_chosen_by_a_caller():
    """The option lands in a POST body CAPE dispatches on."""
    def handler(request):
        raise AssertionError("must not reach the network")

    for bad in ("../../etc", "drop table", "", "configs; --"):
        with pytest.raises(cape.CapeValidationError):
            build(handler).search_reports(bad, "x")


def test_an_overlong_search_argument_is_refused():
    def handler(request):
        raise AssertionError("must not reach the network")

    with pytest.raises(cape.CapeValidationError):
        build(handler).search_reports("domain", "a" * 600)


# ── URL detonation ───────────────────────────────────────────────────────────
#
# CAPE fetches a URL and runs whatever comes back. The parameter name is taken
# from the instance's own API page: curl -F url="somebadness.tld" .../create/url/


def test_a_url_submission_sends_the_documented_field_and_the_route():
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        captured["body"] = request.read()
        return ok({"error": False, "data": {"task_ids": [88]}})

    submission = build(handler).submit_url(url="http://evil.test/landing")
    assert submission.task_id == 88
    assert captured["path"].endswith("/tasks/create/url/")
    from urllib.parse import parse_qs

    fields = parse_qs(captured["body"].decode())
    assert fields["url"] == ["http://evil.test/landing"]
    assert fields["route"] == ["internet"]
    assert fields["enforce_timeout"] == ["1"]


def test_a_bare_host_is_given_a_scheme():
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        return ok({"error": False, "data": {"task_ids": [1]}})

    build(handler).submit_url(url="evil.test")
    # The body is form-encoded, so decode before asserting on the value.
    from urllib.parse import parse_qs

    fields = parse_qs(captured["body"].decode())
    assert fields["url"] == ["http://evil.test"]


@pytest.mark.parametrize(
    "hostile",
    [
        "file:///etc/passwd",          # would read the guest's own disk
        "ftp://evil.test/x",
        "http://",                     # no host
        "",
        "x" * 3000,
        "http://evil.test/\nInjected: 1",
    ],
)
def test_a_hostile_url_never_reaches_cape(hostile):
    """CAPE fetches this from inside the sandbox, so the target is a security
    decision, not a formatting one."""
    def handler(request):
        raise AssertionError("must not reach the network")

    with pytest.raises(cape.CapeValidationError):
        build(handler).submit_url(url=hostile)


def test_an_ambiguous_url_submission_is_not_resent():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ReadTimeout("no answer")

    with pytest.raises(cape.CapeAmbiguousSubmission):
        build(handler).submit_url(url="http://evil.test/")
    assert calls["n"] == 1
