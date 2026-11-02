"""Falcon OAuth, against the two directions that have already cost months.

**The expiry.** Spamhaus's stored SIA token was a JWT whose `exp` decoded to
2026-05-12 — the day the integration was committed — and the collector then
failed on 2,198 consecutive runs for 98 days. The expiry was in the token, in
the database, readable, and nothing read it. So the expiry here is a value
this module computes and exposes, and the tests assert it is read rather than
discovered by a 401.

**The secret.** It reaches one request body and must appear in no log, no
exception and no response. `requests` puts request bodies into some exception
strings, so the redaction is asserted against that specific shape.

Controls throughout: a working credential must still verify, and the
redaction must not mangle an ordinary message.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.integrations import falcon_client as fc

CLIENT_ID = "falcon-client-id-not-real"
SECRET = "falcon-client-secret-not-real-0123456789"


class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Session:
    """A fake HTTP session that records what it was asked, never a real call."""

    def __init__(self, token_resp=None, api_resp=None, raise_on_post=None):
        self.token_resp = token_resp
        self.api_resp = api_resp
        self.raise_on_post = raise_on_post
        self.posts: list[dict] = []
        self.gets: list[dict] = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.posts.append({"url": url, "data": data, "headers": headers})
        if self.raise_on_post:
            raise self.raise_on_post
        return self.token_resp

    def get(self, url, headers=None, params=None, timeout=None):
        self.gets.append({"url": url, "headers": headers, "params": params})
        return self.api_resp


def _token_ok(expires_in=1800, scopes="detections:read hosts:read"):
    return _Resp(201, {"access_token": "tok-abc", "expires_in": expires_in,
                       "scope": scopes})


# ─── the expiry is read, not discovered ──────────────────────────────────

def test_the_token_expiry_is_read_from_the_response():
    s = _Session(token_resp=_token_ok(expires_in=1800))
    tok = fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert 1700 < tok.expires_in_seconds <= 1800
    assert tok.expires_at > datetime.now(timezone.utc)
    assert tok.expired is False
    assert tok.scopes == ("detections:read", "hosts:read")


def test_a_token_inside_the_refresh_margin_counts_as_expired():
    """A token valid when checked and dead when used is the race the margin
    exists for. 60 seconds left is not 'fine'."""
    s = _Session(token_resp=_token_ok(expires_in=60))
    tok = fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert tok.expired is True
    assert tok.as_status()["near_expiry"] is True


def test_a_missing_expires_in_is_not_defaulted_to_comfortable():
    """Falcon answering without `expires_in` must make the next call refresh,
    not assume half an hour. The safe direction is the short one."""
    s = _Session(token_resp=_Resp(201, {"access_token": "tok-abc"}))
    tok = fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert tok.expired is True


def test_the_expiry_status_never_carries_the_token():
    s = _Session(token_resp=_token_ok())
    status = fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET,
                            session=s).as_status()
    assert "tok-abc" not in str(status)
    assert "access_token" not in status


# ─── no credential means no request ──────────────────────────────────────

@pytest.mark.parametrize("cid,sec", [("", SECRET), (CLIENT_ID, ""), ("", "")])
def test_a_missing_credential_makes_no_request(cid, sec):
    """An unauthenticated call can only return 401, and a 401 recorded as an
    outage is what made the last one invisible."""
    s = _Session(token_resp=_token_ok())
    with pytest.raises(fc.FalconAuthError):
        fc.fetch_token(client_id=cid, client_secret=sec, session=s)
    assert s.posts == [], "a request was sent with no credential"


# ─── credential failure and provider failure are different statuses ──────

@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_credential_is_an_auth_error(status):
    s = _Session(token_resp=_Resp(status, {}))
    with pytest.raises(fc.FalconAuthError):
        fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)


@pytest.mark.parametrize("status", [429, 500, 503])
def test_a_provider_problem_is_not_an_auth_error(status):
    """Reporting these as one status is how 'enabled' came to mean nothing:
    one is a credential to fix, the other is a provider to wait for."""
    s = _Session(token_resp=_Resp(status, {}))
    with pytest.raises(fc.FalconUnavailable):
        fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)


def test_a_2xx_with_no_token_is_an_absence_not_a_success():
    s = _Session(token_resp=_Resp(201, {"expires_in": 1800}))
    with pytest.raises(fc.FalconUnavailable) as exc:
        fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert "no access_token" in str(exc.value)


# ─── the secret reaches no log, exception or response ────────────────────

def test_the_secret_is_not_in_a_transport_exception():
    """`requests` puts request bodies into some exception strings, and this
    request's body is client_id=...&client_secret=..."""
    boom = RuntimeError(
        f"HTTPSConnectionPool: failed sending body "
        f"client_id={CLIENT_ID}&client_secret={SECRET}"
    )
    s = _Session(raise_on_post=boom)
    with pytest.raises(fc.FalconUnavailable) as exc:
        fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert SECRET not in str(exc.value)
    assert CLIENT_ID not in str(exc.value)
    assert "[redacted]" in str(exc.value)


def test_the_secret_is_not_in_a_verify_result():
    boom = RuntimeError(f"body client_secret={SECRET} rejected")
    s = _Session(raise_on_post=boom)
    out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert SECRET not in str(out)
    assert out["state"] == "verified_failing"


def test_a_bearer_token_is_not_in_an_error():
    s = _Session(token_resp=_token_ok(),
                 api_resp=_Resp(500, {}, text="Authorization: Bearer tok-abc bad"))
    out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert "tok-abc" not in str(out)


def test_an_ordinary_message_survives_redaction():
    """The control. A redactor that mangles everything passes the tests
    above and destroys the reason field."""
    msg = "Falcon token endpoint returned HTTP 503"
    assert fc._redact(msg) == msg


# ─── verify makes a real authenticated call, not just a token fetch ──────

def test_verify_calls_the_api_after_getting_a_token():
    """A token proves the credential is valid and proves nothing about
    whether this API client can do anything."""
    s = _Session(token_resp=_token_ok(), api_resp=_Resp(200, {"resources": []}))
    out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert out["state"] == "verified_ok"
    assert out["reason"] is None
    assert len(s.gets) == 1, "verify did not make an authenticated API call"
    assert s.gets[0]["headers"]["Authorization"].startswith("Bearer ")
    assert out["token"]["near_expiry"] is False


def test_a_valid_credential_with_no_scope_is_its_own_failure_kind():
    """Token issued, API refused. A credential to keep and a scope to grant —
    reported as neither a credential nor a provider problem."""
    s = _Session(token_resp=_token_ok(), api_resp=_Resp(403, {}))
    out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET, session=s)
    assert out["state"] == "verified_failing"
    assert out["failure_kind"] == "scope"
    assert "scope" in out["reason"]


def test_verify_never_raises_for_a_credential_or_provider_problem():
    """Those are the answer, not an exception — the page has to render them."""
    for resp in (_Resp(401, {}), _Resp(503, {})):
        out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET,
                        session=_Session(token_resp=resp))
        assert out["state"] == "verified_failing"
        assert out["reason"]


# ─── the cloud/base-url resolution ───────────────────────────────────────

@pytest.mark.parametrize("config,expected", [
    ({}, fc.DEFAULT_BASE_URL),
    ({"cloud": "eu-1"}, "https://api.eu-1.crowdstrike.com"),
    ({"cloud": "EU-1"}, "https://api.eu-1.crowdstrike.com"),
    ({"base_url": "https://api.us-2.crowdstrike.com/"},
     "https://api.us-2.crowdstrike.com"),
    # An explicit base_url wins over a cloud name: one request must not
    # carry two answers.
    ({"cloud": "us-1", "base_url": "https://custom.example"},
     "https://custom.example"),
    ({"cloud": "nonsense"}, fc.DEFAULT_BASE_URL),
])
def test_base_url_resolution(config, expected):
    assert fc.base_url_for(config) == expected
