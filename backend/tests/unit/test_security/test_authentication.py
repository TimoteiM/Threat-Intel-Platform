"""Authentication, from the credential primitives up to the middleware.

Context: the platform shipped with none. Every one of its documented operations
answered requests carrying no credential, and the schema was readable by anyone
on the network. These cover the pieces that close that — including the part an
outage would come from, that `monitor` mode really does let traffic through
while the ingest integrations are being migrated onto a key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.api.auth import _refuse_if_last_admin
from app.middleware.auth import AuthenticationMiddleware
from app.security.credentials import (
    generate_api_key,
    hash_api_key,
    hash_password,
    issue_session,
    looks_like_session_token,
    read_session,
    read_session_claims,
    verify_password,
)

SECRET = "test-secret-not-a-real-one"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# ── Passwords ────────────────────────────────────────────────────────────────


def test_a_password_verifies_against_its_own_hash():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored) is True
    assert verify_password("Correct horse battery staple", stored) is False


def test_the_same_password_hashes_differently_every_time():
    """Per-user salt: two accounts sharing a password must not share a hash."""
    assert hash_password("same") != hash_password("same")


def test_a_corrupt_stored_hash_is_a_failure_not_an_exception():
    for junk in ("", "not-a-hash", "scrypt$only-one-part", "md5$a$b"):
        assert verify_password("anything", junk) is False


# ── Sessions ─────────────────────────────────────────────────────────────────


def test_a_session_round_trips_to_the_user_it_names():
    assert read_session(issue_session("user-1", SECRET, ttl_seconds=60), SECRET) == "user-1"


def test_a_session_signed_with_another_secret_is_refused():
    token = issue_session("user-1", SECRET, ttl_seconds=60)
    assert read_session(token, "a-different-secret") is None


def test_an_edited_session_is_refused():
    """The point of signing: the user id cannot be swapped for someone else's."""
    token = issue_session("user-1", SECRET, ttl_seconds=60)
    header, _, signature = token.split(".")
    forged = _b64(json.dumps({"iss": "threat-intel-platform", "sub": "admin",
                              "exp": int(time.time()) + 60}).encode())
    assert read_session(f"{header}.{forged}.{signature}", SECRET) is None


def test_an_expired_session_is_refused():
    assert read_session(issue_session("user-1", SECRET, ttl_seconds=-1), SECRET) is None


def test_rubbish_does_not_crash_the_reader():
    for junk in ("", "a", "a.b", "....", "a.b.c.d"):
        assert read_session(junk, SECRET) is None


# ── API keys ─────────────────────────────────────────────────────────────────


def test_an_api_key_is_identifiable_and_only_its_hash_is_stored():
    minted = generate_api_key()
    assert minted.plaintext.startswith("tip_")
    assert minted.prefix == minted.plaintext[:12]
    assert minted.key_hash == hash_api_key(minted.plaintext)
    # The stored form must not contain the key, or storing it defeats the point.
    assert minted.plaintext not in minted.key_hash


def test_two_api_keys_are_never_the_same():
    assert generate_api_key().plaintext != generate_api_key().plaintext


# ── Middleware ───────────────────────────────────────────────────────────────


def _client(monkeypatch, *, mode: str, identity=None) -> TestClient:
    """A minimal app carrying the real middleware, with identity lookup stubbed."""
    import app.middleware.auth as auth_mod

    class _Settings:
        auth_mode = mode
        session_secret = SECRET
        # No ingest exemption in these cases: they are about the credential
        # path, and a stray trusted range would quietly make them pass.
        ingest_trusted_networks: list = []
        ingest_trusted_path_set: frozenset = frozenset()

    monkeypatch.setattr(auth_mod, "get_settings", lambda: _Settings())
    monkeypatch.setattr(auth_mod, "_identify", lambda request, settings: identity)

    api = FastAPI()
    api.add_middleware(AuthenticationMiddleware)

    @api.get("/api/health")
    def health():
        return {"ok": True}

    @api.get("/api/dashboard/stats")
    def stats():
        return {"secret": "live data"}

    @api.delete("/api/clients/{client_id}")
    def delete_client(client_id: str):
        return {"deleted": client_id}

    return TestClient(api)


def test_enforce_denies_a_read_with_no_credential(monkeypatch):
    response = _client(monkeypatch, mode="enforce").get("/api/dashboard/stats")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"
    assert "live data" not in response.text


def test_enforce_denies_a_delete_with_no_credential(monkeypatch):
    """The finding named DELETE /api/clients/{id} specifically."""
    assert _client(monkeypatch, mode="enforce").delete("/api/clients/abc").status_code == 401


def test_enforce_admits_a_recognised_caller(monkeypatch):
    client = _client(monkeypatch, mode="enforce", identity={"kind": "api_key", "role": "ingest"})
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    assert response.json()["secret"] == "live data"


def test_health_stays_open_because_the_container_probe_uses_it(monkeypatch):
    """Locking this makes the API unstartable rather than secure."""
    assert _client(monkeypatch, mode="enforce").get("/api/health").status_code == 200


def test_the_unprefixed_health_probe_is_open_too(monkeypatch):
    """TraceCat's delivery template preflights /health before it sends.

    That path is not under /api, so default-deny refused it with a 401 — and a
    failed preflight means a batch of alerts is never sent at all. The
    appliance is not supposed to need modifying, so the probe answers here.
    """
    import app.middleware.auth as auth_mod

    class _Settings:
        auth_mode = "enforce"
        session_secret = SECRET
        ingest_trusted_networks: list = []
        ingest_trusted_path_set: frozenset = frozenset()

    monkeypatch.setattr(auth_mod, "get_settings", lambda: _Settings())
    monkeypatch.setattr(auth_mod, "_identify", lambda request, settings: None)

    api = FastAPI()
    api.add_middleware(AuthenticationMiddleware)

    @api.get("/health")
    def health():
        return {"status": "ok"}

    @api.get("/metrics")
    def metrics():
        return {"secret": "not a liveness probe"}

    client = TestClient(api)
    assert client.get("/health").status_code == 200
    # And only that path: being outside /api is not itself a reason to be open.
    assert client.get("/metrics").status_code == 401


def test_monitor_lets_an_unauthenticated_request_through(monkeypatch, caplog):
    """The rollout mode. If this ever denies, a live alert pipeline drops alerts."""
    with caplog.at_level("WARNING"):
        response = _client(monkeypatch, mode="monitor").get("/api/dashboard/stats")
    assert response.status_code == 200
    # And it has to be loud: the mode only works if somebody reads the lines.
    assert any("UNAUTHENTICATED" in record.message for record in caplog.records)


def test_monitor_does_not_invent_an_identity(monkeypatch):
    """Route code must not mistake a tolerated caller for an authenticated one."""
    import app.middleware.auth as auth_mod

    class _Settings:
        auth_mode = "monitor"
        session_secret = SECRET
        ingest_trusted_networks: list = []
        ingest_trusted_path_set: frozenset = frozenset()

    monkeypatch.setattr(auth_mod, "get_settings", lambda: _Settings())
    monkeypatch.setattr(auth_mod, "_identify", lambda request, settings: None)

    api = FastAPI()
    api.add_middleware(AuthenticationMiddleware)
    seen: dict = {}

    @api.get("/api/whoami")
    def whoami():
        return {"ok": True}

    @api.middleware("http")
    async def capture(request, call_next):
        response = await call_next(request)
        seen["identity"] = getattr(request.state, "identity", "unset")
        return response

    TestClient(api).get("/api/whoami")
    assert seen["identity"] is None


def test_preflight_is_never_challenged(monkeypatch):
    """A CORS preflight carries no credentials by definition."""
    response = _client(monkeypatch, mode="enforce").options(
        "/api/dashboard/stats",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code != 401


# ── The ingest network exemption ─────────────────────────────────────────────
#
# An appliance whose webhook cannot carry a header still has to deliver, so its
# address is exempted. The danger is that the platform's own frontend reaches
# this API from the compose bridge, so every browser request arrives from one
# internal address — an exemption keyed on address alone is a full bypass.


def _ingest_client(monkeypatch, *, cidrs: str, peer: str) -> TestClient:
    import app.middleware.auth as auth_mod

    class _Settings:
        auth_mode = "enforce"
        session_secret = SECRET
        ingest_trusted_paths = "/api/alert-investigations"
        ingest_trusted_path_set = frozenset({"/api/alert-investigations"})

        @property
        def ingest_trusted_networks(self):
            import ipaddress

            return [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs.split(",") if c.strip()]

    monkeypatch.setattr(auth_mod, "get_settings", lambda: _Settings())
    monkeypatch.setattr(auth_mod, "_identify", lambda request, settings: None)

    api = FastAPI()
    api.add_middleware(AuthenticationMiddleware)

    @api.post("/api/alert-investigations")
    def ingest():
        return {"accepted": True}

    @api.get("/api/investigations")
    def read():
        return {"secret": "live data"}

    @api.delete("/api/clients/{client_id}")
    def delete_client(client_id: str):
        return {"deleted": client_id}

    return TestClient(api, client=(peer, 50000))


def test_the_appliance_can_post_alerts_without_a_credential(monkeypatch):
    client = _ingest_client(monkeypatch, cidrs="172.23.10.16/32", peer="172.23.10.16")
    assert client.post("/api/alert-investigations", json={}).status_code == 200


def test_the_same_address_cannot_read(monkeypatch):
    """The exemption is for delivery, not for access."""
    client = _ingest_client(monkeypatch, cidrs="172.23.10.16/32", peer="172.23.10.16")
    assert client.get("/api/investigations").status_code == 401


def test_the_same_address_cannot_delete(monkeypatch):
    client = _ingest_client(monkeypatch, cidrs="172.23.10.16/32", peer="172.23.10.16")
    assert client.delete("/api/clients/abc").status_code == 401


def test_another_address_posting_the_same_route_is_refused(monkeypatch):
    client = _ingest_client(monkeypatch, cidrs="172.23.10.16/32", peer="10.0.0.9")
    assert client.post("/api/alert-investigations", json={}).status_code == 401


def test_a_forwarded_for_header_cannot_claim_the_exemption(monkeypatch):
    """The header is written by the caller. Trusting it would exempt anyone."""
    client = _ingest_client(monkeypatch, cidrs="172.23.10.16/32", peer="10.0.0.9")
    response = client.post(
        "/api/alert-investigations",
        json={},
        headers={"X-Forwarded-For": "172.23.10.16", "X-Real-IP": "172.23.10.16"},
    )
    assert response.status_code == 401


def test_with_no_ranges_configured_nothing_is_exempt(monkeypatch):
    client = _ingest_client(monkeypatch, cidrs="", peer="172.23.10.16")
    assert client.post("/api/alert-investigations", json={}).status_code == 401


# ── Public paths still have to recognise the caller ──────────────────────────
#
# /auth/status and /auth/me are public because the UI must be able to ask "am I
# signed in" before it has anywhere to sign in from. But public was implemented
# as "return immediately", which skipped identification — so both routes, whose
# entire job is to report the caller, answered "nobody" to a request carrying a
# valid session. The UI read that as signed-out, sent the user to /login, the
# login succeeded, and the next status check said "nobody" again: a redirect
# loop on a correct password.


def _identity_on(monkeypatch, path: str, *, identity) -> object:
    """What the route handler sees in request.state.identity on `path`."""
    import app.middleware.auth as auth_mod

    class _Settings:
        auth_mode = "enforce"
        session_secret = SECRET
        ingest_trusted_networks: list = []
        ingest_trusted_path_set: frozenset = frozenset()

    monkeypatch.setattr(auth_mod, "get_settings", lambda: _Settings())
    monkeypatch.setattr(auth_mod, "_identify", lambda request, settings: identity)

    api = FastAPI()
    api.add_middleware(AuthenticationMiddleware)
    seen: dict = {}

    @api.get(path)
    def route(request: Request):
        seen["identity"] = getattr(request.state, "identity", "unset")
        return {"ok": True}

    response = TestClient(api).get(path)
    assert response.status_code == 200, "a public path must stay reachable"
    return seen["identity"]


def test_a_public_path_reports_the_signed_in_caller(monkeypatch):
    """The redirect loop: a valid session reaching /auth/status read as nobody."""
    who = {"kind": "user", "username": "admin", "role": "admin"}
    assert _identity_on(monkeypatch, "/api/auth/status", identity=who) == who


def test_the_same_holds_for_me(monkeypatch):
    who = {"kind": "user", "username": "admin", "role": "admin"}
    assert _identity_on(monkeypatch, "/api/auth/me", identity=who) == who


def test_a_public_path_with_no_credential_reports_nobody(monkeypatch):
    """Still public, and still honest: identification is best-effort, not required."""
    assert _identity_on(monkeypatch, "/api/auth/status", identity=None) is None


# ── The session token is a JWT ───────────────────────────────────────────────
#
# It moved from an ad-hoc `<id>.<expiry>.<hmac>` string to a standard JWT, so
# that a script, the UI and eventually Entra ID are all handling one shape of
# token. The forgeries below are the reason a JWT verifier is worth testing at
# all: the algorithm is named *inside the token*, by whoever sends it.


def test_a_session_token_is_a_readable_jwt():
    token = issue_session("user-1", SECRET, ttl_seconds=60, username="admin", role="admin")
    header_b64, payload_b64, _ = token.split(".")
    assert json.loads(_unb64(header_b64)) == {"alg": "HS256", "typ": "JWT"}

    claims = json.loads(_unb64(payload_b64))
    assert claims["sub"] == "user-1"
    assert claims["iss"] == "threat-intel-platform"
    assert claims["username"] == "admin" and claims["role"] == "admin"
    assert claims["exp"] > claims["iat"]


def test_verified_claims_come_back_whole():
    token = issue_session("user-1", SECRET, ttl_seconds=60, role="analyst")
    assert read_session_claims(token, SECRET)["role"] == "analyst"


def test_an_unsigned_token_is_refused():
    """alg=none, the oldest JWT forgery there is."""
    header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"iss": "threat-intel-platform", "sub": "admin",
                               "exp": int(time.time()) + 600}).encode())
    assert read_session(f"{header}.{payload}.", SECRET) is None
    assert read_session(f"{header}.{payload}.{_b64(b'')}", SECRET) is None


def test_a_token_naming_another_algorithm_is_refused():
    """Even signed correctly with our own secret, the header must say HS256.

    Pinning the algorithm rather than believing the token is the habit that
    stops the RS256-to-HS256 confusion attack the day an asymmetric key is
    introduced — which is exactly what Entra ID sign-in brings.
    """
    header = _b64(json.dumps({"alg": "HS512", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"iss": "threat-intel-platform", "sub": "admin",
                               "exp": int(time.time()) + 600}).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64(hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    assert read_session(f"{signing_input}.{signature}", SECRET) is None


def test_a_token_from_another_issuer_is_refused():
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"iss": "somewhere-else", "sub": "admin",
                               "exp": int(time.time()) + 600}).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64(hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    assert read_session(f"{signing_input}.{signature}", SECRET) is None


def test_a_token_naming_nobody_is_refused():
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"iss": "threat-intel-platform", "exp": int(time.time()) + 600}).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64(hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    assert read_session(f"{signing_input}.{signature}", SECRET) is None


def test_a_token_that_is_not_valid_yet_is_refused():
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    soon = int(time.time()) + 600
    payload = _b64(json.dumps({"iss": "threat-intel-platform", "sub": "a",
                               "nbf": soon, "exp": soon + 600}).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64(hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    assert read_session(f"{signing_input}.{signature}", SECRET) is None


def test_the_old_session_format_no_longer_verifies():
    """The cutover is deliberate: everyone signs in once more, nothing lingers."""
    legacy_body = f"user-1.{int(time.time()) + 600}"
    legacy_signature = _b64(hmac.new(SECRET.encode(), legacy_body.encode(), hashlib.sha256).digest())
    assert read_session(f"{legacy_body}.{legacy_signature}", SECRET) is None


@pytest.mark.parametrize(
    "value,is_session",
    [
        ("tip_abcdefghijklmnop", False),   # an API key, even with dots after it
        ("eyJhbGc.eyJzdWI.sig", True),
        ("not-a-token", False),
        ("", False),
    ],
)
def test_a_bearer_header_is_routed_to_the_right_verifier(value, is_session):
    """Sessions and API keys share one header; the prefix decides which is which."""
    assert looks_like_session_token(value) is is_session


# ── Nobody can lock everybody out ────────────────────────────────────────────


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _CountingDB:
    """Stands in for the session, answering only the count this guard asks for."""

    def __init__(self, other_admins: int):
        self._other_admins = other_admins

    async def execute(self, *_args, **_kwargs):
        return _Result(self._other_admins)


class _Row:
    def __init__(self, role="admin", row_id="11111111-1111-1111-1111-111111111111"):
        self.role = role
        self.id = row_id


def _guard(row, db, identity):
    import asyncio

    return asyncio.run(_refuse_if_last_admin(row, db, identity, action="deactivate"))


def test_the_last_administrator_cannot_be_deactivated():
    """There is no way back from this short of editing the database by hand."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _guard(_Row(), _CountingDB(other_admins=0), {"id": "someone-else"})
    assert caught.value.status_code == 409


def test_an_administrator_cannot_deactivate_their_own_account():
    """The commonest way to do it by accident, and still a lockout."""
    from fastapi import HTTPException

    row = _Row()
    with pytest.raises(HTTPException):
        _guard(row, _CountingDB(other_admins=3), {"id": row.id})


def test_another_administrator_may_be_deactivated_when_one_remains():
    _guard(_Row(), _CountingDB(other_admins=1), {"id": "someone-else"})


def test_an_analyst_is_not_protected_by_the_guard():
    _guard(_Row(role="analyst"), _CountingDB(other_admins=0), {"id": "someone-else"})
