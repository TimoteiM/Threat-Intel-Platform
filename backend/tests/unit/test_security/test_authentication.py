"""Authentication, from the credential primitives up to the middleware.

Context: the platform shipped with none. Every one of its documented operations
answered requests carrying no credential, and the schema was readable by anyone
on the network. These cover the pieces that close that — including the part an
outage would come from, that `monitor` mode really does let traffic through
while the ingest integrations are being migrated onto a key.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.auth import AuthenticationMiddleware
from app.security.credentials import (
    generate_api_key,
    hash_api_key,
    hash_password,
    issue_session,
    read_session,
    verify_password,
)

SECRET = "test-secret-not-a-real-one"


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
    _, expires, signature = token.rsplit(".", 2)
    assert read_session(f"admin.{expires}.{signature}", SECRET) is None


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
