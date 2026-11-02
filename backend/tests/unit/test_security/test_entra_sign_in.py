"""Microsoft Entra ID sign-in, concentrating on the checks that are load-bearing.

An ID token is a bearer statement about who somebody is. Every test below is a
forged or misdirected one that must not be accepted, because each corresponds
to a real way OIDC integrations get broken into:

* a token from another Microsoft tenant   → sign in as anyone, from a tenant
                                             the attacker registered themselves
* a token minted for another application  → any app in the directory mints logins
* `alg` swapped to none or HMAC           → the classic JWT forgery
* a replayed token, or one with no nonce  → a token captured elsewhere reused here
* a callback with no flow cookie          → login CSRF

Async functions are driven with asyncio.run rather than a plugin marker so the
file runs under a bare pytest, in the container or out of it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.security import oidc

TENANT = "8f3b1c2d-4e5a-6b7c-8d9e-0a1b2c3d4e5f"
CLIENT = "11112222-3333-4444-5555-666677778888"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
SECRET = "test-secret-not-a-real-one"

# One key for the whole module: RSA generation is the slowest thing here.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_METADATA = {
    "authorization_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize",
    "token_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    "jwks_uri": f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
    "issuer": ISSUER,
}


class _Settings:
    oidc_tenant_id = TENANT
    oidc_client_id = CLIENT
    oidc_client_secret = "shh"
    oidc_redirect_url = "https://tip.example.net/api/auth/oidc/callback"
    oidc_allowed_domains = "expertware.net"
    oidc_auto_provision = True
    oidc_default_role = "analyst"

    @property
    def oidc_allowed_domain_list(self):
        return [d.strip().lower() for d in self.oidc_allowed_domains.split(",") if d.strip()]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _claims(**overrides) -> dict:
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": CLIENT,
        "tid": TENANT,
        "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "preferred_username": "alex.ionescu@expertware.net",
        "name": "Alex Ionescu",
        "nonce": "the-expected-nonce",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    base.update(overrides)
    return base


def _token(claims: dict, *, key=_KEY, kid="key-1", alg="RS256") -> str:
    header = _b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}"
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64(signature)}"


def _jwks(key=_KEY, kid="key-1") -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }
        ]
    }


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test here touches the network; a JWKS fetch would be a real request."""
    async def fake_jwks(uri, *, force=False, now=None):
        return _jwks()

    monkeypatch.setattr(oidc, "get_jwks", fake_jwks)
    oidc.reset_caches()


def _validate(token: str, *, nonce: str = "the-expected-nonce", now: float | None = None) -> dict:
    return asyncio.run(
        oidc.validate_id_token(token, _METADATA, _Settings(), expected_nonce=nonce, now=now)
    )


# ── The token that should work ───────────────────────────────────────────────


def test_a_genuine_token_validates():
    claims = _validate(_token(_claims()))
    assert claims["oid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ── Tokens that must not ─────────────────────────────────────────────────────


def test_a_token_from_another_tenant_is_refused():
    """The single most important check in the module.

    Anyone can create a Microsoft tenant and a user inside it called whatever
    they like. Signature, audience, expiry and even the email domain can all be
    made to look right. `tid` is what makes a token *ours*.
    """
    other = "99999999-9999-9999-9999-999999999999"
    token = _token(_claims(tid=other, iss=f"https://login.microsoftonline.com/{other}/v2.0"))
    with pytest.raises(oidc.OIDCError):
        _validate(token)


def test_the_tenant_pin_holds_on_its_own():
    """Isolates `tid` from the issuer check that also happens to catch this.

    The test above rejects a foreign token at `iss`, so it proves the pair
    works, not the pin. Here the issuer is ours and only `tid` disagrees —
    which is the shape a token takes when the metadata issuer carries a
    {tenantid} placeholder and the issuer check therefore cannot catch it.
    """
    with pytest.raises(oidc.OIDCError, match="tenant"):
        _validate(_token(_claims(tid="99999999-9999-9999-9999-999999999999")))


def test_a_token_for_another_application_is_refused():
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims(aud="another-app-in-the-same-tenant")))


def test_an_unsigned_token_is_refused():
    """alg=none: the header is written by whoever sends the token."""
    header = _b64(json.dumps({"alg": "none", "kid": "key-1"}).encode())
    payload = _b64(json.dumps(_claims()).encode())
    with pytest.raises(oidc.OIDCError):
        _validate(f"{header}.{payload}.")


def test_an_hmac_signed_token_is_refused():
    """The alg-confusion forgery: sign with HMAC over the known public key."""
    import hashlib
    import hmac as hmac_mod

    header = _b64(json.dumps({"alg": "HS256", "kid": "key-1"}).encode())
    payload = _b64(json.dumps(_claims()).encode())
    signing_input = f"{header}.{payload}"
    forged = _b64(hmac_mod.new(b"public-key-bytes", signing_input.encode(), hashlib.sha256).digest())
    with pytest.raises(oidc.OIDCError):
        _validate(f"{signing_input}.{forged}")


def test_a_token_signed_by_the_wrong_key_is_refused():
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims(), key=impostor))


def test_an_edited_payload_is_refused():
    """Signature covers the claims: promoting yourself invalidates the token."""
    token = _token(_claims())
    header, _, signature = token.split(".")
    tampered = _b64(json.dumps(_claims(oid="somebody-else")).encode())
    with pytest.raises(oidc.OIDCError):
        _validate(f"{header}.{tampered}.{signature}")


def test_an_expired_token_is_refused():
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims()), now=time.time() + 7200)


def test_a_token_from_the_future_is_refused():
    future = int(time.time()) + 7200
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims(iat=future, nbf=future, exp=future + 3600)))


def test_a_replayed_token_is_refused():
    """A token that was valid for a different sign-in attempt."""
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims(nonce="a-different-attempt")))


def test_a_token_with_no_nonce_is_refused():
    claims = _claims()
    claims.pop("nonce")
    with pytest.raises(oidc.OIDCError):
        _validate(_token(claims))


def test_a_token_signed_by_an_unknown_key_is_refused():
    with pytest.raises(oidc.OIDCError):
        _validate(_token(_claims(), kid="a-key-we-have-never-seen"))


def test_clock_skew_is_tolerated():
    """A minute of drift between us and Microsoft is not a security event."""
    assert _validate(_token(_claims()), now=time.time() + 3660)["tid"] == TENANT


# ── Who the token says you are ───────────────────────────────────────────────


def test_the_immutable_object_id_identifies_the_person():
    principal = oidc.principal_from_claims(_claims())
    assert principal.subject == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert principal.email == "alex.ionescu@expertware.net"
    assert principal.display_name == "Alex Ionescu"


def test_the_email_claim_is_preferred_and_upn_is_the_fallback():
    assert oidc.principal_from_claims(_claims(email="Alex@Expertware.NET")).email == "alex@expertware.net"
    claims = _claims()
    claims.pop("preferred_username")
    claims["upn"] = "alex@expertware.net"
    assert oidc.principal_from_claims(claims).email == "alex@expertware.net"


def test_a_token_naming_nobody_is_refused():
    claims = _claims()
    claims.pop("oid")
    with pytest.raises(oidc.OIDCError):
        oidc.principal_from_claims(claims)


def test_a_guest_from_outside_the_domain_is_refused():
    """Guests authenticate against the tenant but are not staff."""
    with pytest.raises(oidc.OIDCError):
        oidc.check_domain("contractor@gmail.com", _Settings())


def test_the_domain_check_accepts_staff():
    oidc.check_domain("alex.ionescu@expertware.net", _Settings())


def test_with_no_domains_configured_any_tenant_account_is_accepted():
    class _Open(_Settings):
        oidc_allowed_domains = ""

    oidc.check_domain("guest@partner.example", _Open())


# ── The in-flight flow ───────────────────────────────────────────────────────


def test_a_flow_round_trips():
    flow = oidc.start_flow("/settings")
    assert oidc.open_flow(oidc.seal_flow(flow, SECRET), SECRET) == flow


def test_a_flow_sealed_with_another_secret_is_refused():
    flow = oidc.start_flow("/settings")
    assert oidc.open_flow(oidc.seal_flow(flow, SECRET), "another-secret") is None


def test_an_edited_flow_is_refused():
    """Swapping in your own nonce would defeat the replay check."""
    sealed = oidc.seal_flow(oidc.start_flow("/settings"), SECRET)
    body, signature = sealed.rsplit(".", 1)
    forged = _b64(json.dumps({"s": "x", "n": "x", "v": "x", "p": "/", "e": time.time() + 600}).encode())
    assert oidc.open_flow(f"{forged}.{signature}", SECRET) is None


def test_an_expired_flow_is_refused():
    sealed = oidc.seal_flow(oidc.start_flow("/settings"), SECRET, now=time.time() - 3600)
    assert oidc.open_flow(sealed, SECRET) is None


def test_a_missing_flow_cookie_is_refused():
    """An unsolicited callback — the login-CSRF case — looks exactly like this."""
    for junk in (None, "", "not-a-cookie", "a.b.c"):
        assert oidc.open_flow(junk, SECRET) is None


def test_state_and_nonce_are_unpredictable():
    flows = [oidc.start_flow("/") for _ in range(10)]
    assert len({f.state for f in flows}) == 10
    assert len({f.nonce for f in flows}) == 10
    assert len({f.verifier for f in flows}) == 10
    assert min(len(f.state) for f in flows) >= 32


# ── Redirecting back ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "hostile",
    [
        "//evil.example",              # protocol-relative: a full redirect off-site
        "https://evil.example",
        "http://evil.example",
        "/\\evil.example",             # backslash, which some parsers read as a slash
        "/dashboard\r\nSet-Cookie: x", # header injection through the Location
        "",
        None,
    ],
)
def test_a_hostile_next_is_discarded(hostile):
    """An open redirect on a trusted domain is how phishing links get built."""
    assert oidc.safe_next(hostile) == "/dashboard"


def test_an_ordinary_next_survives():
    assert oidc.safe_next("/investigations/abc-123") == "/investigations/abc-123"


# ── The authorization request ────────────────────────────────────────────────


def test_the_authorization_url_carries_pkce_and_the_tenant():
    from urllib.parse import parse_qs, urlparse

    flow = oidc.start_flow("/dashboard")
    query = parse_qs(urlparse(oidc.authorization_url(_METADATA, _Settings(), flow)).query)

    assert query["client_id"] == [CLIENT]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [flow.state]
    assert query["nonce"] == [flow.nonce]
    # The challenge is the hash of the verifier, never the verifier itself:
    # sending the verifier here would give PKCE away to anyone watching.
    import hashlib

    expected = _b64(hashlib.sha256(flow.verifier.encode()).digest())
    assert query["code_challenge"] == [expected]
    assert flow.verifier not in oidc.authorization_url(_METADATA, _Settings(), flow)
