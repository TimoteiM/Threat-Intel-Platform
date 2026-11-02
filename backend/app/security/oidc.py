"""Microsoft Entra ID sign-in: discovery, PKCE, and ID token validation.

An OpenID Connect authorization code flow is a short list of steps with a long
list of ways to get it wrong, so each guard here says which attack it is for.

The shape of it:

1. The browser asks for /api/auth/oidc/start. We mint `state`, `nonce` and a
   PKCE verifier, put them in a signed, short-lived, HttpOnly cookie, and send
   the browser to Microsoft.
2. Microsoft authenticates the person and redirects back with a `code`.
3. We check `state` against the cookie, exchange the code over TLS for an ID
   token, verify its signature and claims, and only then issue our own session
   cookie — the same one password login issues, so nothing downstream changes.

Why the pieces exist:

* **state** — the callback is a GET anyone can navigate a victim's browser to.
  Without it, an attacker completes a flow with *their* code and silently logs
  the victim into the attacker's account (login CSRF).
* **PKCE** — binds the code to this browser's flow, so a code captured in
  transit, in a log, or in a Referer header cannot be redeemed by anyone else.
* **nonce** — binds the ID token to this flow, which is what stops a token
  obtained elsewhere being replayed into our callback.
* **signature and issuer** — an ID token is a bearer statement about who
  someone is. Unverified, it is a text file the caller wrote themselves.
* **tenant** — the single most important line in this module. See `_check_tid`.

No new dependency: `httpx` is already used for collectors and `cryptography`
ships with the image, which is all RS256 verification needs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)

# The in-flight flow, not a session: it exists between the redirect out and the
# redirect back, and is deleted the moment the callback consumes it.
OIDC_FLOW_COOKIE = "tip_oidc"
FLOW_TTL_SECONDS = 600

# Every claim carrying a time is checked against our clock, and the two clocks
# are not the same clock. Two minutes is the usual allowance.
CLOCK_SKEW_SECONDS = 120

# `openid` identifies, `profile` gives a display name, `email` gives an address.
# Nothing else is requested: this is sign-in, not access to anyone's mailbox.
SCOPES = "openid profile email"

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_METADATA_TTL = 3600
_JWKS_TTL = 3600
_metadata_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}

_HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class OIDCError(Exception):
    """Sign-in could not be completed. The message is for the log, not the user.

    Callers turn this into a generic failure on the login page: telling an
    anonymous caller precisely which claim failed helps only the person probing.
    """


# ── Discovery ────────────────────────────────────────────────────────────────


def authority(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{str(tenant_id).strip()}/v2.0"


async def get_metadata(tenant_id: str, *, now: float | None = None) -> dict:
    """The tenant's OpenID configuration, cached for an hour.

    Read rather than hardcoded because Microsoft has moved these endpoints
    before, and a pinned URL becomes an outage on the day they move again.
    """
    now = time.time() if now is None else now
    key = str(tenant_id).strip().lower()
    cached = _metadata_cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    url = f"{authority(tenant_id)}/.well-known/openid-configuration"
    document = await _get_json(url)
    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not document.get(required):
            raise OIDCError(f"Tenant metadata is missing {required}")
    _metadata_cache[key] = (now + _METADATA_TTL, document)
    return document


async def get_jwks(jwks_uri: str, *, force: bool = False, now: float | None = None) -> dict:
    """Signing keys, cached. `force` refetches, for a key we have not seen.

    Microsoft rolls these keys on their own schedule. Without the refetch, a
    rollover would break sign-in for everyone until the cache expired.
    """
    now = time.time() if now is None else now
    cached = _jwks_cache.get(jwks_uri)
    if cached and cached[0] > now and not force:
        return cached[1]
    document = await _get_json(jwks_uri)
    _jwks_cache[jwks_uri] = (now + _JWKS_TTL, document)
    return document


async def _get_json(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
    except Exception as exc:
        raise OIDCError(f"Could not read {url}: {exc}") from exc


def reset_caches() -> None:
    """For tests, and for an operator who has just changed the tenant."""
    _metadata_cache.clear()
    _jwks_cache.clear()


# ── The in-flight flow ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Flow:
    state: str
    nonce: str
    verifier: str
    next_path: str


def start_flow(next_path: str) -> Flow:
    # token_urlsafe(32) is 256 bits from the system CSPRNG for each value. A
    # guessable state or nonce is the same as not having one.
    return Flow(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(64),
        next_path=safe_next(next_path),
    )


def safe_next(candidate: str | None) -> str:
    """Only ever a path on this site.

    A `next` that survives into a redirect is an open redirect, which is how a
    convincing phishing link gets built out of a domain people already trust.
    Anything with a scheme, a host, or a backslash is discarded rather than
    repaired — a sanitiser that tries to fix hostile input eventually loses.
    """
    value = str(candidate or "").strip()
    if (
        not value
        or not value.startswith("/")
        or value.startswith("//")
        or value.startswith("/\\")
        or "\\" in value
        or "\n" in value
        or "\r" in value
    ):
        return "/dashboard"
    return value


def seal_flow(flow: Flow, secret: str, *, now: float | None = None) -> str:
    """The flow, signed, to travel in a cookie.

    Signed rather than stored server-side so sign-in needs no shared session
    store and survives a restart or a second API replica. The cookie is
    HttpOnly, so script on the page cannot read the verifier out of it.
    """
    now = time.time() if now is None else now
    payload = {
        "s": flow.state,
        "n": flow.nonce,
        "v": flow.verifier,
        "p": flow.next_path,
        "e": int(now) + FLOW_TTL_SECONDS,
    }
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{body}.{_sign(body, secret)}"


def open_flow(cookie: str | None, secret: str, *, now: float | None = None) -> Flow | None:
    """The flow this browser started, or None if forged, expired or absent."""
    now = time.time() if now is None else now
    try:
        body, signature = str(cookie or "").rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(body, secret), signature):
        return None
    try:
        payload = json.loads(_unb64(body))
        if float(payload["e"]) < now:
            return None
        return Flow(
            state=str(payload["s"]),
            nonce=str(payload["n"]),
            verifier=str(payload["v"]),
            next_path=safe_next(payload.get("p")),
        )
    except Exception:
        return None


def authorization_url(metadata: dict, settings, flow: Flow) -> str:
    from urllib.parse import urlencode

    query = {
        "client_id": str(settings.oidc_client_id).strip(),
        "response_type": "code",
        "redirect_uri": str(settings.oidc_redirect_url).strip(),
        "response_mode": "query",
        "scope": SCOPES,
        "state": flow.state,
        "nonce": flow.nonce,
        "code_challenge": _challenge(flow.verifier),
        "code_challenge_method": "S256",
    }
    domains = settings.oidc_allowed_domain_list
    if len(domains) == 1:
        # A hint only — it pre-fills the sign-in box. It is not a control, and
        # nothing downstream trusts it; the real check is _check_domain.
        query["domain_hint"] = domains[0]
    return f"{metadata['authorization_endpoint']}?{urlencode(query)}"


def _challenge(verifier: str) -> str:
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


# ── Code exchange ────────────────────────────────────────────────────────────


async def exchange_code(metadata: dict, settings, *, code: str, verifier: str) -> dict:
    """Trade the code for tokens, over TLS, as a confidential client.

    The secret never reaches the browser: this call is made by the API, which
    is why this is a confidential client and not a SPA doing it in JavaScript.
    """
    form = {
        "client_id": str(settings.oidc_client_id).strip(),
        "client_secret": str(settings.oidc_client_secret).strip(),
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": str(settings.oidc_redirect_url).strip(),
        "code_verifier": verifier,
        "scope": SCOPES,
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.post(metadata["token_endpoint"], data=form)
    except Exception as exc:
        raise OIDCError(f"Token endpoint unreachable: {exc}") from exc

    if response.status_code != 200:
        # Microsoft's error body names the misconfiguration (wrong secret, wrong
        # redirect URI) and contains no token, so it is worth having in the log.
        raise OIDCError(f"Token exchange refused ({response.status_code}): {response.text[:400]}")

    payload = response.json()
    if not payload.get("id_token"):
        raise OIDCError("Token response carried no id_token")
    return payload


# ── ID token validation ──────────────────────────────────────────────────────


async def validate_id_token(id_token: str, metadata: dict, settings, *, expected_nonce: str,
                            now: float | None = None) -> dict:
    """Verified claims, or OIDCError. Nothing here is skipped on a happy path."""
    now = time.time() if now is None else now
    header, claims = _split_unverified(id_token)

    if str(header.get("alg", "")).upper() != "RS256":
        # `alg` is attacker-controlled. "none" and an HMAC alg verified against
        # the public key are the two classic JWT forgeries; only RS256 is taken.
        raise OIDCError(f"Unexpected token algorithm {header.get('alg')!r}")

    await _check_signature(id_token, header, metadata)

    _check_iss(claims, metadata)
    _check_tid(claims, settings)
    _check_aud(claims, settings)
    _check_times(claims, now)
    _check_nonce(claims, expected_nonce)
    return claims


async def _check_signature(id_token: str, header: dict, metadata: dict) -> None:
    kid = header.get("kid")
    if not kid:
        raise OIDCError("Token header carried no kid")

    jwks = await get_jwks(metadata["jwks_uri"])
    key = _find_key(jwks, kid)
    if key is None:
        # Not yet a failure: this is what a key rollover looks like.
        jwks = await get_jwks(metadata["jwks_uri"], force=True)
        key = _find_key(jwks, kid)
    if key is None:
        raise OIDCError(f"No signing key matches kid {kid!r}")

    signing_input, signature = id_token.rsplit(".", 1)
    try:
        _public_key(key).verify(
            _unb64(signature),
            signing_input.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise OIDCError("Token signature does not verify") from exc
    except Exception as exc:
        raise OIDCError(f"Token signature could not be checked: {exc}") from exc


def _find_key(jwks: dict, kid: str) -> dict | None:
    for key in jwks.get("keys") or []:
        if key.get("kid") == kid and str(key.get("kty", "RSA")).upper() == "RSA":
            return key
    return None


def _public_key(jwk: dict):
    numbers = rsa.RSAPublicNumbers(
        e=int.from_bytes(_unb64(jwk["e"]), "big"),
        n=int.from_bytes(_unb64(jwk["n"]), "big"),
    )
    return numbers.public_key()


def _check_iss(claims: dict, metadata: dict) -> None:
    expected = str(metadata["issuer"])
    # The multi-tenant metadata document carries a placeholder here.
    if "{tenantid}" in expected:
        expected = expected.replace("{tenantid}", str(claims.get("tid", "")))
    if str(claims.get("iss", "")) != expected:
        raise OIDCError(f"Issuer {claims.get('iss')!r} is not {expected!r}")


def _check_tid(claims: dict, settings) -> None:
    """The tenant pin, and the reason `common` is not used anywhere above.

    Every Microsoft account in the world can obtain a valid, correctly signed
    ID token. What makes one of them *yours* is `tid`. Without this check, the
    sign-in page accepts anybody with any Microsoft account — a personal
    outlook.com address, or a tenant an attacker registered this morning and
    populated with a user called whatever they liked.
    """
    configured = str(settings.oidc_tenant_id or "").strip()
    if not _GUID.match(configured):
        # Configured by domain name. The issuer check above still pinned the
        # token to that directory, so this is consistent, not skipped.
        return
    if str(claims.get("tid", "")).lower() != configured.lower():
        raise OIDCError(f"Token came from tenant {claims.get('tid')!r}, not {configured!r}")


def _check_aud(claims: dict, settings) -> None:
    """Ours, not another application's.

    Tokens minted for a different app in the same tenant are perfectly valid
    tokens; accepting them lets any app in the directory mint sign-ins here.
    """
    audience = claims.get("aud")
    accepted = audience if isinstance(audience, list) else [audience]
    if str(settings.oidc_client_id).strip() not in [str(a) for a in accepted]:
        raise OIDCError(f"Token audience {audience!r} is not this application")


def _check_times(claims: dict, now: float) -> None:
    exp = _as_int(claims.get("exp"))
    if exp is None or exp + CLOCK_SKEW_SECONDS < now:
        raise OIDCError("Token has expired")
    nbf = _as_int(claims.get("nbf"))
    if nbf is not None and nbf - CLOCK_SKEW_SECONDS > now:
        raise OIDCError("Token is not valid yet")
    iat = _as_int(claims.get("iat"))
    if iat is not None and iat - CLOCK_SKEW_SECONDS > now:
        raise OIDCError("Token was issued in the future")


def _check_nonce(claims: dict, expected: str) -> None:
    presented = str(claims.get("nonce", ""))
    if not presented or not expected or not hmac.compare_digest(presented, str(expected)):
        raise OIDCError("Token nonce does not match this sign-in attempt")


# ── Claims → a person ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Principal:
    """Who signed in, reduced to what the platform stores."""

    subject: str      # Entra's `oid`: immutable, survives renames and remarriages
    email: str
    display_name: str


def principal_from_claims(claims: dict) -> Principal:
    # `oid` is the object id within the tenant and never changes. `sub` is
    # pairwise per-application, so it would break if the app were ever
    # re-registered; the email would break the first time someone's name does.
    subject = str(claims.get("oid") or "").strip()
    if not subject:
        raise OIDCError("Token carried no oid claim to identify the user by")

    email = ""
    for claim in ("email", "preferred_username", "upn", "unique_name"):
        candidate = str(claims.get(claim) or "").strip().lower()
        if "@" in candidate:
            email = candidate
            break
    if not email:
        raise OIDCError("Token carried no email address to identify the user by")

    display = str(claims.get("name") or "").strip() or email
    return Principal(subject=subject, email=email, display_name=display[:120])


def check_domain(email: str, settings) -> None:
    """Keep guests out when a domain list is configured.

    A guest invited into the tenant passes every check above — they really are
    an account in your directory — but they are not staff.
    """
    allowed = settings.oidc_allowed_domain_list
    if not allowed:
        return
    domain = str(email).rsplit("@", 1)[-1].lower()
    if domain not in allowed:
        raise OIDCError(f"Address {email!r} is not in an allowed domain")


# ── Encoding helpers ─────────────────────────────────────────────────────────


def _split_unverified(id_token: str) -> tuple[dict, dict]:
    """Header and claims, BEFORE any check. Only for deciding how to verify."""
    try:
        header_b64, claims_b64, _ = str(id_token).split(".")
        return json.loads(_unb64(header_b64)), json.loads(_unb64(claims_b64))
    except Exception as exc:
        raise OIDCError("Token is not a well-formed JWT") from exc


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sign(body: str, secret: str) -> str:
    return _b64(hmac.new(str(secret).encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
