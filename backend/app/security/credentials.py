"""Password hashing, session tokens and API keys, on the standard library only.

The image had no password hashing of any kind, so every option here was a new
dependency. `hashlib.scrypt` is memory-hard, is in the standard library, and is
the thing to reach for when bcrypt and argon2 are not already present — adding
a C-extension dependency to close an unauthenticated-access finding means the
fix ships slower and with a rebuild risk attached.

Three credential kinds, deliberately distinct:

* A **password** is hashed with a per-user salt and never leaves the database.
* A **session token** is a JWT: a signed, expiring statement that a browser
  holds in an HttpOnly cookie, and that a script can equally send as
  `Authorization: Bearer`. No server-side session store to keep in sync or to
  leak, and the same shape Entra ID issues, so there is one kind of token in
  the system rather than two.
* An **API key** is for callers that cannot log in — the alert ingest. Only its
  SHA-256 is stored, so a dumped database hands over no working keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

# scrypt parameters. n=2**14 with r=8,p=1 is roughly 16MB and a few tens of
# milliseconds per hash — enough to make offline cracking expensive without
# making a login feel slow.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32

# Keys are recognisable on sight, so one turning up in a log or a ticket is
# identifiable as a platform credential and can be revoked.
API_KEY_PREFIX = "tip_"
_API_KEY_BYTES = 32

SESSION_COOKIE = "tip_session"


def hash_password(password: str) -> str:
    """`scrypt$<salt b64>$<hash b64>` — salt and parameters travel with it."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_BYTES
    )
    return f"scrypt${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. A malformed stored value is a failure, not a crash."""
    try:
        scheme, salt_b64, digest_b64 = str(stored).split("$", 2)
        if scheme != "scrypt":
            return False
        salt = _unb64(salt_b64)
        expected = _unb64(digest_b64)
    except Exception:
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)


def generate_password(words: int = 4) -> str:
    """A generated password that a person can actually retype from a log line."""
    alphabet = "abcdefghijkmnopqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(words)
    )


# ── API keys ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NewApiKey:
    """The one moment the plaintext exists. It is not recoverable afterwards."""

    plaintext: str
    prefix: str
    key_hash: str


def generate_api_key() -> NewApiKey:
    raw = API_KEY_PREFIX + secrets.token_urlsafe(_API_KEY_BYTES)
    return NewApiKey(plaintext=raw, prefix=raw[:12], key_hash=hash_api_key(raw))


def hash_api_key(raw: str) -> str:
    """SHA-256, not scrypt: a 256-bit random key has no dictionary to attack,
    and this runs on every ingest request."""
    return hashlib.sha256(str(raw).strip().encode("utf-8")).hexdigest()


# ── Session tokens ────────────────────────────────────────────────────────────


JWT_ISSUER = "threat-intel-platform"
JWT_ALGORITHM = "HS256"


def issue_session(
    user_id: str,
    secret: str,
    *,
    ttl_seconds: int,
    username: str | None = None,
    role: str | None = None,
) -> str:
    """A signed JWT naming the user, stateless so a restart logs nobody out.

    `username` and `role` ride along for anything that wants to read the token
    without a database round trip — a log line, a debugging session, a script.
    Nothing in this platform authorises on them: the middleware looks the user
    up on every request, so deactivating or demoting somebody takes effect on
    their next call rather than whenever their token happens to expire.
    """
    now = int(time.time())
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload: dict = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + int(ttl_seconds),
        # Distinct per token, so two sessions issued in the same second are
        # still distinguishable in a log.
        "jti": secrets.token_urlsafe(9),
    }
    if username:
        payload["username"] = str(username)
    if role:
        payload["role"] = str(role)

    signing_input = f"{_b64(_json(header))}.{_b64(_json(payload))}"
    return f"{signing_input}.{_sign(signing_input, secret)}"


def read_session(token: str, secret: str) -> str | None:
    """The user id this token proves, or None if it is forged or expired."""
    claims = read_session_claims(token, secret)
    return str(claims["sub"]) if claims else None


def read_session_claims(token: str, secret: str) -> dict | None:
    """Verified claims, or None. Never raises — a bad token is just a refusal."""
    try:
        header_b64, payload_b64, signature = str(token).split(".")
    except ValueError:
        return None

    signing_input = f"{header_b64}.{payload_b64}"
    # Signature first: nothing in the token is worth reading until it verifies.
    if not hmac.compare_digest(_sign(signing_input, secret), signature):
        return None

    try:
        header = json.loads(_unb64(header_b64))
        claims = json.loads(_unb64(payload_b64))
    except Exception:
        return None

    # `alg` is part of the token, which means it is attacker-supplied. "none"
    # and a swapped algorithm are the two classic JWT forgeries, so only the
    # one algorithm this platform issues is accepted — never whatever the
    # token asks for. The signature check above already used HS256 regardless,
    # and this makes that explicit rather than incidental.
    if str(header.get("alg", "")) != JWT_ALGORITHM:
        return None
    if str(claims.get("iss", "")) != JWT_ISSUER:
        return None
    if not str(claims.get("sub", "")):
        return None

    now = int(time.time())
    exp = _as_int(claims.get("exp"))
    if exp is None or exp < now:
        return None
    nbf = _as_int(claims.get("nbf"))
    if nbf is not None and nbf > now:
        return None
    return claims


def looks_like_session_token(value: str) -> bool:
    """Tells a session JWT apart from an API key, for the Bearer header.

    Both arrive as `Authorization: Bearer ...`. API keys carry a deliberate
    `tip_` prefix; a JWT is three dot-separated segments. This only decides
    which verifier to call — neither path trusts the answer.
    """
    candidate = str(value or "")
    return not candidate.startswith(API_KEY_PREFIX) and candidate.count(".") == 2


def _json(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sign(body: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
