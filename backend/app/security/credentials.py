"""Password hashing, session tokens and API keys, on the standard library only.

The image had no password hashing of any kind, so every option here was a new
dependency. `hashlib.scrypt` is memory-hard, is in the standard library, and is
the thing to reach for when bcrypt and argon2 are not already present — adding
a C-extension dependency to close an unauthenticated-access finding means the
fix ships slower and with a rebuild risk attached.

Three credential kinds, deliberately distinct:

* A **password** is hashed with a per-user salt and never leaves the database.
* A **session token** is a signed, expiring statement that a browser holds in
  an HttpOnly cookie. It carries the user id and an expiry, and is verified by
  HMAC — no server-side session store to keep in sync or to leak.
* An **API key** is for callers that cannot log in — the alert ingest. Only its
  SHA-256 is stored, so a dumped database hands over no working keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
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


def issue_session(user_id: str, secret: str, *, ttl_seconds: int) -> str:
    """`<user id>.<expiry>.<hmac>` — stateless, so a restart does not log anyone out."""
    expires = int(time.time()) + int(ttl_seconds)
    body = f"{user_id}.{expires}"
    return f"{body}.{_sign(body, secret)}"


def read_session(token: str, secret: str) -> str | None:
    """The user id this token proves, or None if it is forged or expired."""
    try:
        user_id, expires_raw, signature = str(token).rsplit(".", 2)
    except ValueError:
        return None
    body = f"{user_id}.{expires_raw}"
    if not hmac.compare_digest(_sign(body, secret), signature):
        return None
    try:
        if int(expires_raw) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    return user_id


def _sign(body: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
