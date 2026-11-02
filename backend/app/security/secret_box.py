"""Encryption at rest for per-tenant integration credentials.

One job: take a credential the platform must be able to *use* later, store it
so that reading the database does not disclose it, and never hand it back
through an API.

Why Fernet
----------
`cryptography` is already a dependency — `app/security/oidc.py` uses it for
RSA signature verification — so this adds no package. Fernet gives
authenticated encryption (AES-128-CBC + HMAC-SHA256), a version byte, and a
timestamp, and `MultiFernet` implements key rotation natively: decrypt under
any configured key, encrypt only under the first. That is the rotation path,
rather than something to invent.

What this refuses to do
-----------------------
**It will not store a secret when no key is configured.** A missing key
degrading to plaintext is the failure that matters here: it would look like
a working feature and every credential in the estate would be readable to
anyone who can read a row. `encrypt()` raises instead. A credential nobody
can save is an outage; a credential silently saved in the clear is a breach,
and the two must not be the same code path.

Key identity, and why each row carries it
-----------------------------------------
Every ciphertext is stored with a `key_id` — a truncated SHA-256 of the key
that encrypted it, never the key. Without it, "re-encrypt every row under the
new key" is a claim nobody can check: a row missed by a rotation is
indistinguishable from one already done. With it, `needs_rotation()` is a
query, and the rotation can be verified rather than asserted. Same discipline
as every other completeness claim in this codebase — if it quantifies over
every row, something has to be able to count the ones left.

Losing the key
--------------
**If `INTEGRATION_ENCRYPTION_KEY` is lost, every stored credential is
unrecoverable.** There is no escrow, no recovery code and no backdoor — that
is the point of encrypting them. The remedy is re-entering each credential,
which means the key belongs wherever the deployment keeps things it cannot
regenerate. `docs/design/integrations.md` states this where an operator will
read it.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

#: How much of the key's digest identifies it. Sixteen hex characters is
#: enough to tell two keys apart in a table of rows and far too little to
#: help anyone reconstruct one.
KEY_ID_LENGTH = 16


class SecretBoxUnconfigured(RuntimeError):
    """No encryption key is configured, so nothing can be stored.

    Raised rather than falling back to plaintext. See the module docstring:
    an outage and a breach must not share a code path.
    """


class SecretBoxUndecryptable(RuntimeError):
    """A stored ciphertext cannot be decrypted with any configured key.

    Either the key was rotated without re-encrypting this row, or the key is
    gone. Distinct from "no key configured", because the operator actions are
    different: one is a rotation to finish, the other is a credential to
    re-enter.
    """


def key_id(key: str) -> str:
    """A stable identifier for a key, derived from the key but not reversible."""
    return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()[:KEY_ID_LENGTH]


def generate_key() -> str:
    """A new key, in the form `INTEGRATION_ENCRYPTION_KEY` expects.

    Here so an operator never has to guess the format, and so a test can make
    one without hard-coding a value that would then live in the repository.
    """
    return Fernet.generate_key().decode("ascii")


@dataclass(frozen=True)
class Sealed:
    """A credential as it is stored. Carries no plaintext, by construction."""

    ciphertext: str
    key_id: str

    def as_row(self) -> dict[str, Any]:
        return {"ciphertext": self.ciphertext, "key_id": self.key_id}


def _normalise(key: str) -> bytes:
    """Accept a Fernet key, or any 32 bytes, and return Fernet key bytes.

    Operators paste what they have. A 32-byte hex or raw string is accepted
    by deriving a Fernet key from it rather than failing on the format —
    but a *short* value is refused, because silently stretching a weak secret
    into a key that looks strong is the kind of help that hides a problem.
    """
    raw = key.strip()
    if not raw:
        raise SecretBoxUnconfigured(
            "INTEGRATION_ENCRYPTION_KEY is not set. Integration credentials "
            "cannot be stored without it, and are deliberately not stored in "
            "the clear instead. Generate one with "
            "`python -c \"from app.security.secret_box import generate_key; "
            "print(generate_key())\"` and keep it where the deployment keeps "
            "things it cannot regenerate — if it is lost, every stored "
            "credential is unrecoverable."
        )
    try:
        # The ordinary case: a Fernet key, which is urlsafe-b64 of 32 bytes.
        if len(base64.urlsafe_b64decode(raw.encode("ascii"))) == 32:
            return raw.encode("ascii")
    except Exception:  # noqa: BLE001 - not a Fernet key; fall through
        pass
    if len(raw) < 32:
        raise SecretBoxUnconfigured(
            "INTEGRATION_ENCRYPTION_KEY is shorter than 32 characters. It is "
            "refused rather than stretched: a short secret turned into a "
            "key-shaped value looks as strong as a real one and is not."
        )
    return base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())


class SecretBox:
    """Encrypt and decrypt integration credentials.

    `keys[0]` encrypts. Every key decrypts, so a rotation can be performed
    without downtime: add the new key at the front, re-encrypt the rows,
    then drop the old one.
    """

    def __init__(self, keys: list[str] | None = None) -> None:
        self._keys = [k for k in (keys or []) if (k or "").strip()]
        self._fernets = [Fernet(_normalise(k)) for k in self._keys] if self._keys else []
        self._multi = MultiFernet(self._fernets) if self._fernets else None

    @property
    def configured(self) -> bool:
        return bool(self._multi)

    @property
    def primary_key_id(self) -> str | None:
        return key_id(self._keys[0]) if self._keys else None

    @property
    def known_key_ids(self) -> set[str]:
        return {key_id(k) for k in self._keys}

    def encrypt(self, plaintext: str) -> Sealed:
        """Seal a credential. Raises if no key is configured."""
        if not self._multi:
            _normalise("")                      # raises SecretBoxUnconfigured
        token = self._multi.encrypt(plaintext.encode("utf-8"))  # type: ignore[union-attr]
        return Sealed(ciphertext=token.decode("ascii"),
                      key_id=self.primary_key_id or "")

    def decrypt(self, ciphertext: str) -> str:
        """Open a credential for the platform's own use — never for a response.

        Callers are the connectors. No API serializer may call this; the
        write-only rule is enforced by the schemas, and
        `test_integration_secrets.py` asserts no response model carries a
        secret field.
        """
        if not self._multi:
            _normalise("")
        try:
            return self._multi.decrypt(ciphertext.encode("ascii")).decode("utf-8")  # type: ignore[union-attr]
        except InvalidToken as exc:
            raise SecretBoxUndecryptable(
                "A stored credential could not be decrypted with any "
                "configured key. Either INTEGRATION_ENCRYPTION_KEY was "
                "rotated without re-encrypting this row — check "
                "`needs_rotation` — or the key that encrypted it is gone, in "
                "which case the credential must be re-entered."
            ) from exc

    def needs_rotation(self, row_key_id: str | None) -> bool:
        """Whether this row is encrypted under something other than the
        primary key.

        The question a rotation has to be able to answer about every row, or
        "all rows re-encrypted" is an assertion rather than a fact.
        """
        if not self.configured:
            return False
        return (row_key_id or "") != self.primary_key_id

    def rotate(self, ciphertext: str) -> Sealed:
        """Re-encrypt under the primary key, without seeing the plaintext twice.

        `MultiFernet.rotate` decrypts with whichever key works and re-encrypts
        with the first, so the plaintext never leaves this call.
        """
        if not self._multi:
            _normalise("")
        try:
            token = self._multi.rotate(ciphertext.encode("ascii"))  # type: ignore[union-attr]
        except InvalidToken as exc:
            raise SecretBoxUndecryptable(
                "A stored credential could not be re-encrypted because no "
                "configured key decrypts it. It must be re-entered."
            ) from exc
        return Sealed(ciphertext=token.decode("ascii"),
                      key_id=self.primary_key_id or "")


def from_settings() -> SecretBox:
    """The box this deployment is configured for.

    Primary key first, then any retired keys, so rotation is a config change
    plus a sweep rather than a migration.
    """
    from app.config import get_settings

    settings = get_settings()
    primary = (getattr(settings, "integration_encryption_key", "") or "").strip()
    retired = [
        k.strip()
        for k in (getattr(settings, "integration_encryption_keys_retired", "") or "").split(",")
        if k.strip()
    ]
    return SecretBox([primary, *retired] if primary else retired)
