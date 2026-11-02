"""Encryption at rest for integration credentials, against the dangerous
directions.

Three of them, in order of how much they would cost:

  1. **no key configured degrades to plaintext.** Every credential in the
     estate readable from a row, behind something that looks like a working
     feature. An outage and a breach must not share a code path.
  2. **a rotation that cannot be verified.** "Every row re-encrypted" is a
     claim quantifying over all rows, so something has to be able to count
     the ones left — otherwise a missed row is indistinguishable from a done
     one until the old key is dropped and the credential is gone.
  3. **unauthenticated storage.** A tampered ciphertext decrypting to
     something is worse than failing, because the connector would then
     authenticate with an attacker's value.

The control each time: the box must still work. A box that refuses
everything passes all three and stores nothing.
"""

from __future__ import annotations

import pytest

from app.security.secret_box import (
    SecretBox,
    SecretBoxUnconfigured,
    SecretBoxUndecryptable,
    generate_key,
    key_id,
)

# Generated per-run, never a literal: a key committed to the repository is a
# key, even in a test.
KEY_A = generate_key()
KEY_B = generate_key()
SECRET = "falcon-client-secret-value-not-real"


# ─── 1. no key must not mean plaintext ───────────────────────────────────

def test_no_key_refuses_to_store_rather_than_storing_in_the_clear():
    box = SecretBox([])
    assert box.configured is False
    with pytest.raises(SecretBoxUnconfigured) as exc:
        box.encrypt(SECRET)
    # And it says what to do, because the operator meets this first.
    assert "INTEGRATION_ENCRYPTION_KEY" in str(exc.value)
    assert "unrecoverable" in str(exc.value)


def test_no_key_refuses_to_read_too():
    box = SecretBox([])
    with pytest.raises(SecretBoxUnconfigured):
        box.decrypt("anything")


@pytest.mark.parametrize("weak", ["", "   ", "short", "x" * 31])
def test_a_short_key_is_refused_rather_than_stretched(weak):
    """Hashing a weak secret into a key-shaped value looks as strong as a
    real key and is not. Refusing is the honest answer."""
    with pytest.raises(SecretBoxUnconfigured):
        SecretBox([weak]).encrypt(SECRET)


# ─── the control: it must actually work ──────────────────────────────────

def test_a_configured_box_round_trips():
    box = SecretBox([KEY_A])
    sealed = box.encrypt(SECRET)
    assert sealed.ciphertext != SECRET
    assert SECRET not in sealed.ciphertext
    assert box.decrypt(sealed.ciphertext) == SECRET


def test_the_ciphertext_does_not_leak_the_plaintext_anywhere():
    box = SecretBox([KEY_A])
    sealed = box.encrypt(SECRET)
    blob = str(sealed.as_row())
    assert SECRET not in blob
    # Nor any run of it long enough to matter.
    assert SECRET[:12] not in blob


def test_a_32_byte_passphrase_is_accepted():
    """Operators paste what they have. 32+ characters is derived from, not
    refused — the refusal is for values too short to be a key at all."""
    box = SecretBox(["a" * 40])
    assert box.decrypt(box.encrypt(SECRET).ciphertext) == SECRET


# ─── 2. rotation has to be verifiable ────────────────────────────────────

def test_each_row_records_which_key_sealed_it():
    a = SecretBox([KEY_A]).encrypt(SECRET)
    b = SecretBox([KEY_B]).encrypt(SECRET)
    assert a.key_id == key_id(KEY_A)
    assert b.key_id == key_id(KEY_B)
    assert a.key_id != b.key_id
    # The id identifies the key without being the key.
    assert KEY_A not in a.key_id and len(a.key_id) == 16


def test_a_row_under_a_retired_key_is_detectable():
    """The property that makes "all rows re-encrypted" checkable. Without
    it a missed row looks identical to a done one until the old key is
    dropped and the credential is gone."""
    old = SecretBox([KEY_B]).encrypt(SECRET)
    rotated_box = SecretBox([KEY_A, KEY_B])          # A primary, B retired
    assert rotated_box.needs_rotation(old.key_id) is True
    fresh = rotated_box.encrypt(SECRET)
    assert rotated_box.needs_rotation(fresh.key_id) is False


def test_a_missing_key_id_counts_as_needing_rotation():
    """Rows written before this column existed. Unknown is not done."""
    assert SecretBox([KEY_A]).needs_rotation(None) is True
    assert SecretBox([KEY_A]).needs_rotation("") is True


def test_rotation_re_encrypts_without_losing_the_value():
    old = SecretBox([KEY_B]).encrypt(SECRET)
    rotated_box = SecretBox([KEY_A, KEY_B])
    new = rotated_box.rotate(old.ciphertext)
    assert new.key_id == key_id(KEY_A)
    assert new.ciphertext != old.ciphertext
    assert rotated_box.decrypt(new.ciphertext) == SECRET
    # And the new ciphertext survives the retired key being dropped.
    assert SecretBox([KEY_A]).decrypt(new.ciphertext) == SECRET


def test_a_retired_key_still_decrypts_until_it_is_dropped():
    """Otherwise a rotation is an outage: rows sealed under the old key must
    keep working while the sweep runs."""
    old = SecretBox([KEY_B]).encrypt(SECRET)
    assert SecretBox([KEY_A, KEY_B]).decrypt(old.ciphertext) == SECRET


def test_dropping_a_key_that_still_seals_rows_is_loud():
    """The failure an unfinished rotation produces. It must name both
    possible causes, because the operator actions differ."""
    old = SecretBox([KEY_B]).encrypt(SECRET)
    with pytest.raises(SecretBoxUndecryptable) as exc:
        SecretBox([KEY_A]).decrypt(old.ciphertext)
    assert "rotated" in str(exc.value)
    assert "re-entered" in str(exc.value)


# ─── 3. storage must be authenticated ────────────────────────────────────

def test_a_tampered_ciphertext_fails_rather_than_decrypting():
    """A connector authenticating with an attacker-chosen value is worse
    than a connector that cannot authenticate at all."""
    box = SecretBox([KEY_A])
    sealed = box.encrypt(SECRET)
    tampered = sealed.ciphertext[:-4] + ("AAAA" if sealed.ciphertext[-4:] != "AAAA" else "BBBB")
    with pytest.raises(SecretBoxUndecryptable):
        box.decrypt(tampered)


def test_a_foreign_ciphertext_fails():
    with pytest.raises(SecretBoxUndecryptable):
        SecretBox([KEY_A]).decrypt(SecretBox([KEY_B]).encrypt(SECRET).ciphertext)


def test_two_seals_of_the_same_value_differ():
    """Equal ciphertexts would let a reader of the table tell which tenants
    share a credential."""
    box = SecretBox([KEY_A])
    assert box.encrypt(SECRET).ciphertext != box.encrypt(SECRET).ciphertext
