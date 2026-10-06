"""A password-protected archive: asked for, checked, and read.

Submitting a locked archive used to be accepted in full and then reported as
holding nothing. The three states these tests keep apart are the ones an
analyst acts on differently:

    password_required      — retype nothing, go and find the password
    password_incorrect     — retype the password
    encryption_unsupported — stop retyping, the format cannot be opened here

The fixtures are real encrypted archives, built with 7z and embedded as
base64, because every interesting behaviour here lives in a format detail —
the general-purpose bit flag, WinZip AES being compression method 99,
libarchive declining 7z content encryption. A hand-rolled stub would assert
nothing about any of them. The payload inside is a two-line script that
launches calc, not a sample.
"""

from __future__ import annotations

import base64
import shutil

import pytest

from app.services import file_content_service as fcs

PASSWORD = "Infected2026"

# `7z a -tzip -pInfected2026 -mem=ZipCrypto` — the classic, which Python's own
# zipfile can decrypt in process.
ZIPCRYPTO = base64.b64decode(
    "UEsDBBQAAQAAADNMRl1IyUmnTgAAAEIAAAAKAAAAcGF5bG9hZC5qc79M/N1325ZFLfLel4M7jPvdImw+HjSUvyeJb0DEFgot3fnc"
    "e0eq3Vsj+PkbDQYd3DdGPgh9z8PceHYP16fvCfJhM2W9WZTuXLwxdfAnLVBLAQI/AxQAAQAAADNMRl1IyUmnTgAAAEIAAAAKACQA"
    "AAAAAAAAIIC0gQAAAABwYXlsb2FkLmpzCgAgAAAAAAABABgA9vr9wnVV3QEAAAAAAAAAAAAAAAAAAAAAUEsFBgAAAAABAAEAXAAA"
    "AHYAAAAAAA=="
)

# `-mem=AES256` — the flag reads the same, but the stdlib cannot decrypt it and
# raises NotImplementedError, which is a *subclass of RuntimeError* and was
# therefore swallowed by the "bad password" arm before it could be handled.
AES = base64.b64decode(
    "UEsDBDMAAQBjADNMRl0AAAAAXgAAAEIAAAAKAAsAcGF5bG9hZC5qcwGZBwACAEFFAwAAK6wGIRLQcrP+c11GKCmki6MUDXXOwAAb"
    "IZ/l0wO8/1AcyVy94MYNsU8y1Y4mym+SJL52oI4pcHOG9mpK5vdDWGubN594YBzx2FbhkKz+qJUzNq25RxJzreQv4xyQJ1BLAQI/"
    "AzMAAQBjADNMRl0AAAAAXgAAAEIAAAAKAC8AAAAAAAAAIIC0gQAAAABwYXlsb2FkLmpzCgAgAAAAAAABABgA9vr9wnVV3QEAAAAA"
    "AAAAAAAAAAAAAAAAAZkHAAIAQUUDAABQSwUGAAAAAAEAAQBnAAAAkQAAAAAA"
)

ENCRYPTED_7Z = base64.b64decode(
    "N3q8ryccAARXiZfwUAAAAAAAAAByAAAAAAAAAM0mQ9SoY8H+8fP/JBGm0ahRx0fhqdnZMKA+eDkRRO8NRSGCJy4liyDRYuAMtiGB"
    "i5meWMPhQrmC4188rmEQrIfRSLNQlsU3K6W2J5mF5c54u71hZQEEBgABCVAABwsBAAIkBvEHARJTDwXGtPrBEmaYgq/OVEvUXgAh"
    "IQEAAQAMRkIACAoBSMlJpwAABQEZAQARFwBwAGEAeQBsAG8AYQBkAC4AagBzAAAAGQQAAAAAFAoBAPb6/cJ1Vd0BFQYBACCAtIEA"
    "AA=="
)

needs_bsdtar = pytest.mark.skipif(
    shutil.which("bsdtar") is None, reason="libarchive is only installed in the app image"
)


def _read(result) -> str:
    return "\n".join(f.text or "" for f in result.files)


# --- the probe, which decides whether to ask at all --------------------------

def test_probe_reads_the_lock_from_the_header_without_a_password():
    for data, reason in ((ZIPCRYPTO, "ZipCrypto"), (AES, "AES")):
        lock = fcs.probe(data, "sample.zip")
        assert lock.encrypted is True
        assert lock.supported is True
        assert lock.reason == reason
        # The names are in the clear even when the contents are not, which is
        # what lets the prompt say what is inside before anyone has the key.
        assert lock.entries == ["payload.js"]


def test_probe_does_not_call_an_unlocked_archive_encrypted():
    import io, zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "nothing to see")
    lock = fcs.probe(buf.getvalue(), "plain.zip")
    assert lock.encrypted is False
    assert lock.entries == ["readme.txt"]


# --- zipcrypto, read in process ---------------------------------------------

def test_a_locked_zip_without_a_password_asks_rather_than_reporting_nothing():
    result = fcs.extract(ZIPCRYPTO, "sample.zip")
    assert result.encrypted is True
    assert result.password_required is True
    assert result.password_incorrect is False
    assert result.files == []
    assert any("password" in note.lower() for note in result.limitations)


def test_the_wrong_password_is_not_the_same_answer_as_no_password():
    result = fcs.extract(ZIPCRYPTO, "sample.zip", password="not-it")
    assert result.password_incorrect is True
    assert result.password_required is False
    assert any("case-sensitive" in note for note in result.limitations)


def test_the_right_password_yields_the_content():
    result = fcs.extract(ZIPCRYPTO, "sample.zip", password=PASSWORD)
    assert result.password_incorrect is False
    assert result.password_required is False
    assert len(result.files) == 1
    assert "WScript.CreateObject" in _read(result)


def test_the_password_never_appears_in_what_is_stored_or_sent():
    result = fcs.extract(ZIPCRYPTO, "sample.zip", password=PASSWORD)
    assert PASSWORD not in str(result.as_dict())
    assert "password" not in result.as_dict() or isinstance(
        result.as_dict().get("password_required"), bool
    )
    assert "password" not in {k for k in result.as_dict() if k == "password"}


# --- winzip aes, which needs libarchive -------------------------------------

@needs_bsdtar
def test_an_aes_zip_is_read_rather_than_written_off():
    """NotImplementedError subclasses RuntimeError, so the "bad password" arm
    caught it first and the archive was reported unreadable even with the
    right password."""
    result = fcs.extract(AES, "sample.zip", password=PASSWORD)
    assert len(result.files) == 1
    assert "WScript.CreateObject" in _read(result)


@needs_bsdtar
def test_an_aes_zip_with_the_wrong_password_says_so():
    result = fcs.extract(AES, "sample.zip", password="not-it")
    assert result.password_incorrect is True
    assert result.files == []


def test_an_aes_zip_without_a_password_asks_for_one():
    result = fcs.extract(AES, "sample.zip")
    assert result.password_required is True
    assert result.files == []


# --- 7z, which cannot be decrypted here at all ------------------------------

@needs_bsdtar
def test_an_encrypted_7z_says_a_password_will_not_help():
    """libarchive lists the entry and refuses the contents: "The file content
    is encrypted, but currently not supported". Reporting that as a wrong
    password sends an analyst round a loop that cannot terminate."""
    for password in (None, "not-it", PASSWORD):
        result = fcs.extract(ENCRYPTED_7Z, "sample.7z", password=password)
        assert result.encryption_unsupported is True, password
        assert result.password_incorrect is False, password
        assert result.files == []


@needs_bsdtar
def test_a_locked_archive_does_not_sit_at_an_interactive_prompt():
    """Handed an encrypted archive and no passphrase, bsdtar prompts — and with
    no terminal it re-prompts in a loop, producing 332 KB of "Enter
    passphrase:" before the timeout killed it. Every locked archive cost a
    full timeout. This asserts the cost is now nothing."""
    import time

    started = time.monotonic()
    fcs.extract(ENCRYPTED_7Z, "sample.7z")
    elapsed = time.monotonic() - started
    assert elapsed < fcs.EXTERNAL_TIMEOUT_SECONDS, "the extractor waited on a prompt"
    assert elapsed < 5


# --- what the upload endpoint does with all that -----------------------------
#
# 409, not 400: the request is well formed and the file is acceptable. What is
# missing is a key for the archive, and the client retries the same submission
# with it. A 400 would read as "this file is no good" and the analyst would go
# looking for a different one.


def _submit(data: bytes, name: str, password: str = ""):
    from app.api import investigations as api

    return api._read_submitted_content(data, name, password)


def test_a_plain_file_is_left_for_the_analysis_task():
    """A bare script has no lock to check and nothing to say about one, so the
    request does not do work the task is already going to do."""
    assert _submit(b"var a = 1;\nWScript.Echo(a);\n", "dropper.js") is None


def test_an_unlocked_archive_is_still_read_in_the_request():
    """Archives are read here even when the probe found no lock, because the
    probe cannot always see one — a 7z lists its entries happily and only
    refuses when you ask for the bytes. Accepting that file and reporting
    "nothing found" later is the failure this is here to prevent. The result is
    stored, so the task does not extract a second time."""
    import io, zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.js", "var a = 1;")
    stored = _submit(buf.getvalue(), "plain.zip")
    assert stored is not None
    assert stored["readable_files"] == 1
    assert stored["password_required"] is False


def test_a_locked_upload_is_refused_with_what_is_inside_it():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _submit(ZIPCRYPTO, "sample.zip")
    assert caught.value.status_code == 409
    # Names the contents, so an analyst knows the password is worth finding.
    assert "payload.js" in caught.value.detail
    assert "ZipCrypto" in caught.value.detail


def test_a_wrong_password_is_refused_as_a_wrong_password():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _submit(ZIPCRYPTO, "sample.zip", "not-it")
    assert caught.value.status_code == 409
    assert "case-sensitive" in caught.value.detail


def test_the_right_password_returns_the_contents_to_store():
    stored = _submit(ZIPCRYPTO, "sample.zip", PASSWORD)
    assert stored is not None
    assert stored["readable_files"] == 1
    assert "WScript" in str(stored["files"])
    # The key opened it and went no further. What is persisted is the content.
    assert PASSWORD not in str(stored)


@needs_bsdtar
def test_an_undecryptable_archive_is_refused_without_asking_for_a_password():
    """Asking for a password that cannot work invites an analyst to type it
    repeatedly. The refusal says so and points at the sandbox instead."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        _submit(ENCRYPTED_7Z, "sample.7z")
    assert caught.value.status_code == 409
    assert "will not help" in caught.value.detail
    assert "sandbox" in caught.value.detail


def test_the_upload_endpoint_accepts_and_forwards_an_archive_password():
    import inspect

    from app.api import investigations as api

    source = inspect.getsource(api.upload_file_investigation)
    assert "archive_password: str = Form(default=\"\")" in source
    assert "_read_submitted_content(file_bytes, filename, archive_password)" in source
    # Stored on the artifact, because the password is not going to the worker.
    assert "_attach_extraction" in source


def test_the_analysis_task_prefers_what_the_upload_already_read():
    """Re-extracting in the worker would report "password-protected, nothing
    read" for a file the analyst had already unlocked."""
    import inspect

    from app.tasks import analysis_task

    source = inspect.getsource(analysis_task._build_file_content_analysis)
    assert "_stored_extraction(investigation_id)" in source
    assert source.index("_stored_extraction") < source.index("_uploaded_sample")
