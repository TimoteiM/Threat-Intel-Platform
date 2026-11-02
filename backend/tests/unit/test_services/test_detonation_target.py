"""What gets sent to the sandbox when an archive is submitted.

A sandbox handed a zip has to open it and find the payload itself, with
whatever time its automated interactivity has. An analyst watching the
recording of a submitted archive saw it unpacked and then nothing — the run
ended first. The platform has already opened that archive and knows exactly
which file is worth running, so it sends that file instead.

The verdict then belongs to the extracted executable and not to the zip it
arrived in, which is why the substitution is recorded rather than silent.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

from app.services import file_content_service as fcs


def _pe(tail: bytes = b"payload", size: int | None = None) -> bytes:
    head = bytearray(b"MZ" + b"\x00" * 58)
    head += struct.pack("<I", 64)
    head += b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 200
    body = bytes(head) + tail
    if size and size > len(body):
        import secrets

        body += secrets.token_bytes(size - len(body))
    return body


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


# --- the case this exists for ------------------------------------------------

def test_an_archive_with_one_executable_sends_the_executable():
    payload = _pe(b"ScreenConnect stub")
    archive = _zip({"manifest.json": b"[]", "Setup.exe": payload})

    target = fcs.detonation_target(archive, "dropper.zip")

    assert target is not None
    assert target.name == "Setup.exe"
    assert target.data == payload
    assert target.sha256 == hashlib.sha256(payload).hexdigest()
    assert target.source_path == "dropper.zip/Setup.exe"


def test_an_executable_too_big_to_keep_is_still_re_read_for_the_sandbox():
    """Extraction streams a large member through a digest and drops the bytes —
    the read limit bounds what is kept for reading as *text*. A sandbox needs
    the file, so it is read again, once, for the member that will be run."""
    payload = _pe(size=3_000_000)
    archive = _zip({"Setup.exe": payload})

    target = fcs.detonation_target(archive, "dropper.zip")

    assert target is not None
    assert len(target.data) == len(payload)
    assert target.sha256 == hashlib.sha256(payload).hexdigest()


def test_an_encrypted_archive_yields_its_executable_when_the_password_is_known():
    import subprocess
    import tempfile
    import os
    import shutil

    if not shutil.which("7z"):
        import pytest

        pytest.skip("7z is only present where the fixtures are built")

    payload = _pe(b"locked payload")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "Setup.exe")
        with open(exe, "wb") as fh:
            fh.write(payload)
        out = os.path.join(tmp, "locked.zip")
        subprocess.run(["7z", "a", "-tzip", "-pInfected2026", out, exe],
                       capture_output=True, check=True)
        archive = open(out, "rb").read()

    assert fcs.detonation_target(archive, "locked.zip", password="Infected2026") is not None
    # Without it, nothing is substituted: the password is used at upload and
    # discarded, and a sandbox cannot open the archive either.
    assert fcs.detonation_target(archive, "locked.zip") is None


# --- when the answer is not obvious, submit what was submitted ---------------

def test_two_executables_are_left_to_the_sandbox():
    """Choosing between them is a guess, and a guess that runs the decoy
    instead of the payload is worse than letting the sandbox decide."""
    archive = _zip({"a.exe": _pe(b"one"), "b.exe": _pe(b"two")})
    assert fcs.detonation_target(archive, "dropper.zip") is None


def test_an_archive_with_no_executable_is_submitted_as_it_is():
    archive = _zip({"notes.txt": b"hello", "script.js": b"var a = 1;"})
    assert fcs.detonation_target(archive, "docs.zip") is None


def test_a_bare_executable_is_not_an_archive():
    assert fcs.detonation_target(_pe(), "Setup.exe") is None


def test_a_document_is_not_an_archive_for_this_purpose():
    assert fcs.detonation_target(b"just some text", "notes.txt") is None


# --- integrity ---------------------------------------------------------------

def test_nothing_is_run_if_the_re_read_disagrees_with_the_hash(monkeypatch):
    """The hash was taken over the whole member during extraction. If reading
    it again produces different bytes, the two are not the same file and the
    archive is submitted instead."""
    archive = _zip({"Setup.exe": _pe(b"original")})
    monkeypatch.setattr(fcs, "read_member", lambda *a, **k: b"MZ" + b"different")

    # Force the re-read path by dropping the bytes the extraction kept.
    real_extract = fcs.extract

    def _no_bytes(data, filename="submitted", *, password=None):
        result = real_extract(data, filename, password=password)
        for binary in result.binaries:
            binary.data = None
        return result

    monkeypatch.setattr(fcs, "extract", _no_bytes)
    assert fcs.detonation_target(archive, "dropper.zip") is None


def test_a_member_nested_several_archives_deep_is_not_a_target():
    assert fcs.read_member(b"", "a.zip/b/c/d/e/f.exe") is None
    assert fcs.read_member(b"", "no-slash") is None


def test_the_reason_says_what_happened_and_why():
    archive = _zip({"Setup.exe": _pe()})
    target = fcs.detonation_target(archive, "dropper.zip")
    assert "in place of the archive" in target.reason


# --- the collector, which has to say what it did -----------------------------

def test_the_collector_submits_the_payload_and_records_the_swap():
    """The verdict that comes back is about the extracted file. A report that
    does not say so is making a claim about the wrong file."""
    from app.collectors.hybrid_analysis_collector import HybridAnalysisCollector

    payload = _pe(b"inner")
    archive = _zip({"manifest.json": b"[]", "Setup.exe": payload})

    collector = HybridAnalysisCollector(
        domain="deadbeef", investigation_id="inv-1", observable_type="hash",
    )
    swapped = collector._detonation_substitution("dropper.zip", archive)

    assert swapped is not None
    record, name, data = swapped
    assert name == "Setup.exe"
    assert data == payload
    assert record.sha256 == hashlib.sha256(payload).hexdigest()
    assert record.source_path == "dropper.zip/Setup.exe"


def test_the_collector_leaves_an_ambiguous_archive_alone():
    from app.collectors.hybrid_analysis_collector import HybridAnalysisCollector

    collector = HybridAnalysisCollector(
        domain="deadbeef", investigation_id="inv-1", observable_type="hash",
    )
    archive = _zip({"a.exe": _pe(b"one"), "b.exe": _pe(b"two")})
    assert collector._detonation_substitution("dropper.zip", archive) is None


def test_a_broken_archive_never_fails_the_collector(monkeypatch):
    from app.collectors.hybrid_analysis_collector import HybridAnalysisCollector

    monkeypatch.setattr(
        fcs, "detonation_target",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("corrupt")),
    )
    collector = HybridAnalysisCollector(
        domain="deadbeef", investigation_id="inv-1", observable_type="hash",
    )
    assert collector._detonation_substitution("dropper.zip", b"not an archive") is None


def test_the_evidence_model_keeps_the_substitution():
    """`HybridAnalysisEvidence` drops any field it does not declare, which is
    how three password flags went missing from the file content evidence."""
    from app.models.schemas import HybridAnalysisEvidence

    dumped = HybridAnalysisEvidence(
        detonated={
            "name": "Setup.exe", "sha256": "a" * 64,
            "source_path": "dropper.zip/Setup.exe", "reason": "because",
        }
    ).model_dump()

    assert dumped["detonated"]["sha256"] == "a" * 64
    assert dumped["detonated"]["name"] == "Setup.exe"
