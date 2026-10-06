"""The executable inside the archive, which nothing used to look at.

A password-protected archive held a one-line manifest and a 5 MB installer.
The content reader did its job — "1 readable file" — and said of the installer
only that its code is not readable as text. Which is true, and describes the
one member that actually runs.

A compiled file cannot be read, so it is identified by hash and looked up like
any other sample, and what comes back is attached to the same investigation.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

import pytest

from app.services import decision_engine, file_content_service as fcs


def _pe(tail: bytes = b"payload") -> bytes:
    """A file that sniffs as a PE: MZ, e_lfanew, then the PE signature."""
    head = bytearray(b"MZ" + b"\x00" * 58)
    head += struct.pack("<I", 64)
    head += b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 200
    return bytes(head) + tail


def _archive(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


# --- recording ---------------------------------------------------------------

def test_a_packed_executable_is_recorded_with_its_hash():
    payload = _pe(b"ScreenConnect stub")
    data = _archive({"manifest.json": b'[{"included":true}]', "Setup.exe": payload})

    result = fcs.extract(data, "dropper.zip")

    assert len(result.files) == 1, "the manifest is the only readable member"
    assert len(result.binaries) == 1
    binary = result.binaries[0]
    assert binary.path == "dropper.zip/Setup.exe"
    assert binary.kind == "pe"
    # The hash every reputation source takes, over the real bytes.
    assert binary.sha256 == hashlib.sha256(payload).hexdigest()
    assert binary.sha1 == hashlib.sha1(payload).hexdigest()
    assert binary.md5 == hashlib.md5(payload).hexdigest()


def test_the_bytes_ride_on_the_object_and_not_into_the_evidence():
    """A caller may want to store or detonate it; the evidence row is JSON."""
    data = _archive({"Setup.exe": _pe()})
    result = fcs.extract(data, "dropper.zip")

    assert result.binaries[0].data is not None
    assert "data" not in result.as_dict()["binaries"][0]


def test_an_executable_too_large_to_read_is_not_hashed_at_all():
    """Hashing the prefix would produce an identifier that looks real, matches
    nothing, and makes every reputation source answer confidently about a file
    that does not exist. No hash is the honest answer."""
    result = fcs.ExtractionResult()
    fcs._add_binary(_pe(b"x" * 100), "big.zip/huge.exe", result, kind="pe",
                    declared_size=50_000_000)

    assert result.binaries == []
    assert any("could not be hashed" in note for note in result.limitations)


def test_the_limitation_still_says_why_the_code_is_not_shown():
    data = _archive({"Setup.exe": _pe()})
    result = fcs.extract(data, "dropper.zip")
    assert any("not readable as text" in n for n in result.limitations)
    assert any("looked up separately" in n for n in result.limitations)


# --- the lookup --------------------------------------------------------------

class _Meta:
    def __init__(self, status="success"):
        self.status = status


def _patch_vt(monkeypatch, *, found=True, malicious=0, suspicious=0, total=0,
              raises=None, names=None):
    """Stubbed with the collector's *real* field names.

    `last_analysis_stats` is VirusTotal's wire shape, not this collector's —
    reading it here would have left every lookup reporting "unknown" while the
    tests passed happily against the invented shape.
    """
    from app.tasks import analysis_task
    from app.models.schemas import VTEvidence

    assert {"found", "malicious_count", "suspicious_count", "total_vendors", "file_names"} <= set(
        VTEvidence.model_fields
    ), "the stub below must track the collector's evidence model"

    class _Evidence:
        def model_dump(self):
            return {
                "found": found,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_vendors": total,
                "file_names": names or [],
                "vt_creation_date": None,
                "notes": [],
            }

    class _Collector:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            calls.append(kwargs.get("domain"))

        def run(self):
            if raises:
                raise raises
            return _Evidence(), _Meta(), {}

    calls: list[str] = []
    # Patched on the imported module, not by dotted string. The string form
    # resolves `app.collectors` as an attribute of `app`, which only exists
    # once something else has imported that submodule — so these passed alone
    # and failed in the full suite depending on test order.
    import app.collectors.vt_collector as vt_module

    monkeypatch.setattr(vt_module, "VTCollector", _Collector)
    return calls, analysis_task


def test_a_known_bad_executable_comes_back_malicious(monkeypatch):
    calls, task = _patch_vt(monkeypatch, malicious=41, total=61,
                            names=["ScreenConnect.ClientSetup.exe"])
    content = {"binaries": [{"sha256": "a" * 64, "path": "d.zip/Setup.exe"}]}

    task._look_up_embedded_binaries(content, investigation_id="inv-1")

    assert calls == ["a" * 64], "the embedded hash is what gets queried"
    binary = content["binaries"][0]
    assert binary["verdict"] == "malicious"
    assert binary["malicious_count"] == 41
    assert binary["total_engines"] == 61
    assert binary["names"] == ["ScreenConnect.ClientSetup.exe"]


def test_a_file_virustotal_has_never_seen_is_unknown_not_benign(monkeypatch):
    """"Nothing known" and "known to be clean" are different answers, and on a
    sample unpacked from a password-protected archive the difference matters."""
    _patch_vt(monkeypatch, found=False)
    content = {"binaries": [{"sha256": "b" * 64, "path": "d.zip/Setup.exe"}]}

    from app.tasks import analysis_task

    analysis_task._look_up_embedded_binaries(content, investigation_id="inv-1")
    assert content["binaries"][0]["verdict"] == "unknown"


def test_a_failed_lookup_is_recorded_rather_than_raised(monkeypatch):
    _patch_vt(monkeypatch, raises=RuntimeError("rate limited"))
    content = {"binaries": [{"sha256": "c" * 64, "path": "d.zip/Setup.exe"}]}

    from app.tasks import analysis_task

    analysis_task._look_up_embedded_binaries(content, investigation_id="inv-1")
    binary = content["binaries"][0]
    assert binary.get("verdict") is None, "no verdict was reached"
    assert "RuntimeError" in binary["note"]


def test_only_a_bounded_number_of_executables_are_looked_up(monkeypatch):
    """An archive of two hundred DLLs is a real shape, and each lookup draws on
    the same per-minute budget the investigation's own hash is using."""
    calls, task = _patch_vt(monkeypatch, malicious=0, total=60)
    content = {"binaries": [
        {"sha256": f"{i:064x}", "path": f"d.zip/{i}.exe"} for i in range(9)
    ]}

    task._look_up_embedded_binaries(content, investigation_id="inv-1")

    assert len(calls) == task.MAX_EMBEDDED_LOOKUPS
    assert all("Not looked up" in b["note"] for b in content["binaries"][task.MAX_EMBEDDED_LOOKUPS:])


# --- scoring -----------------------------------------------------------------

def test_a_malicious_packed_executable_scores_the_investigation():
    """Previously the archive scored on its own hash, which VirusTotal had
    never seen — so a container holding a known-bad installer came back
    benign-ish. The verdict is about the payload, not the wrapper."""
    signal = decision_engine._file_collector_signal({
        "file_content": {
            "files": [{"path": "d.zip/manifest.json"}],
            "binaries": [{
                "path": "d.zip/ScreenConnect.ClientSetup.exe", "sha256": "a" * 64,
                "verdict": "malicious", "malicious_count": 41, "total_engines": 61,
            }],
        },
    })

    assert signal is not None
    assert signal["classification"] == "malicious"
    assert signal["risk_score"] >= 75
    assert signal["recommended_action"] == "block"
    assert any("already known to be malicious" in e for e in signal["key_evidence"])
    assert any("41/61 engines" in e for e in signal["key_evidence"])


def test_a_suspicious_packed_executable_raises_it_without_blocking():
    signal = decision_engine._file_collector_signal({
        "file_content": {"files": [], "binaries": [
            {"path": "d.zip/x.exe", "sha256": "a" * 64, "verdict": "suspicious"},
        ]},
    })
    assert signal["classification"] == "suspicious"
    assert signal["risk_score"] >= 45


def test_an_unknown_packed_executable_is_named_but_does_not_condemn():
    signal = decision_engine._file_collector_signal({
        "file_content": {"files": [], "binaries": [
            {"path": "d.zip/x.exe", "sha256": "a" * 64, "verdict": "unknown"},
        ]},
    })
    assert signal["classification"] == "benign"
    # Still reported: an analyst should see what was in the archive.
    assert any("x.exe" in e for e in signal["key_evidence"])


def test_a_packed_executable_alone_is_enough_to_have_an_opinion():
    """Before, an archive whose only finding was a packed binary produced no
    signal at all, and the report said nothing ran."""
    assert decision_engine._file_collector_signal({"file_content": {"binaries": [
        {"path": "d.zip/x.exe", "sha256": "a" * 64, "verdict": "unknown"},
    ]}}) is not None
    assert decision_engine._file_collector_signal({}) is None


# --- the registry that silently drops fields ---------------------------------

def test_the_evidence_model_keeps_the_binaries_and_the_password_state():
    """`CollectedEvidence` drops any key its model does not declare. The three
    password flags were already being dropped this way."""
    from app.models.schemas import FileContentEvidence

    dumped = FileContentEvidence(**{
        "files": [], "limitations": [], "entries_seen": 2, "bytes_read": 287,
        "encrypted": True, "readable_files": 1, "password_required": True,
        "password_incorrect": False, "encryption_unsupported": False,
        "binaries": [{"path": "d.zip/x.exe", "sha256": "a" * 64, "verdict": "malicious"}],
    }).model_dump()

    assert dumped["password_required"] is True
    assert dumped["binaries"][0]["verdict"] == "malicious"
