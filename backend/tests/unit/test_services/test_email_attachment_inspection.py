"""
Judging an attachment by what it is, not what it is named.

The previous static check read the extension and stopped:
`macro_detected = ext in {".docm", ".xlsm", ...}`. That misses the two things
attackers actually do — put a macro in a `.docx`, and name an executable
`invoice.pdf`.
"""

import base64
import io
import os
import zipfile

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services.email_attachment_inspection import inspect_attachment, inspect_attachments


def _att(filename: str, data: bytes) -> dict:
    return {"filename": filename, "content_b64": base64.b64encode(data).decode(), "sha256": "x"}


def _ooxml(*names: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("word/document.xml", "<xml/>")
        for name in names:
            archive.writestr(name, b"payload")
    return buf.getvalue()


def _ids(result) -> set[str]:
    return {finding["id"] for finding in result["findings"]}


def test_a_macro_inside_a_docx_is_found_despite_the_extension():
    """`.docx` is the macro-free extension. The archive is what tells the truth."""
    result = inspect_attachment(_att("Quarterly-Report.docx", _ooxml("word/vbaProject.bin")))
    assert "embedded_macro" in _ids(result)
    assert result["worth_detonating"] is True


def test_an_executable_named_as_a_pdf_is_identified_by_its_magic_bytes():
    result = inspect_attachment(_att("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 128))
    assert result["detected_type"]["kind"] == "pe"
    assert {"type_mismatch", "executable_attachment"} <= _ids(result)


def test_urls_inside_a_pdf_are_recovered():
    """A link in an attachment is invisible to a body-text URL scan."""
    pdf = (
        b"%PDF-1.7\n/Annots[<</A<</URI(https://phish.example/verify)/S/URI>>>>]\n%%EOF"
    )
    result = inspect_attachment(_att("statement.pdf", pdf))
    assert result["extracted_urls"] == ["https://phish.example/verify"]


def test_pdf_javascript_and_auto_open_are_reported():
    pdf = b"%PDF-1.7\n/OpenAction<</S/JavaScript/JS(app.alert\\(1\\))>>\n%%EOF"
    result = inspect_attachment(_att("doc.pdf", pdf))
    assert "pdf_javascript" in _ids(result)


def test_a_double_extension_is_reported():
    result = inspect_attachment(_att("photo.jpg.exe", b"MZ" + b"\x00" * 32))
    assert "double_extension" in _ids(result)


def test_an_executable_inside_an_archive_is_reported():
    result = inspect_attachment(_att("docs.zip", _ooxml("setup.exe")))
    assert "executable_in_archive" in _ids(result)


def test_an_ordinary_document_produces_nothing():
    """Quiet on real attachments, or the signal is worthless."""
    result = inspect_attachment(_att("notes.docx", _ooxml()))
    assert result["findings"] == []
    assert result["worth_detonating"] is False


def test_an_attachment_without_retained_content_says_so():
    result = inspect_attachment({"filename": "big.iso", "sha256": "x"})
    assert result["inspected"] is False
    assert result["reason_not_inspected"]


def test_the_summary_lists_only_files_worth_a_sandbox_credit():
    result = inspect_attachments([
        _att("clean.docx", _ooxml()),
        _att("macro.docx", _ooxml("word/vbaProject.bin")),
    ])
    assert result["detonation_candidates"] == ["macro.docx"]
    assert result["risk"] == "high"


# ── The sandbox budget ────────────────────────────────────────────────────────


def _gate(vt_found: bool, attachments: list[dict], run_anyrun: bool = True):
    """Run the attachment check with every external call stubbed out."""
    from unittest.mock import patch
    from app.services import email_indicator_checks_service as svc

    inspection = {"detonation_candidates": ["macro.docx", "second.docx"]}
    with patch.object(svc, "_vt_lookup", return_value={"found": vt_found}), \
         patch.object(svc, "_anyrun_hash_ti_lookup", return_value={"checked": True}), \
         patch.object(svc, "_detonate_attachment", return_value={"submitted": True, "reason": "detonated"}) as det:
        result = svc._check_attachments(
            attachments, max_hashes=5, run_anyrun=run_anyrun, inspection=inspection
        )
    return det.call_count, result


def test_a_file_virustotal_already_knows_is_not_detonated():
    """A known hash needs no sandbox credit."""
    calls, _ = _gate(True, [_att("macro.docx", _ooxml("word/vbaProject.bin"))])
    assert calls == 0


def test_a_file_local_inspection_liked_is_not_detonated():
    """Unknown to reputation is not on its own a reason to spend a credit."""
    calls, _ = _gate(False, [_att("notes.txt", b"hello")])
    assert calls == 0


def test_an_unknown_and_suspicious_file_is_detonated():
    calls, _ = _gate(False, [_att("macro.docx", _ooxml("word/vbaProject.bin"))])
    assert calls == 1


def test_at_most_one_attachment_per_email_is_detonated():
    """AnyRun credits are finite; one email must not be able to drain them."""
    calls, result = _gate(False, [
        _att("macro.docx", _ooxml("word/vbaProject.bin")),
        _att("second.docx", _ooxml("word/vbaProject.bin")),
    ])
    assert calls == 1
    assert "budget" in result["items"][1]["sandbox"]["reason"].lower()


def test_nothing_is_submitted_when_anyrun_is_disabled():
    calls, _ = _gate(False, [_att("macro.docx", _ooxml("word/vbaProject.bin"))], run_anyrun=False)
    assert calls == 0
