"""
Look inside an email attachment instead of trusting its name.

The existing static check decides everything from the extension:

    macro_detected = ext in {".docm", ".xlsm", ".doc", ".xls", ...}

That misses the two things attackers actually do. A modern `.docx` can carry a
`vbaProject.bin` — the extension says macro-free, the archive says otherwise.
And a file named `invoice.pdf` can be a PE executable, because nothing was
reading the first two bytes.

Everything here is local: magic-byte typing, a walk of the OOXML container, and
a scan of PDF structure. No hashing service, no sandbox, no quota. The output
also carries `worth_detonating`, so the sandbox — which does cost — is only
spent on files this pass found a reason to distrust.
"""

from __future__ import annotations

import base64
import io
import re
import zipfile
from typing import Any

# Magic bytes, in the order they must be tested. Longer signatures first so a
# prefix does not shadow a more specific match.
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x50\x4b\x03\x04", "zip", "ZIP container (also .docx/.xlsx/.pptx/.jar/.apk)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Legacy OLE compound file (.doc/.xls/.ppt/.msg)"),
    (b"%PDF-", "pdf", "PDF document"),
    (b"MZ", "pe", "Windows executable (PE)"),
    (b"\x7fELF", "elf", "Linux executable (ELF)"),
    (b"\xca\xfe\xba\xbe", "macho", "macOS executable (Mach-O)"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\x1f\x8b", "gzip", "gzip archive"),
    (b"#!", "script", "Script with a shebang"),
)

_EXTENSION_EXPECTATION = {
    ".pdf": {"pdf"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"},
    ".docm": {"zip"}, ".xlsm": {"zip"}, ".pptm": {"zip"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"},
    ".zip": {"zip"}, ".jar": {"zip"}, ".apk": {"zip"},
    ".rar": {"rar"}, ".7z": {"7z"}, ".gz": {"gzip"},
    ".exe": {"pe"}, ".dll": {"pe"}, ".scr": {"pe"},
}

# Extensions that execute if opened, whatever they claim to be.
_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".hta",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".bat", ".cmd", ".ps1",
    ".lnk", ".reg", ".jar", ".iso", ".img", ".vhd",
}

_URL_IN_PDF = re.compile(rb"/URI\s*\(\s*([^)]{4,400}?)\s*\)")
_PDF_ACTIONS = (
    (b"/OpenAction", "opens an action automatically when the document is opened"),
    (b"/AA", "carries an additional-actions trigger"),
    (b"/JavaScript", "embeds JavaScript"),
    (b"/JS", "embeds JavaScript"),
    (b"/Launch", "can launch an external program"),
    (b"/EmbeddedFile", "contains an embedded file"),
)


def _sniff(data: bytes) -> tuple[str, str]:
    for signature, kind, label in _SIGNATURES:
        if data.startswith(signature):
            return kind, label
    return "unknown", "Unrecognised file type"


def _extension(filename: str) -> str:
    name = str(filename or "").strip().lower()
    return name[name.rfind("."):] if "." in name else ""


def inspect_attachment(attachment: dict[str, Any]) -> dict[str, Any]:
    """
    What this attachment actually is, and what it would do if opened.

    Never raises: a malformed or truncated attachment is exactly what a hostile
    one looks like, so a parse failure is reported rather than thrown.
    """
    filename = str(attachment.get("filename") or "unnamed_attachment")
    extension = _extension(filename)
    encoded = attachment.get("content_b64")

    result: dict[str, Any] = {
        "filename": filename,
        "extension": extension or None,
        "inspected": False,
        "detected_type": None,
        "findings": [],
        "extracted_urls": [],
        "worth_detonating": False,
        "reason_not_inspected": None,
    }

    if not encoded:
        result["reason_not_inspected"] = (
            "Attachment content was not retained (absent, or larger than the inspection limit)."
        )
        # Without bytes the only thing left is the name, which is the weakest
        # possible signal — but a double extension is still worth saying.
        if _double_extension(filename):
            result["findings"].append({
                "id": "double_extension",
                "severity": "high",
                "detail": f"{filename} uses a double extension, a common way to disguise an executable.",
            })
        return result

    try:
        data = base64.b64decode(encoded)
    except Exception:
        result["reason_not_inspected"] = "Attachment content could not be decoded."
        return result

    result["inspected"] = True
    kind, label = _sniff(data)
    result["detected_type"] = {"kind": kind, "description": label}
    findings: list[dict[str, str]] = []

    if _double_extension(filename):
        findings.append({
            "id": "double_extension",
            "severity": "high",
            "detail": f"{filename} uses a double extension, a common way to disguise an executable.",
        })

    # ── The file is not what it is named ─────────────────────────────────────
    expected = _EXTENSION_EXPECTATION.get(extension)
    if expected and kind != "unknown" and kind not in expected:
        findings.append({
            "id": "type_mismatch",
            "severity": "high",
            "detail": (
                f"{filename} is named as {extension} but its contents are {label.lower()}. "
                "The name does not describe the file."
            ),
        })

    if kind in {"pe", "elf", "macho"}:
        findings.append({
            "id": "executable_attachment",
            "severity": "high",
            "detail": f"{filename} is {label.lower()} — an executable delivered by email.",
        })
    elif extension in _EXECUTABLE_EXTENSIONS:
        findings.append({
            "id": "executable_extension",
            "severity": "high",
            "detail": f"{filename} runs when opened ({extension}).",
        })

    if kind == "zip":
        findings.extend(_inspect_zip(data, filename))
    elif kind == "ole":
        findings.extend(_inspect_ole(data, filename))
    elif kind == "pdf":
        pdf_findings, urls = _inspect_pdf(data, filename)
        findings.extend(pdf_findings)
        result["extracted_urls"] = urls

    result["findings"] = findings
    # The sandbox costs credits, so it is reserved for files this pass already
    # found a reason to distrust.
    result["worth_detonating"] = any(f["severity"] == "high" for f in findings)
    return result


def _double_extension(filename: str) -> bool:
    parts = str(filename or "").lower().split(".")
    if len(parts) < 3:
        return False
    return f".{parts[-1]}" in _EXECUTABLE_EXTENSIONS and f".{parts[-2]}" in {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".htm", ".html",
    }


def _inspect_zip(data: bytes, filename: str) -> list[dict[str, str]]:
    """
    Walk the OOXML container rather than trusting the extension.

    This is what catches a `.docx` carrying `vbaProject.bin`: the extension says
    the document is macro-free and the archive says it is not.
    """
    findings: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
    except Exception:
        findings.append({
            "id": "unreadable_archive",
            "severity": "medium",
            "detail": f"{filename} looks like an archive but could not be opened — it may be encrypted or malformed.",
        })
        return findings

    lowered = [n.lower() for n in names]

    if any("vbaproject.bin" in n for n in lowered):
        findings.append({
            "id": "embedded_macro",
            "severity": "high",
            "detail": (
                f"{filename} contains vbaProject.bin — an embedded VBA macro. "
                "The file extension does not have to indicate this."
            ),
        })
    if any(n.endswith(".bin") and "oleobject" in n for n in lowered):
        findings.append({
            "id": "embedded_ole_object",
            "severity": "high",
            "detail": f"{filename} embeds an OLE object, which can execute on open.",
        })
    if any("externallink" in n for n in lowered):
        findings.append({
            "id": "external_link",
            "severity": "medium",
            "detail": f"{filename} references external content, which can be used to fetch a payload or track opening.",
        })

    risky_inside = [
        name for name in names
        if _extension(name) in _EXECUTABLE_EXTENSIONS
    ]
    if risky_inside:
        findings.append({
            "id": "executable_in_archive",
            "severity": "high",
            "detail": f"{filename} contains executable content: {', '.join(risky_inside[:4])}.",
        })

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if any(info.flag_bits & 0x1 for info in archive.infolist()):
                findings.append({
                    "id": "encrypted_archive",
                    "severity": "high",
                    "detail": (
                        f"{filename} is password-protected. Encrypted archives defeat scanning, and the "
                        "password is usually supplied in the email body for exactly that reason."
                    ),
                })
    except Exception:
        pass

    return findings


def _inspect_ole(data: bytes, filename: str) -> list[dict[str, str]]:
    """Legacy Office. Macro streams are named in the raw compound file."""
    findings: list[dict[str, str]] = []
    lowered = data.lower()
    if b"vba" in lowered or b"macros" in lowered:
        findings.append({
            "id": "embedded_macro",
            "severity": "high",
            "detail": f"{filename} contains VBA macro streams.",
        })
    if b"equation.3" in lowered or b"equation native" in lowered:
        findings.append({
            "id": "equation_editor_object",
            "severity": "high",
            "detail": (
                f"{filename} embeds an Equation Editor object — the component behind a long-exploited "
                "Office vulnerability class."
            ),
        })
    return findings


def _inspect_pdf(data: bytes, filename: str) -> tuple[list[dict[str, str]], list[str]]:
    """
    PDF structure and the links inside it.

    A phishing link inside an attached PDF was previously invisible: the URL
    extractor reads the email body, and the PDF is an opaque blob to it.
    """
    findings: list[dict[str, str]] = []
    for marker, description in _PDF_ACTIONS:
        if marker in data:
            findings.append({
                "id": f"pdf_{marker.decode('ascii', 'ignore').strip('/').lower()}",
                "severity": "high" if marker in (b"/Launch", b"/JavaScript", b"/JS") else "medium",
                "detail": f"{filename} {description}.",
            })

    urls: list[str] = []
    for match in _URL_IN_PDF.finditer(data):
        try:
            url = match.group(1).decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if url.lower().startswith(("http://", "https://")) and url not in urls:
            urls.append(url)
        if len(urls) >= 25:
            break

    if urls:
        findings.append({
            "id": "pdf_contains_links",
            "severity": "medium",
            "detail": f"{filename} contains {len(urls)} link(s); these are not visible to a body-text URL scan.",
        })
    return findings, urls


def inspect_attachments(attachments: list[dict[str, Any]]) -> dict[str, Any]:
    """Inspect each attachment and summarise what the set as a whole shows."""
    items = [inspect_attachment(a) for a in attachments if isinstance(a, dict)]
    all_findings = [f for item in items for f in item["findings"]]
    urls = [u for item in items for u in item["extracted_urls"]]

    if any(f["severity"] == "high" for f in all_findings):
        risk = "high"
    elif all_findings:
        risk = "medium"
    else:
        risk = "none"

    return {
        "checked": True,
        "risk": risk,
        "items": items,
        "urls_found_in_attachments": urls,
        "detonation_candidates": [i["filename"] for i in items if i["worth_detonating"]],
    }
