"""
Static attachment analyzer (no execution).

It reads the file now. It used to read only the name and the hash, while
reporting two fields that looked like measurements of content:

    entropy = _pseudo_entropy_from_hash(sha256 or md5)

That is the Shannon entropy of the *hex digits of the digest*. A digest is
uniformly distributed by construction, so the number was a constant with
noise — measured across 500 unrelated files it ranged 0.8913 to 0.9917, and a
file of 10,000 zero bytes differed from one of random bytes by 0.013. It said
nothing about any file, and it said it beside findings that were real.

`suspicious_import_count` was the same shape of claim: it matched words like
"powershell" and "invoice" in the *filename* and added one if VirusTotal had
seen anything. No imports were read.

Both are now computed from bytes when bytes are available, and reported as
`None` when they are not. A field that is absent says "not measured", which is
a true thing to say; a fabricated number does not.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any


MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}


def analyze_attachments_static(
    attachments: list[dict[str, Any]],
    *,
    vt_items_by_sha256: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    vt_items_by_sha256 = vt_items_by_sha256 or {}
    items: list[dict[str, Any]] = []
    for att in attachments:
        if not isinstance(att, dict):
            continue
        filename = str(att.get("filename") or "unnamed_attachment")
        sha256 = str(att.get("sha256") or "").strip().lower()
        md5 = str(att.get("md5") or "").strip().lower()
        ext = os.path.splitext(filename.lower())[1]
        vt_item = vt_items_by_sha256.get(sha256) or {}
        vt_verdict = str(((vt_item.get("vt") or {}).get("verdict") or "unknown")).lower()

        data = _bytes_of(att)

        macro_detected = ext in MACRO_EXTENSIONS
        embedded_objects = ext in ARCHIVE_EXTENSIONS
        entropy = _shannon_entropy(data) if data else None
        apis = _suspicious_apis(data) if data else []
        suspicious_api_count = len(apis)

        risk_score = 0.0
        if macro_detected:
            risk_score += 0.35
        if embedded_objects:
            risk_score += 0.2
        if ext in EXECUTABLE_EXTENSIONS:
            risk_score += 0.3
        risk_score += min(0.25, suspicious_api_count * 0.05)
        # High entropy in something that should be text is worth a little. It is
        # not worth much on its own: a zip is high-entropy because it is
        # compressed, which is what a zip is for.
        if entropy is not None and entropy > 0.90 and ext in EXECUTABLE_EXTENSIONS:
            risk_score += 0.1
        if vt_verdict in {"malicious", "suspicious"}:
            risk_score += 0.3

        items.append(
            {
                "hash": sha256 or md5 or None,
                "filename": filename,
                "file_type": ext or "unknown",
                "macro_detected": macro_detected,
                "embedded_objects": embedded_objects,
                # None, not 0.0, when the bytes were never available. Zero is a
                # measurement; absence is the honest answer.
                "entropy": round(entropy, 4) if entropy is not None else None,
                "entropy_measured": entropy is not None,
                "suspicious_api_count": suspicious_api_count,
                "suspicious_apis": apis[:12],
                "content_examined": bool(data),
                "static_risk_score": round(max(0.0, min(1.0, risk_score)), 4),
                "risk_level": _risk_label(risk_score),
            }
        )

    return {
        "checked": bool(items),
        "items": items,
        "summary": _summarize(items),
    }


def _bytes_of(att: dict[str, Any]) -> bytes:
    """The attachment's content, however this caller carries it."""
    raw = att.get("data")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    encoded = att.get("content_b64")
    if encoded:
        import base64

        try:
            return base64.b64decode(encoded)
        except Exception:  # noqa: BLE001 — a malformed attachment is expected
            return b""
    return b""


# What a dropper reaches for. Matched against the file's own bytes, so a hit
# means the string is in the file — not that the filename resembled it.
_SUSPICIOUS_APIS: tuple[bytes, ...] = (
    b"wscript.shell", b"activexobject", b"shell.application",
    b"powershell", b"-encodedcommand", b"-enc ", b"-nop", b"-windowstyle hidden",
    b"frombase64string", b"invoke-expression", b"iex ", b"downloadstring",
    b"downloadfile", b"invoke-webrequest", b"start-process", b"certutil",
    b"regsvr32", b"rundll32", b"mshta", b"bitsadmin", b"schtasks",
    b"createobject", b"eval(", b"unescape(", b"atob(", b"document.write",
    b"auto_open", b"autoopen", b"document_open", b"workbook_open",
    b"virtualalloc", b"createremotethread", b"writeprocessmemory",
)


def _suspicious_apis(data: bytes) -> list[str]:
    """Which of them appear in this file. Read from the bytes, not the name.

    Case-folded over a bounded prefix: a dropper declares what it needs early,
    and scanning a 50 MB installer end to end to re-learn that it calls
    CreateObject is not worth the read.
    """
    haystack = bytes(data[:2_000_000]).lower()
    return [marker.decode().strip() for marker in _SUSPICIOUS_APIS if marker in haystack]


def _shannon_entropy(data: bytes) -> float:
    """Entropy of the file's bytes, normalised to 0..1 over 8 bits.

    Compressed and packed content sits near 1.0, English prose and source
    nearer 0.5-0.7. Unlike its predecessor this actually distinguishes them.
    """
    sample = bytes(data[:1_000_000])
    if not sample:
        return 0.0
    counts: dict[int, int] = {}
    for byte in sample:
        counts[byte] = counts.get(byte, 0) + 1
    n = len(sample)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return max(0.0, min(1.0, entropy / 8.0))


def _risk_label(score: float) -> str:
    if score > 0.65:
        return "high"
    if score >= 0.30:
        return "medium"
    return "low"


def _summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        return {"high": 0, "medium": 0, "low": 0}
    return {
        "high": sum(1 for i in items if i.get("risk_level") == "high"),
        "medium": sum(1 for i in items if i.get("risk_level") == "medium"),
        "low": sum(1 for i in items if i.get("risk_level") == "low"),
    }

