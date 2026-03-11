"""
Static attachment analyzer (no execution).
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

        macro_detected = ext in MACRO_EXTENSIONS
        embedded_objects = ext in ARCHIVE_EXTENSIONS
        suspicious_import_count = _estimate_suspicious_import_count(filename=filename, vt_item=vt_item)
        entropy = _pseudo_entropy_from_hash(sha256 or md5)

        risk_score = 0.0
        if macro_detected:
            risk_score += 0.35
        if embedded_objects:
            risk_score += 0.2
        if ext in EXECUTABLE_EXTENSIONS:
            risk_score += 0.3
        risk_score += min(0.25, suspicious_import_count * 0.05)
        if vt_verdict in {"malicious", "suspicious"}:
            risk_score += 0.3

        items.append(
            {
                "hash": sha256 or md5 or None,
                "filename": filename,
                "file_type": ext or "unknown",
                "macro_detected": macro_detected,
                "embedded_objects": embedded_objects,
                "entropy": round(entropy, 4),
                "suspicious_import_count": suspicious_import_count,
                "static_risk_score": round(max(0.0, min(1.0, risk_score)), 4),
                "risk_level": _risk_label(risk_score),
            }
        )

    return {
        "checked": bool(items),
        "items": items,
        "summary": _summarize(items),
    }


def _estimate_suspicious_import_count(*, filename: str, vt_item: dict[str, Any]) -> int:
    base = 0
    lowered = filename.lower()
    suspicious_markers = ("powershell", "cmd", "wscript", "regsvr", "rundll32", "macro", "invoice")
    for marker in suspicious_markers:
        if marker in lowered:
            base += 1
    vt = vt_item.get("vt") or {}
    malicious = int(vt.get("malicious_count") or 0)
    suspicious = int(vt.get("suspicious_count") or 0)
    return min(10, base + (1 if malicious > 0 else 0) + (1 if suspicious > 0 else 0))


def _pseudo_entropy_from_hash(hash_hex: str) -> float:
    h = re.sub(r"[^0-9a-f]", "", (hash_hex or "").lower())
    if not h:
        return 0.0
    counts: dict[str, int] = {}
    for ch in h:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(h)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    # normalize by hex alphabet entropy ceiling (4 bits)
    return max(0.0, min(1.0, entropy / 4.0))


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

