"""
Lightweight email indicator checks.

Policy:
- URLs: VirusTotal only (+ optional screenshot/final URL capture)
- IPs: VirusTotal + AbuseIPDB
- Attachments: hash extraction + VirusTotal hash lookup
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import requests

from app.collectors.vt_collector import VTCollector
from app.collectors.visual_comparison import capture_screenshot
from app.config import get_settings

logger = logging.getLogger(__name__)


def run_email_indicator_checks(
    extracted: dict[str, Any],
    *,
    include_url_screenshots: bool = True,
    max_urls: int = 5,
    max_attachment_hashes: int = 5,
) -> dict[str, Any]:
    """Run deterministic checks for extracted email indicators."""
    sender_ip = extracted.get("sender_ip")
    urls = [u for u in (extracted.get("urls") or []) if isinstance(u, str) and u][: max(0, max_urls)]
    attachments = [a for a in (extracted.get("attachments") or []) if isinstance(a, dict)]

    checks = {
        "sender_ip": _check_ip(sender_ip) if sender_ip else {"present": False, "message": "Not present in the provided evidence."},
        "urls": [_check_url(url, include_screenshot=include_url_screenshots) for url in urls],
        "attachments": _check_attachments(attachments, max_hashes=max_attachment_hashes),
    }
    return checks


def _check_url(url: str, *, include_screenshot: bool) -> dict[str, Any]:
    vt = _vt_lookup(url, "url")
    screenshot: dict[str, Any] = {
        "captured": False,
        "final_url": None,
        "image_base64": None,
        "error": "Not requested",
    }

    if include_screenshot:
        try:
            png_bytes, final_url = capture_screenshot(url, timeout=20)
            screenshot = {
                "captured": True,
                "final_url": final_url,
                "image_base64": base64.b64encode(png_bytes).decode("ascii"),
                "error": None,
            }
        except Exception as exc:
            screenshot = {
                "captured": False,
                "final_url": None,
                "image_base64": None,
                "error": str(exc),
            }

    return {
        "url": url,
        "vt": vt,
        "screenshot": screenshot,
    }


def _check_ip(ip: str) -> dict[str, Any]:
    return {
        "present": True,
        "ip": ip,
        "vt": _vt_lookup(ip, "ip"),
        "abuseipdb": _abuseipdb_lookup(ip),
    }


def _check_attachments(attachments: list[dict[str, Any]], *, max_hashes: int) -> dict[str, Any]:
    if not attachments:
        return {
            "present": False,
            "items": [],
            "message": "Not present in the provided evidence.",
        }

    items: list[dict[str, Any]] = []
    for att in attachments[: max(0, max_hashes)]:
        sha256 = str(att.get("sha256") or "").strip()
        items.append(
            {
                "filename": att.get("filename"),
                "sha256": sha256 or None,
                "md5": att.get("md5"),
                "size_bytes": att.get("size_bytes"),
                "vt": _vt_lookup(sha256, "hash") if sha256 else {"found": False, "error": "Missing SHA256 hash"},
            }
        )
    return {"present": True, "items": items}


def _vt_lookup(value: str, observable_type: str) -> dict[str, Any]:
    if not value:
        return {
            "found": False,
            "verdict": "unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 0,
            "error": "Empty indicator",
        }
    try:
        collector = VTCollector(
            domain=value,
            investigation_id="email-indicator-check",
            observable_type=observable_type,
            timeout=20,
        )
        evidence, meta, _ = collector.run()
        malicious = int(getattr(evidence, "malicious_count", 0) or 0)
        suspicious = int(getattr(evidence, "suspicious_count", 0) or 0)
        total = int(getattr(evidence, "total_vendors", 0) or 0)
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        return {
            "found": bool(getattr(evidence, "found", False)),
            "status": meta.status.value,
            "error": meta.error,
            "verdict": verdict,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_vendors": total,
            "reputation_score": getattr(evidence, "reputation_score", 0),
            "notes": getattr(evidence, "notes", []),
        }
    except Exception as exc:
        logger.warning("VT lookup failed for %s (%s): %s", observable_type, value, exc)
        return {
            "found": False,
            "verdict": "unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 0,
            "error": str(exc),
        }


def _abuseipdb_lookup(ip: str) -> dict[str, Any]:
    settings = get_settings()
    api_key = settings.abuseipdb_api_key
    if not api_key:
        return {"checked": False, "error": "ABUSEIPDB_API_KEY not configured"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=20,
        )
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
        return {
            "checked": True,
            "ip": data.get("ipAddress", ip),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "country_code": data.get("countryCode"),
        }
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {"checked": False, "error": str(exc)}
