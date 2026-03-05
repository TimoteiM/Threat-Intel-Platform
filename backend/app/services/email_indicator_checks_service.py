"""
Lightweight email indicator checks.

Policy:
- URLs: VirusTotal only (+ optional screenshot/final URL capture)
- IPs: VirusTotal + AbuseIPDB
- Attachments: hash extraction + VirusTotal hash lookup
- Sender domain: WHOIS evidence
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any

import requests
import whois as python_whois

from app.collectors.vt_collector import VTCollector
from app.collectors.visual_comparison import capture_screenshot
from app.config import get_settings
from app.utils.domain_utils import extract_registered_domain, normalize_domain

logger = logging.getLogger(__name__)


def run_email_indicator_checks(
    extracted: dict[str, Any],
    *,
    include_url_screenshots: bool = False,
    max_urls: int = 20,
    max_attachment_hashes: int = 5,
) -> dict[str, Any]:
    """Run deterministic checks for extracted email indicators."""
    sender_ip = extracted.get("sender_ip")
    sender_domain = extracted.get("sender_domain")
    urls = [u for u in (extracted.get("urls") or []) if isinstance(u, str) and u][: max(0, max_urls)]
    attachments = [a for a in (extracted.get("attachments") or []) if isinstance(a, dict)]

    checks = {
        "sender_domain": _check_sender_domain(sender_domain) if sender_domain else {"present": False, "message": "Not present in the provided evidence."},
        "sender_ip": _check_ip(sender_ip) if sender_ip else {"present": False, "message": "Not present in the provided evidence."},
        "urls": [_check_url(url, include_screenshot=include_url_screenshots) for url in urls],
        "attachments": _check_attachments(attachments, max_hashes=max_attachment_hashes),
    }
    return checks


def _check_sender_domain(domain: str) -> dict[str, Any]:
    try:
        normalized = normalize_domain(domain)
        query_domain = extract_registered_domain(normalized)
        record = python_whois.whois(query_domain)

        created = _pick_datetime(getattr(record, "creation_date", None))
        expiry = _pick_datetime(getattr(record, "expiration_date", None))
        age_days = None
        if created:
            created_utc = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
            age_days = (datetime.now(timezone.utc) - created_utc).days

        statuses_raw = getattr(record, "status", None)
        statuses = statuses_raw if isinstance(statuses_raw, list) else ([statuses_raw] if statuses_raw else [])
        statuses_clean = [str(s) for s in statuses if s]

        name_servers_raw = getattr(record, "name_servers", None)
        name_servers = name_servers_raw if isinstance(name_servers_raw, list) else ([name_servers_raw] if name_servers_raw else [])
        ns_clean = sorted({str(ns).lower() for ns in name_servers if ns})

        return {
            "present": True,
            "domain": normalized,
            "query_domain": query_domain,
            "whois": {
                "registrar": _as_text(getattr(record, "registrar", None)),
                "created_date": created.isoformat() if created else None,
                "expiry_date": expiry.isoformat() if expiry else None,
                "domain_age_days": age_days,
                "statuses": statuses_clean,
                "name_servers": ns_clean,
                "registrant_org": _as_text(getattr(record, "org", None)),
                "registrant_country": _as_text(getattr(record, "country", None)),
            },
        }
    except Exception as exc:
        logger.warning("Sender domain WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "present": True,
            "domain": domain,
            "whois": {},
            "error": str(exc),
        }


def _check_url(url: str, *, include_screenshot: bool) -> dict[str, Any]:
    vt = _vt_lookup(url, "url")
    resolved_final_url = _resolve_final_url(url)
    final_vt_used = False
    if _should_retry_vt_on_final(vt, url=url, final_url=resolved_final_url):
        vt_final = _vt_lookup(str(resolved_final_url), "url")
        if _is_better_vt_result(vt_final, vt):
            vt = vt_final
            final_vt_used = True
    screenshot: dict[str, Any] = {
        "captured": False,
        "final_url": resolved_final_url,
        "image_base64": None,
        "error": "Not requested",
    }

    if include_screenshot:
        try:
            png_bytes, final_url = capture_screenshot(url, timeout=20)
            screenshot = {
                "captured": True,
                "final_url": final_url or resolved_final_url,
                "image_base64": base64.b64encode(png_bytes).decode("ascii"),
                "error": None,
            }
        except Exception as exc:
            screenshot = {
                "captured": False,
                "final_url": resolved_final_url,
                "image_base64": None,
                "error": str(exc),
            }

    return {
        "url": url,
        "vt": vt,
        "vt_checked_on_final_url": final_vt_used,
        "screenshot": screenshot,
    }


def _check_ip(ip: str) -> dict[str, Any]:
    abuse = _abuseipdb_lookup(ip)
    ipwhois = _ipwhois_lookup(ip)
    return {
        "present": True,
        "ip": ip,
        "vt": _vt_lookup(ip, "ip"),
        "abuseipdb": abuse,
        "ipwhois": ipwhois,
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


def _should_retry_vt_on_final(vt_result: dict[str, Any], *, url: str, final_url: str | None) -> bool:
    if not final_url:
        return False
    if str(final_url).strip() == str(url).strip():
        return False
    verdict = str(vt_result.get("verdict") or "unknown").lower()
    total = int(vt_result.get("total_vendors") or 0)
    # Retry when current VT signal is weak/inconclusive.
    return verdict == "unknown" or total == 0


def _is_better_vt_result(candidate: dict[str, Any], current: dict[str, Any]) -> bool:
    c_score = _vt_strength_score(candidate)
    cur_score = _vt_strength_score(current)
    return c_score > cur_score


def _vt_strength_score(v: dict[str, Any]) -> int:
    verdict = str(v.get("verdict") or "unknown").lower()
    malicious = int(v.get("malicious_count") or 0)
    suspicious = int(v.get("suspicious_count") or 0)
    total = int(v.get("total_vendors") or 0)
    base = {
        "malicious": 3000,
        "suspicious": 2000,
        "clean": 1000,
        "unknown": 0,
    }.get(verdict, 0)
    return base + (malicious * 20) + (suspicious * 5) + min(total, 500)


def _ipwhois_lookup(ip: str) -> dict[str, Any]:
    """Best-effort IP enrichment fallback when AbuseIPDB is unavailable."""
    try:
        resp = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=15,
            headers={"User-Agent": "ThreatIntelEmailChecker/1.0"},
        )
        resp.raise_for_status()
        data = resp.json() or {}
        if not data.get("success"):
            return {"checked": False, "error": str(data.get("message") or "lookup failed")}
        conn = data.get("connection") or {}
        return {
            "checked": True,
            "ip": data.get("ip", ip),
            "isp": conn.get("isp"),
            "org": conn.get("org"),
            "asn": conn.get("asn"),
            "domain": conn.get("domain"),
            "country_code": data.get("country_code"),
        }
    except Exception as exc:
        logger.warning("ipwho.is lookup failed for %s: %s", ip, exc)
        return {"checked": False, "error": str(exc)}


def _resolve_final_url(url: str) -> str | None:
    """Resolve final destination via HTTP redirects without taking screenshots."""
    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=12,
            stream=True,
            headers={"User-Agent": "ThreatIntelEmailChecker/1.0"},
        )
        try:
            return str(resp.url) if resp.url else None
        finally:
            resp.close()
    except Exception:
        return None


def _pick_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            if isinstance(item, datetime):
                return item
        return None
    return value if isinstance(value, datetime) else None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None
