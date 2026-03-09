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
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests
import whois as python_whois

from app.collectors.vt_collector import VTCollector
from app.collectors.urlscan_collector import URLScanCollector
from app.collectors.visual_comparison import capture_screenshot
from app.config import get_settings
from app.services.url_lexical_ml_service import assess_url_lexical_risk
from app.utils.domain_utils import extract_registered_domain, normalize_domain

logger = logging.getLogger(__name__)
_OPENPHISH_CACHE_TTL_SECONDS = 1800
_openphish_cache: dict[str, Any] = {"loaded_at": 0.0, "lines": []}


def run_email_indicator_checks(
    extracted: dict[str, Any],
    *,
    include_url_screenshots: bool = True,
    max_urls: int = 5,
    max_attachment_hashes: int = 5,
) -> dict[str, Any]:
    """Run deterministic checks for extracted email indicators."""
    sender_ip = extracted.get("sender_ip")
    sender_domain = extracted.get("sender_domain")
    urls = [u for u in (extracted.get("urls") or []) if isinstance(u, str) and u][: max(0, max_urls)]
    attachments = [a for a in (extracted.get("attachments") or []) if isinstance(a, dict)]

    max_urlscan_urls = min(len(urls), 5)
    checks = {
        "sender_domain": _check_sender_domain(sender_domain) if sender_domain else {"present": False, "message": "Not present in the provided evidence."},
        "sender_ip": _check_ip(sender_ip) if sender_ip else {"present": False, "message": "Not present in the provided evidence."},
        "urls": [
            _check_url(
                url,
                include_screenshot=include_url_screenshots,
                include_urlscan=(idx < max_urlscan_urls),
            )
            for idx, url in enumerate(urls)
        ],
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


def _check_url(url: str, *, include_screenshot: bool, include_urlscan: bool) -> dict[str, Any]:
    vt = _vt_lookup(url, "url")
    lexical_ml = assess_url_lexical_risk(url)
    fallback_feeds = _url_fallback_lookup(url)
    google_safe_browsing = _google_safe_browsing_lookup(url)
    urlscan = _urlscan_lookup(url) if include_urlscan else {"checked": False, "error": "Skipped for quota control"}
    effective_verdict = _effective_url_verdict(
        vt=vt,
        fallback=fallback_feeds,
        urlscan=urlscan,
        google_safe_browsing=google_safe_browsing,
    )
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
        "fallback_feeds": fallback_feeds,
        "google_safe_browsing": google_safe_browsing,
        "urlscan": urlscan,
        "effective_verdict": effective_verdict,
        "lexical_ml": lexical_ml,
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


def _url_fallback_lookup(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    result: dict[str, Any] = {
        "checked": True,
        "urlhaus": {"listed": False},
        "openphish": {"listed": False},
        "phishtank": {"listed": False},
        "verdict": "unknown",
    }

    urlhaus = _urlhaus_url_lookup(url)
    result["urlhaus"] = urlhaus

    openphish_listed = _openphish_lookup(url, host)
    result["openphish"] = {"listed": openphish_listed}

    phishtank = _phishtank_url_lookup(url)
    result["phishtank"] = phishtank

    if bool(urlhaus.get("listed")) or openphish_listed or bool(phishtank.get("listed")):
        result["verdict"] = "malicious"
    return result


def _urlhaus_url_lookup(url: str) -> dict[str, Any]:
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        status = str(data.get("query_status") or "").lower()
        if status == "ok":
            return {
                "listed": True,
                "status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": data.get("tags") or [],
            }
        return {"listed": False}
    except Exception as exc:
        return {"listed": False, "error": str(exc)}


def _openphish_lookup(url: str, host: str) -> bool:
    lines = _get_openphish_feed_lines()
    if not lines:
        return False
    u = (url or "").lower()
    h = (host or "").lower()
    for line in lines:
        if u in line:
            return True
        if h and h in line:
            return True
    return False


def _get_openphish_feed_lines() -> list[str]:
    now = time.time()
    loaded_at = float(_openphish_cache.get("loaded_at") or 0.0)
    if (now - loaded_at) <= _OPENPHISH_CACHE_TTL_SECONDS and _openphish_cache.get("lines"):
        return list(_openphish_cache.get("lines") or [])
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=20)
        resp.raise_for_status()
        lines = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
        _openphish_cache["loaded_at"] = now
        _openphish_cache["lines"] = lines
        return lines
    except Exception:
        return list(_openphish_cache.get("lines") or [])


def _phishtank_url_lookup(url: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        encoded_url = urllib.parse.quote(url, safe="")
        payload: dict[str, Any] = {"url": encoded_url, "format": "json"}
        if settings.phishtank_api_key:
            payload["app_key"] = settings.phishtank_api_key
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={"User-Agent": "phishtank/threat-investigator"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        results = data.get("results") or {}
        in_db = bool(results.get("in_database"))
        return {
            "listed": in_db,
            "verified": str(results.get("verified") or "").lower() == "yes",
            "phish_id": results.get("phish_id"),
        }
    except Exception as exc:
        return {"listed": False, "error": str(exc)}


def _urlscan_lookup(url: str) -> dict[str, Any]:
    try:
        collector = URLScanCollector(
            domain=url,
            investigation_id="email-indicator-check",
            observable_type="url",
            timeout=20,
        )
        evidence, meta, _ = collector.run()
        verdict = str(getattr(evidence, "verdict", "") or "").lower() or "unknown"
        if verdict == "benign":
            verdict = "clean"
        if verdict not in {"clean", "suspicious", "malicious"}:
            verdict = "unknown"
        return {
            "checked": True,
            "status": meta.status.value,
            "error": meta.error,
            "scan_id": getattr(evidence, "scan_id", None),
            "verdict": verdict,
            "score": getattr(evidence, "score", None),
            "page_url": getattr(evidence, "page_url", None),
            "page_ip": getattr(evidence, "page_ip", None),
            "page_country": getattr(evidence, "page_country", None),
            "page_server": getattr(evidence, "page_server", None),
            "page_title": getattr(evidence, "page_title", None),
            "requests_count": getattr(evidence, "requests_count", None),
            "tags": getattr(evidence, "tags", []) or [],
            "notes": getattr(evidence, "notes", []) or [],
        }
    except Exception as exc:
        logger.warning("URLScan lookup failed for URL %s: %s", url, exc)
        return {"checked": False, "verdict": "unknown", "error": str(exc)}


def _google_safe_browsing_lookup(url: str) -> dict[str, Any]:
    settings = get_settings()
    api_key = settings.google_safe_browsing_api_key
    if not api_key:
        return {"checked": False, "listed": False, "verdict": "unknown", "error": "GOOGLE_SAFE_BROWSING_API_KEY not configured"}
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "threat-intel-platform", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        matches = data.get("matches") or []
        return {
            "checked": True,
            "listed": bool(matches),
            "matches_count": len(matches),
            "threat_types": sorted({str(m.get("threatType") or "") for m in matches if m.get("threatType")}),
            "verdict": "malicious" if matches else "clean",
        }
    except Exception as exc:
        return {"checked": False, "listed": False, "verdict": "unknown", "error": str(exc)}


def _effective_url_verdict(
    *,
    vt: dict[str, Any],
    fallback: dict[str, Any],
    urlscan: dict[str, Any],
    google_safe_browsing: dict[str, Any],
) -> str:
    vt_verdict = str(vt.get("verdict") or "unknown").lower()
    if vt_verdict in {"malicious", "suspicious", "clean"}:
        return vt_verdict
    fallback_verdict = str((fallback or {}).get("verdict") or "unknown").lower()
    if fallback_verdict in {"malicious", "suspicious", "clean"}:
        return fallback_verdict
    urlscan_verdict = str((urlscan or {}).get("verdict") or "unknown").lower()
    if urlscan_verdict in {"malicious", "suspicious", "clean"}:
        return urlscan_verdict
    gsb_verdict = str((google_safe_browsing or {}).get("verdict") or "unknown").lower()
    if gsb_verdict in {"malicious", "suspicious", "clean"}:
        return gsb_verdict
    return "unknown"


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
