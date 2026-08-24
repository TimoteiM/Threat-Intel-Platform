"""
Lightweight email indicator checks.

Policy:
- URLs: VirusTotal (cached) + AnyRun TI lookup (when run_anyrun=True) + optional screenshot
- IPs: VirusTotal + AbuseIPDB
- Attachments: hash extraction + VirusTotal hash lookup + AnyRun TI lookup (when run_anyrun=True)
- Sender domain: WHOIS evidence + live email security DNS checks (DMARC/SPF/DKIM/MX)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
import whois as python_whois
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.email_security import analyze_email_security
from app.collectors.urlscan_collector import URLScanCollector
from app.services.email_attachment_inspection import inspect_attachments
from app.services.email_sender_identity import analyse_sender_identity
from app.services.email_url_triage import triage_email_urls
from app.collectors.vt_collector import VTCollector
from app.collectors.visual_comparison import capture_screenshot
from app.config import get_settings
from app.services.abuseipdb_client import abuseipdb_get, configured_abuseipdb_api_keys
from app.db.session import sync_engine
from app.models.database import LookupCache
from app.services.content_ml_service import classify_email_content_locally
from app.services.ml_attachment_analyzer import analyze_attachments_static
from app.services.ml_url_model import score_url
from app.services.provider_usage_metrics import record_provider_request
from app.services.risk_aggregator import aggregate_risk
from app.services.url_lexical_ml_service import assess_url_lexical_risk
from app.services.url_behavior_analyzer import analyze_url_behavior
from app.utils.domain_utils import extract_registered_domain, normalize_domain

logger = logging.getLogger(__name__)
VT_CACHE_TTL_HOURS = 24


def run_email_indicator_checks(
    extracted: dict[str, Any],
    *,
    include_url_screenshots: bool = False,
    run_anyrun: bool = False,
    max_urls: int = 20,
    max_attachment_hashes: int = 5,
) -> dict[str, Any]:
    """Run deterministic checks for extracted email indicators — all I/O in parallel."""
    t_total = time.perf_counter()

    sender_ip = extracted.get("sender_ip")
    sender_domain = extracted.get("sender_domain")
    attachments = [a for a in (extracted.get("attachments") or []) if isinstance(a, dict)]

    # Triage before spending anything. Checking every URL in an email meant ~20
    # VirusTotal requests per message to re-learn the same few facts — one real
    # message here carried 106 URLs across 5 destinations. Measured over this
    # platform's own 87-email corpus, this cuts external URL lookups from 1,251
    # to 107 while checking strictly more of what matters, because rewritten
    # links are now unwrapped to their real destination first.
    # Local, no quota. Runs before the URL triage because a link inside a PDF is
    # invisible to a body-text scan and still needs checking, and because its
    # findings decide which attachment — if any — is worth a sandbox credit.
    attachment_inspection = inspect_attachments(attachments)

    body_urls = [u for u in (extracted.get("urls") or []) if isinstance(u, str) and u]
    attachment_urls = list(attachment_inspection.get("urls_found_in_attachments") or [])
    triage = triage_email_urls(
        body_urls + attachment_urls,
        sender_domain=str(sender_domain or ""),
        budget=max(0, max_urls),
    )
    selected = triage["selected"]
    urls = [entry.url for entry in selected]
    max_urlscan_urls = min(len(urls), 5)

    checks: dict[str, Any] = {}

    # ── Phase 1: parallel I/O (sender domain WHOIS, sender IP, all URL checks, attachments) ──
    with ThreadPoolExecutor(max_workers=min(4 + len(urls), 32)) as pool:
        futures: dict[Any, str] = {}

        if sender_domain:
            futures[pool.submit(_timed, "sender_domain", _check_sender_domain, sender_domain)] = "sender_domain"
        else:
            checks["sender_domain"] = {"present": False, "message": "Not present in the provided evidence."}

        if sender_ip:
            futures[pool.submit(_timed, "sender_ip", _check_ip, sender_ip)] = "sender_ip"
        else:
            checks["sender_ip"] = {"present": False, "message": "Not present in the provided evidence."}

        futures[pool.submit(_timed, "attachments", _check_attachments, attachments, max_hashes=max_attachment_hashes, run_anyrun=run_anyrun, inspection=attachment_inspection)] = "attachments"

        url_futures: dict[Any, int] = {}
        for idx, url in enumerate(urls):
            f = pool.submit(
                _timed,
                f"url[{idx}]",
                _check_url,
                url,
                include_screenshot=include_url_screenshots,
                include_urlscan=(idx < max_urlscan_urls),
            )
            url_futures[f] = idx

        url_results: dict[int, dict[str, Any]] = {}
        for f in as_completed({**futures, **url_futures}):
            label, elapsed, result = f.result()
            logger.info("  %-30s  %.1fs", label, elapsed)
            if f in url_futures:
                url_results[url_futures[f]] = result
            elif label in ("sender_domain", "sender_ip", "attachments"):
                checks[label] = result

    checks["urls"] = [url_results[i] for i in range(len(urls))]
    for index, entry in enumerate(selected):
        item = checks["urls"][index]
        if not isinstance(item, dict):
            continue
        # Carry the triage decision onto the result so the report can show which
        # link was really checked, and what it was wrapped in.
        item["occurrences_in_email"] = entry.occurrences
        item["selection_reasons"] = entry.reasons
        if entry.unwrapped_from:
            item["unwrapped_from"] = entry.unwrapped_from
            item["original_urls"] = entry.original_urls

    # An analyst must be able to see what was not checked and why. A URL budget
    # that hides its own decisions is indistinguishable from a missed detection.
    checks["url_triage"] = {
        **triage["summary"],
        "infrastructure": [
            {"domain": e.domain, "occurrences": e.occurrences, "recognised_as": e.local_detail}
            for e in triage["infrastructure"]
        ],
        "not_checked": [
            {"domain": e.domain, "occurrences": e.occurrences, "score": e.score, "reasons": e.reasons}
            for e in triage["deferred"]
        ],
    }

    # ── Phase 2: fast local work ──
    t2 = time.perf_counter()
    checks["content_ml"] = classify_email_content_locally(extracted)
    # Who the message claims to be from, versus who sent it. Local only — BEC
    # routinely passes SPF, DKIM and DMARC from a clean new domain, so no
    # reputation or authentication check catches it.
    checks["sender_identity"] = analyse_sender_identity(extracted)
    checks["attachment_inspection"] = attachment_inspection

    attachment_items = (checks.get("attachments") or {}).get("items") or []
    vt_by_sha: dict[str, dict[str, Any]] = {}
    for item in attachment_items:
        if not isinstance(item, dict):
            continue
        sha = str(item.get("sha256") or "").strip().lower()
        if sha:
            vt_by_sha[sha] = item
    checks["attachment_analysis"] = analyze_attachments_static(attachments, vt_items_by_sha256=vt_by_sha)

    hybrid_items: list[dict[str, Any]] = []
    for url_item in checks.get("urls") or []:
        if not isinstance(url_item, dict):
            continue
        hy = url_item.get("hybrid_analysis")
        if isinstance(hy, dict):
            hybrid_items.append(hy)
    for item in attachment_items:
        if not isinstance(item, dict):
            continue
        hy = item.get("hybrid_analysis")
        if isinstance(hy, dict):
            hybrid_items.append(hy)
    checks["hybrid_analysis"] = {"items": hybrid_items}

    # ── Phase 3: email security DNS (needs sender_domain result) ──
    sender_domain_check = checks.get("sender_domain") or {}
    query_domain = str(
        sender_domain_check.get("query_domain")
        or sender_domain_check.get("domain")
        or sender_domain
        or ""
    ).strip()
    if query_domain:
        try:
            t_dns = time.perf_counter()
            email_security = analyze_email_security(query_domain, dns_evidence={}, timeout=3.0)
            checks["email_security"] = email_security
            logger.info("  %-30s  %.1fs", "email_security_dns", time.perf_counter() - t_dns)
        except Exception as exc:
            logger.warning("Email security DNS checks failed for %s: %s", query_domain, exc)
            checks["email_security"] = {"error": str(exc), "checked": False}
    else:
        checks["email_security"] = {"checked": False, "error": "No sender domain available"}

    first_url = next((u for u in checks.get("urls") or [] if isinstance(u, dict)), {}) or {}
    risk_input = {
        "url_lexical_ml": (first_url.get("lexical_ml") or {}),
        "url_behavior": (first_url.get("url_behavior") or {}),
        "content_ml": checks.get("content_ml") or {},
        "attachment_analysis": checks.get("attachment_analysis") or {},
        "hybrid_analysis": checks.get("hybrid_analysis") or {},
        "vt": ((checks.get("sender_ip") or {}).get("vt") or {}),
        "threat_feeds": {"abuseipdb": ((checks.get("sender_ip") or {}).get("abuseipdb") or {})},
        "whois": ((checks.get("sender_domain") or {}).get("whois") or {}),
    }
    checks["final_risk"] = aggregate_risk(risk_input)

    logger.info("email_indicator_checks TOTAL  %.1fs  (%d URLs, run_anyrun=%s)", time.perf_counter() - t_total, len(urls), run_anyrun)
    return checks


def _timed(label: str, fn, *args, **kwargs) -> tuple[str, float, Any]:
    """Run fn(*args, **kwargs), return (label, elapsed_seconds, result)."""
    t = time.perf_counter()
    result = fn(*args, **kwargs)
    return label, time.perf_counter() - t, result


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
    resolved_final_url = _resolve_final_url(url)
    lexical_target = str(resolved_final_url or url)
    try:
        lexical_ml = assess_url_lexical_risk(lexical_target)
    except Exception as exc:
        logger.warning("URL lexical ML failed for URL %s: %s", lexical_target, exc)
        lexical_ml = {
            "enabled": False,
            "model_source": "built_in",
            "score": 0.0,
            "label": "unknown",
            "top_features": [],
            "feature_contributions": {},
            "error": str(exc),
        }
    lexical_ml["target_url"] = lexical_target
    try:
        ml_url_score = score_url(lexical_target)
    except Exception as exc:
        logger.warning("URL ML model facade failed for URL %s: %s", lexical_target, exc)
        ml_url_score = {
            "url": lexical_target,
            "phishing_probability": 0.0,
            "risk_level": "unknown",
            "model_version": "lgbm-url-v1.0",
            "top_features": [],
            "error": str(exc),
        }
    try:
        url_behavior = analyze_url_behavior(lexical_target, timeout=12, max_hops=5)
    except Exception as exc:
        logger.warning("URL behavior analysis failed for URL %s: %s", lexical_target, exc)
        url_behavior = {
            "checked": False,
            "redirect_count": 0,
            "ua_cloaking_detected": False,
            "credential_form_present": False,
            "suspicious_post_endpoints": [],
            "multiple_domain_hops": False,
            "unique_domains_in_chain": [],
            "final_url": resolved_final_url,
            "chains": [],
            "behavior_score": 0.0,
            "error": str(exc),
        }
    final_vt_used = False
    if _should_retry_vt_on_final(vt, url=url, final_url=resolved_final_url):
        vt_final = _vt_lookup(str(resolved_final_url), "url")
        if _is_better_vt_result(vt_final, vt):
            vt = vt_final
            final_vt_used = True
    urlscan = _urlscan_lookup(str(resolved_final_url or url)) if include_urlscan else {
        "checked": False,
        "verdict": "unknown",
        "error": "Skipped for quota control",
    }
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

    # Effective verdict: VT first, URLScan fallback
    anyrun_url: dict[str, Any] = {"checked": False, "verdict": "unknown", "error": "Not requested"}
    effective = _effective_url_verdict(vt=vt, urlscan=urlscan, anyrun=anyrun_url)

    return {
        "url": url,
        "vt": vt,
        "effective_verdict": effective,
        "urlscan": urlscan,
        "anyrun": anyrun_url,
        "lexical_ml": lexical_ml,
        "ml_url_score": ml_url_score,
        "url_behavior": url_behavior,
        "hybrid_analysis": anyrun_url,  # kept for backward compat with risk aggregator
        "vt_checked_on_final_url": final_vt_used,
        "screenshot": screenshot,
    }


def _anyrun_url_ti_lookup(url: str) -> dict[str, Any]:
    """TI-only AnyRun lookup for a URL — no sandbox submission, no extra credits."""
    try:
        from app.services.anyrun_service import lookup_anyrun
        result = lookup_anyrun(
            indicator=url,
            indicator_type="url",
            submit_on_not_found=False,
            sandbox_first=False,
        )
        if not isinstance(result, dict):
            return {"checked": False, "verdict": "unknown", "error": "Empty result"}
        logger.info("AnyRun URL TI: url=%s checked=%s verdict=%s error=%s", url[:80], result.get("checked"), result.get("verdict"), result.get("error"))
        return result
    except Exception as exc:
        logger.warning("AnyRun URL TI lookup failed for %s: %s", url, exc)
        return {"checked": False, "verdict": "unknown", "error": str(exc)}


def _anyrun_hash_ti_lookup(sha256: str) -> dict[str, Any]:
    """TI-only AnyRun lookup for a file hash — no sandbox submission."""
    try:
        from app.services.anyrun_service import lookup_anyrun
        result = lookup_anyrun(
            indicator=sha256,
            indicator_type="hash",
            submit_on_not_found=False,
            sandbox_first=False,
        )
        return result if isinstance(result, dict) else {"checked": False, "verdict": "unknown", "error": "Empty result"}
    except Exception as exc:
        logger.warning("AnyRun hash TI lookup failed for %s: %s", sha256, exc)
        return {"checked": False, "verdict": "unknown", "error": str(exc)}


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


def _effective_url_verdict(
    *,
    vt: dict[str, Any],
    urlscan: dict[str, Any],
    anyrun: dict[str, Any] | None = None,
) -> str:
    vt_verdict = str(vt.get("verdict") or "unknown").lower()
    vt_malicious_count = int(vt.get("malicious_count") or 0)

    if vt_verdict in {"malicious", "suspicious"}:
        return vt_verdict
    if vt_verdict == "clean":
        # VT confirmed clean — AnyRun alone cannot override a clean VT verdict
        anyrun_verdict = str((anyrun or {}).get("verdict") or "unknown").lower()
        anyrun_score = float((anyrun or {}).get("threat_score") or 0)
        if anyrun_verdict == "malicious" and anyrun_score >= 95:
            return "suspicious"  # Downgrade: VT says clean, AnyRun uncertain
        return "clean"

    # VT is rate-limited or unknown — use AnyRun as fallback, but with caution
    anyrun_verdict = str((anyrun or {}).get("verdict") or "unknown").lower()
    anyrun_score = float((anyrun or {}).get("threat_score") or 0)
    if anyrun_verdict == "malicious":
        # Require high confidence (≥95) to report malicious with no VT confirmation
        # Below threshold, report suspicious so analysts can verify manually
        return "malicious" if anyrun_score >= 95 else "suspicious"
    if anyrun_verdict in {"suspicious", "clean"}:
        return anyrun_verdict

    urlscan_verdict = str((urlscan or {}).get("verdict") or "unknown").lower()
    if urlscan_verdict in {"malicious", "suspicious", "clean"}:
        return urlscan_verdict

    return "unknown"


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


# A sandbox detonation costs credits and takes minutes, so at most this many
# attachments per email are ever submitted — and only ones local inspection
# already found reason to distrust.
MAX_SANDBOX_ATTACHMENTS_PER_EMAIL = 1


def _check_attachments(
    attachments: list[dict[str, Any]],
    *,
    max_hashes: int,
    run_anyrun: bool,
    inspection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not attachments:
        return {
            "present": False,
            "items": [],
            "message": "Not present in the provided evidence.",
        }

    # Detonation is reserved for files that are both unknown to reputation and
    # structurally suspicious. Hashing alone answers nothing about a payload
    # nobody has submitted before, which is exactly what arrives in real phishing.
    detonate_candidates = set((inspection or {}).get("detonation_candidates") or [])
    detonations_left = MAX_SANDBOX_ATTACHMENTS_PER_EMAIL if run_anyrun else 0

    items: list[dict[str, Any]] = []
    for att in attachments[: max(0, max_hashes)]:
        sha256 = str(att.get("sha256") or "").strip()

        # AnyRun TI lookup for hash — fast, no sandbox credits
        anyrun_hash: dict[str, Any] = {"checked": False, "verdict": "unknown", "error": "Not requested"}
        if run_anyrun and sha256:
            anyrun_hash = _anyrun_hash_ti_lookup(sha256)

        vt_result = _vt_lookup(sha256, "hash") if sha256 else {"found": False, "error": "Missing SHA256 hash"}

        # Spend a detonation only when reputation has nothing and the file
        # itself looked wrong. Either condition alone is not worth the credit:
        # a known-bad hash needs no sandbox, and a clean-looking document that
        # VirusTotal already knows tells us nothing new.
        filename = str(att.get("filename") or "")
        sandbox: dict[str, Any] = {"submitted": False, "reason": "Not requested"}
        if run_anyrun:
            if not att.get("content_b64"):
                sandbox["reason"] = "Attachment content was not retained for submission."
            elif bool(vt_result.get("found")):
                sandbox["reason"] = "VirusTotal already has a report for this file."
            elif filename not in detonate_candidates:
                sandbox["reason"] = "Local inspection found nothing that warrants a sandbox credit."
            elif detonations_left <= 0:
                sandbox["reason"] = (
                    f"Detonation budget for this email is spent "
                    f"({MAX_SANDBOX_ATTACHMENTS_PER_EMAIL} per message)."
                )
            else:
                detonations_left -= 1
                sandbox = _detonate_attachment(att)

        items.append(
            {
                "filename": att.get("filename"),
                "sha256": sha256 or None,
                "md5": att.get("md5"),
                "size_bytes": att.get("size_bytes"),
                "vt": vt_result,
                "anyrun": anyrun_hash,
                "hybrid_analysis": anyrun_hash,  # backward compat
                "sandbox": sandbox,
            }
        )
    return {"present": True, "items": items}


def _detonate_attachment(att: dict[str, Any]) -> dict[str, Any]:
    """Submit one attachment to the sandbox. Never raises — this is best effort."""
    import base64 as _b64

    filename = str(att.get("filename") or "attachment.bin")
    try:
        payload = _b64.b64decode(str(att.get("content_b64") or ""))
    except Exception as exc:
        return {"submitted": False, "reason": f"Could not decode attachment: {exc}"}
    if not payload:
        return {"submitted": False, "reason": "Attachment content was empty."}

    try:
        from app.services.anyrun_service import lookup_anyrun

        # submit_on_not_found is what makes this a detonation rather than
        # another reputation lookup — without it this function would spend the
        # code path and none of the value.
        result = lookup_anyrun(
            indicator=str(att.get("sha256") or filename),
            indicator_type="file",
            file_bytes=payload,
            file_name=filename,
            submit_on_not_found=True,
        )
        return {"submitted": True, "reason": "Unknown to reputation and structurally suspicious.", "result": result}
    except Exception as exc:
        logger.warning("Attachment detonation failed for %s: %s", filename, exc)
        return {"submitted": False, "reason": f"Sandbox submission failed: {type(exc).__name__}: {exc}"}


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
    cache_key = _vt_cache_key(value=value, observable_type=observable_type)
    cached = _cache_get(cache_key)
    if isinstance(cached, dict):
        out = dict(cached)
        out["cache_hit"] = True
        return out

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

        result = {
            "found": bool(getattr(evidence, "found", False)),
            "status": meta.status.value,
            "error": meta.error,
            "verdict": verdict,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_vendors": total,
            "reputation_score": getattr(evidence, "reputation_score", 0),
            "notes": getattr(evidence, "notes", []),
            "cache_hit": False,
        }
        if verdict != "rate_limited":
            _cache_set(cache_key, result, source="virustotal", ttl_hours=VT_CACHE_TTL_HOURS)
        return result
    except Exception as exc:
        logger.warning("VT lookup failed for %s (%s): %s", observable_type, value, exc)
        message = str(exc)
        lowered = message.lower()
        if "rate limit" in lowered or "429" in lowered:
            return {
                "found": False,
                "verdict": "rate_limited",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 0,
                "error": message,
                "cache_hit": False,
            }
        return {
            "found": False,
            "verdict": "unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 0,
            "error": str(exc),
            "cache_hit": False,
        }


def _abuseipdb_lookup(ip: str) -> dict[str, Any]:
    settings = get_settings()
    if not configured_abuseipdb_api_keys(settings):
        return {"checked": False, "error": "ABUSEIPDB_API_KEY not configured"}
    try:
        # Falls through to the spare key when the first has spent its daily
        # allowance; an email full of sender IPs is exactly what exhausts one.
        resp = abuseipdb_get(
            "check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=20,
            settings=settings,
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
    return verdict in {"unknown", "rate_limited"} or total == 0


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
        "rate_limited": 0,
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


def _vt_cache_key(*, value: str, observable_type: str) -> str:
    raw = f"vt:{observable_type}:{str(value).strip()}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return f"email_vt:{observable_type}:{digest}"


def _cache_get(key: str) -> dict[str, Any] | None:
    try:
        now = datetime.now(timezone.utc)
        with Session(sync_engine) as db:
            row = db.execute(
                select(LookupCache).where(
                    LookupCache.cache_key == key,
                    LookupCache.expires_at > now,
                )
            ).scalar_one_or_none()
            if not row:
                return None
            if isinstance(row.cache_value, dict):
                return dict(row.cache_value)
            return None
    except Exception as exc:
        logger.warning("Lookup cache read failed for key %s: %s", key, exc)
        return None


def _cache_set(key: str, value: dict[str, Any], *, source: str, ttl_hours: int) -> None:
    try:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=max(1, ttl_hours))
        with Session(sync_engine) as db:
            row = db.execute(
                select(LookupCache).where(LookupCache.cache_key == key)
            ).scalar_one_or_none()
            if row:
                row.cache_value = value
                row.source = source
                row.expires_at = expires_at
            else:
                db.add(
                    LookupCache(
                        cache_key=key,
                        cache_value=value,
                        source=source,
                        expires_at=expires_at,
                    )
                )
            db.commit()
    except Exception as exc:
        logger.warning("Lookup cache write failed for key %s: %s", key, exc)


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
