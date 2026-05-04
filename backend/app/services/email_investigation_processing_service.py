"""Email investigation processing helpers shared by API and Celery tasks."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
import base64
import json
import re
from email.header import decode_header
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

from app.services.anyrun_service import lookup_anyrun
from app.services.email_ai_interpreter_service import interpret_email_results_with_ai
from app.services.email_indicator_checks_service import run_email_indicator_checks
from app.services.email_ioc_service import extract_email_iocs
from app.services.risk_aggregator import aggregate_risk
from app.utils.domain_utils import extract_registered_domain, normalize_domain

NOT_PRESENT = "Not present in the provided evidence."


async def process_email_investigation(
    *,
    payload: bytes,
    filename: str,
    context: str = "",
    max_urls: int = 20,
    max_attachment_hashes: int = 5,
    include_url_screenshots: bool = False,
    run_anyrun: bool = False,
    run_ai: bool = True,
    ml_phishing_score: str | None = None,
) -> dict[str, Any]:
    extracted = extract_email_iocs(payload, filename=filename)

    checks, email_anyrun = await asyncio.gather(
        asyncio.to_thread(
            run_email_indicator_checks,
            extracted,
            include_url_screenshots=include_url_screenshots,
            run_anyrun=run_anyrun,
            max_urls=max_urls,
            max_attachment_hashes=max_attachment_hashes,
        ),
        asyncio.to_thread(
            _lookup_email_anyrun,
            payload,
            filename,
            run_anyrun=run_anyrun,
        ),
    )
    if email_anyrun is not None:
        checks["email_anyrun"] = email_anyrun
        checks["hybrid_analysis"] = {"items": [email_anyrun] if email_anyrun.get("checked") else []}
        checks["final_risk"] = _aggregate_email_risk(checks)

    parsed_ml_score: float | None = None
    if ml_phishing_score not in (None, ""):
        try:
            parsed_ml_score = float(ml_phishing_score)
        except ValueError:
            parsed_ml_score = None

    interpretation_payload = {
        "email_subject": extracted.get("email_subject"),
        "sender_email": extracted.get("sender_email"),
        "sender_name": extracted.get("sender_name"),
        "sender_domain": extracted.get("sender_domain"),
        "sender_ip": extracted.get("sender_ip"),
        "authentication": extracted.get("authentication"),
        # Only send suspicious/malicious items to AI — clean ones waste tokens
        "indicator_checks": _compact_suspicious_checks_for_ai(checks),
        "email_security": _compact_email_security_for_ai(checks.get("email_security") or {}),
        "context": context or None,
        "ml_phishing_score": parsed_ml_score,
    }

    if run_ai:
        try:
            resolution = await interpret_email_results_with_ai(interpretation_payload)
            if not isinstance(resolution.get("sender_domain_analysis"), dict):
                resolution["sender_domain_analysis"] = _sender_domain_fallback(
                    extracted=extracted,
                    checks=checks,
                    reason="AI response did not include sender-domain analysis.",
                    classification="unknown",
                )
            # Merge AI url_assessments with deterministic fallback for full coverage
            resolution["url_assessments"] = _merge_url_assessments(
                ai_items=resolution.get("url_assessments"),
                checks=checks,
            )
            resolution_source = "ai"
        except Exception as exc:  # pragma: no cover - fallback path
            logger.warning("AI interpretation failed: %s", exc)
            resolution = {
                "overall_verdict": "inconclusive",
                "confidence": "low",
                "primary_signals": [],
                "url_assessments": _build_url_assessments_fallback(checks),
                "attachment_narratives": [],
                "sender_domain_analysis": _sender_domain_fallback(
                    extracted=extracted,
                    checks=checks,
                    reason=f"AI interpretation failed: {type(exc).__name__}",
                    classification="unknown",
                ),
            }
            resolution_source = "fallback_error"
    else:
        resolution = {
            "overall_verdict": "inconclusive",
            "confidence": "low",
            "primary_signals": [],
            "url_assessments": _build_url_assessments_fallback(checks),
            "attachment_narratives": [],
            "sender_domain_analysis": _sender_domain_fallback(
                extracted=extracted,
                checks=checks,
                reason="AI interpretation disabled for this run.",
                classification="unknown",
            ),
        }
        resolution_source = "disabled"

    # Compute deterministic overall_verdict when AI didn't provide one.
    # If AI is cautious/inconclusive but deterministic checks are all clean,
    # prefer the checked-clean verdict over an ambiguous result.
    det_verdict, det_signals = _deterministic_overall_verdict(checks)
    if resolution_source != "ai":
        resolution["overall_verdict"] = det_verdict
        resolution["primary_signals"] = det_signals
        resolution["confidence"] = "medium" if len(det_signals) >= 2 else "low"
    elif str(resolution.get("overall_verdict") or "").lower() == "inconclusive" and det_verdict == "clean":
        resolution["overall_verdict"] = "clean"
        resolution["primary_signals"] = det_signals
        resolution["confidence"] = "medium"

    # Always build the bullet-point template as the primary formatted_resolution.
    # AI provides narratives for suspicious items that are woven into the template.
    resolution["formatted_resolution"] = _render_template_resolution(
        extracted=extracted,
        checks=checks,
        resolution=resolution,
        context=context,
    )

    return {
        "filename": filename,
        "email_subject": extracted.get("email_subject"),
        "sender_email": extracted.get("sender_email"),
        "sender_name": extracted.get("sender_name"),
        "sender_domain": extracted.get("sender_domain"),
        "sender_ip": extracted.get("sender_ip"),
        "authentication": extracted.get("authentication"),
        "urls_count": len(extracted.get("urls") or []),
        "urls": extracted.get("urls") or [],
        "url_domains": extracted.get("url_domains") or [],
        "attachments_count": len(extracted.get("attachments") or []),
        "attachments": extracted.get("attachments") or [],
        "indicator_checks": checks,
        "resolution_source": resolution_source,
        "resolution": resolution,
    }


def _lookup_email_anyrun(payload: bytes, filename: str, *, run_anyrun: bool) -> dict[str, Any] | None:
    if not run_anyrun:
        return None

    t = time.perf_counter()
    logger.info("AnyRun email sandbox: submitting %s (%d bytes)", filename, len(payload))
    result = lookup_anyrun(
        indicator=filename,
        indicator_type="file",
        file_bytes=payload,
        file_name=filename,
        submit_on_not_found=True,
        sandbox_first=True,
    )
    elapsed = time.perf_counter() - t
    checked = (result or {}).get("checked")
    verdict = (result or {}).get("verdict")
    error = (result or {}).get("error")
    logger.info("AnyRun email sandbox: checked=%s verdict=%s error=%s elapsed=%.1fs", checked, verdict, error, elapsed)
    return {
        **(result if isinstance(result, dict) else {}),
        "file_name": filename,
    }


def _aggregate_email_risk(checks: dict[str, Any]) -> dict[str, Any]:
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
    return aggregate_risk(risk_input)


def _build_url_assessments_fallback(checks: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in checks.get("urls") or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "Not present in the provided evidence.")
        vt = item.get("vt") or {}
        lexical = item.get("lexical_ml") or {}
        ss = item.get("screenshot") or {}
        final_url = str(ss.get("final_url") or "Not present in the provided evidence.")
        verdict = str(vt.get("verdict") or "unknown").lower()
        if verdict == "clean":
            legitimacy = "legitimate"
        elif verdict in {"suspicious", "malicious"}:
            legitimacy = verdict
        else:
            legitimacy = "unknown"
        reasoning = _build_url_reasoning(
            url=url,
            final_url=final_url,
            verdict=verdict,
            malicious_count=int(vt.get("malicious_count") or 0),
            suspicious_count=int(vt.get("suspicious_count") or 0),
            total_vendors=int(vt.get("total_vendors") or 0),
            lexical_label=str(lexical.get("label") or "unknown").lower(),
            lexical_score=float(lexical.get("score") or 0.0),
        )
        out.append(
            {
                "url": url,
                "where_it_points": final_url,
                "legitimacy": legitimacy,
                "reasoning": reasoning,
            }
        )
    return out


def _build_url_reasoning(
    *,
    url: str,
    final_url: str,
    verdict: str,
    malicious_count: int,
    suspicious_count: int,
    total_vendors: int,
    lexical_label: str,
    lexical_score: float,
) -> str:
    target = final_url if final_url != "Not present in the provided evidence." else url
    host = ""
    path = ""
    try:
        parsed = urlparse(target)
        host = (parsed.netloc or parsed.path or "").strip()
        path = (parsed.path or "").strip()
    except Exception:
        pass

    if verdict in {"malicious", "suspicious"}:
        return (
            f"This URL resolves to {target}. VirusTotal flagged it as {verdict} "
            f"(malicious={malicious_count}, suspicious={suspicious_count}, vendors={total_vendors}); "
            "treat the destination as risky."
        )

    if verdict == "rate_limited":
        return (
            f"This URL resolves to {target}. VirusTotal query was rate-limited, "
            "so verdict is temporarily unavailable."
        )

    if verdict == "clean":
        if host:
            if lexical_label in {"high", "medium"}:
                return (
                    f"This URL points to {host}{path if path else ''}. VirusTotal is clean, "
                    f"but lexical ML is {lexical_label} risk (score={lexical_score:.3f}); "
                    "treat as potentially deceptive until validated."
                )
            if host.lower().endswith("w3.org"):
                return (
                    f"This URL points to a W3C-hosted standards resource "
                    f"({path or host}). VirusTotal shows no malicious detections."
                )
            return (
                f"This URL points to {host}{path if path else ''}. "
                f"VirusTotal reports clean (0 malicious detections across {total_vendors} vendors)."
            )
        return (
            f"This URL resolves to {target}. VirusTotal reports clean "
            f"(0 malicious detections across {total_vendors} vendors)."
        )

    return (
        f"This URL resolves to {target}. URL reputation is inconclusive in the current evidence."
    )


def _normalize_url_key(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:-1] if text.endswith("/") else text


def _is_weak_assessment(item: dict[str, Any]) -> bool:
    legitimacy = str(item.get("legitimacy") or "").strip().lower()
    reasoning = str(item.get("reasoning") or "").strip().lower()
    if legitimacy in {"", "unknown"}:
        return True
    if reasoning in {"", "not present in the provided evidence."}:
        return True
    return False


def _merge_url_assessments(ai_items: Any, checks: dict[str, Any]) -> list[dict[str, str]]:
    """
    Keep AI URL assessments when they add value, but never lose deterministic VT-based coverage.
    """
    fallback = _build_url_assessments_fallback(checks)
    if not isinstance(ai_items, list):
        return fallback

    ai_by_url: dict[str, dict[str, Any]] = {}
    for item in ai_items:
        if not isinstance(item, dict):
            continue
        key = _normalize_url_key(item.get("url"))
        if not key:
            continue
        ai_by_url[key] = item

    merged: list[dict[str, str]] = []
    for base in fallback:
        key = _normalize_url_key(base.get("url"))
        ai_item = ai_by_url.get(key)
        if not ai_item or _is_weak_assessment(ai_item):
            merged.append(base)
            continue
        merged.append(
            {
                "url": str(ai_item.get("url") or base["url"]),
                "where_it_points": str(ai_item.get("where_it_points") or base["where_it_points"]),
                "legitimacy": str(ai_item.get("legitimacy") or base["legitimacy"]).lower(),
                "reasoning": str(ai_item.get("reasoning") or base["reasoning"]),
            }
        )
    return merged


def prepare_history_payload(response_payload: dict[str, Any]) -> dict[str, Any]:
    """Store compact result payload for history (no base64 screenshots)."""
    checks = dict(response_payload.get("indicator_checks") or {})
    urls: list[dict[str, Any]] = []
    for item in checks.get("urls") or []:
        if not isinstance(item, dict):
            continue
        ss = dict(item.get("screenshot") or {})
        ss.pop("image_base64", None)
        urls.append(
            {
                "url": item.get("url"),
                "vt": item.get("vt") or {},
                "effective_verdict": item.get("effective_verdict"),
                "urlscan": item.get("urlscan") or {},
                "anyrun": item.get("anyrun") or {},
                "lexical_ml": item.get("lexical_ml") or {},
                "ml_url_score": item.get("ml_url_score") or {},
                "url_behavior": item.get("url_behavior") or {},
                "hybrid_analysis": item.get("hybrid_analysis") or {},
                "screenshot": ss,
            }
        )
    checks["urls"] = urls
    checks["content_ml"] = checks.get("content_ml") or {}
    checks["attachment_analysis"] = checks.get("attachment_analysis") or {}
    checks["hybrid_analysis"] = checks.get("hybrid_analysis") or {}
    checks["email_anyrun"] = checks.get("email_anyrun") or {}
    checks["final_risk"] = checks.get("final_risk") or {}
    checks["email_security"] = checks.get("email_security") or {}

    return {
        "filename": response_payload.get("filename"),
        "email_subject": response_payload.get("email_subject"),
        "sender_email": response_payload.get("sender_email"),
        "sender_domain": response_payload.get("sender_domain"),
        "sender_ip": response_payload.get("sender_ip"),
        "authentication": response_payload.get("authentication") or {},
        "urls_count": int(response_payload.get("urls_count") or 0),
        "urls": response_payload.get("urls") or [],
        "url_domains": response_payload.get("url_domains") or [],
        "attachments_count": int(response_payload.get("attachments_count") or 0),
        "attachments": response_payload.get("attachments") or [],
        "indicator_checks": checks,
        "resolution_source": response_payload.get("resolution_source"),
        "resolution": response_payload.get("resolution") or {},
    }


def _compact_checks_for_ai(checks: dict[str, Any]) -> dict[str, Any]:
    sender_domain = checks.get("sender_domain") or {}
    whois = sender_domain.get("whois") or {}
    urls_compact: list[dict[str, Any]] = []
    for item in checks.get("urls") or []:
        vt = item.get("vt") or {}
        ss = item.get("screenshot") or {}
        lexical = item.get("lexical_ml") or {}
        anyrun_url = item.get("anyrun") or {}
        behavior = item.get("url_behavior") or {}
        urls_compact.append(
            {
                "url": item.get("url"),
                "vt": {
                    "found": vt.get("found"),
                    "verdict": vt.get("verdict"),
                    "malicious_count": vt.get("malicious_count"),
                    "suspicious_count": vt.get("suspicious_count"),
                    "total_vendors": vt.get("total_vendors"),
                    "error": vt.get("error"),
                },
                "effective_verdict": item.get("effective_verdict"),
                "anyrun": {
                    "checked": anyrun_url.get("checked"),
                    "verdict": anyrun_url.get("verdict"),
                    "threat_score": anyrun_url.get("threat_score"),
                    "error": anyrun_url.get("error"),
                },
                "urlscan": item.get("urlscan") or {},
                "lexical_ml": {
                    "target_url": lexical.get("target_url"),
                    "model_source": lexical.get("model_source"),
                    "score": lexical.get("score"),
                    "label": lexical.get("label"),
                    "top_features": lexical.get("top_features") or [],
                    "error": lexical.get("error"),
                },
                "ml_url_score": item.get("ml_url_score") or {},
                "url_behavior": {
                    "checked": behavior.get("checked"),
                    "redirect_count": behavior.get("redirect_count"),
                    "ua_cloaking_detected": behavior.get("ua_cloaking_detected"),
                    "credential_form_present": behavior.get("credential_form_present"),
                    "multiple_domain_hops": behavior.get("multiple_domain_hops"),
                    "final_url": behavior.get("final_url"),
                },
                "screenshot": {
                    "captured": ss.get("captured"),
                    "final_url": ss.get("final_url"),
                    "error": ss.get("error"),
                },
            }
        )

    attachments = checks.get("attachments") or {}
    attachment_analysis = checks.get("attachment_analysis") or {}
    att_static_by_hash: dict[str, dict[str, Any]] = {}
    for static_item in attachment_analysis.get("items") or []:
        if not isinstance(static_item, dict):
            continue
        h = str(static_item.get("hash") or "").strip().lower()
        if h:
            att_static_by_hash[h] = static_item
    att_items = []
    for att in attachments.get("items") or []:
        vt = att.get("vt") or {}
        anyrun = att.get("anyrun") or {}
        sha = str(att.get("sha256") or "").strip().lower()
        static = att_static_by_hash.get(sha) or {}
        att_items.append(
            {
                "filename": att.get("filename"),
                "sha256": att.get("sha256"),
                "md5": att.get("md5"),
                "size_bytes": att.get("size_bytes"),
                "vt": {
                    "found": vt.get("found"),
                    "verdict": vt.get("verdict"),
                    "malicious_count": vt.get("malicious_count"),
                    "suspicious_count": vt.get("suspicious_count"),
                    "total_vendors": vt.get("total_vendors"),
                    "error": vt.get("error"),
                },
                "anyrun": {
                    "checked": anyrun.get("checked"),
                    "verdict": anyrun.get("verdict"),
                    "threat_score": anyrun.get("threat_score"),
                    "error": anyrun.get("error"),
                },
                "static_ml": {
                    "risk_level": static.get("risk_level"),
                    "static_risk_score": static.get("static_risk_score"),
                    "mime_type": static.get("mime_type"),
                } if static else None,
            }
        )

    sender_ip = checks.get("sender_ip") or {}
    ip_vt = sender_ip.get("vt") or {}
    return {
        "sender_domain": {
            "present": sender_domain.get("present"),
            "domain": sender_domain.get("domain"),
            "query_domain": sender_domain.get("query_domain"),
            "error": sender_domain.get("error"),
            "whois": {
                "registrar": whois.get("registrar"),
                "created_date": whois.get("created_date"),
                "expiry_date": whois.get("expiry_date"),
                "domain_age_days": whois.get("domain_age_days"),
                "statuses": whois.get("statuses") or [],
                "name_servers": whois.get("name_servers") or [],
                "registrant_org": whois.get("registrant_org"),
                "registrant_country": whois.get("registrant_country"),
            },
        },
        "sender_ip": {
            "present": sender_ip.get("present"),
            "ip": sender_ip.get("ip"),
            "vt": {
                "found": ip_vt.get("found"),
                "verdict": ip_vt.get("verdict"),
                "malicious_count": ip_vt.get("malicious_count"),
                "suspicious_count": ip_vt.get("suspicious_count"),
                "total_vendors": ip_vt.get("total_vendors"),
                "error": ip_vt.get("error"),
            },
            "abuseipdb": sender_ip.get("abuseipdb"),
            "ipwhois": sender_ip.get("ipwhois"),
        },
        "urls": urls_compact,
        "attachments": {
            "present": attachments.get("present"),
            "items": att_items,
            "message": attachments.get("message"),
        },
        "content_ml": checks.get("content_ml") or {},
        "attachment_analysis": checks.get("attachment_analysis") or {},
        "hybrid_analysis": checks.get("hybrid_analysis") or {},
        "email_anyrun": checks.get("email_anyrun") or {},
        "final_risk": checks.get("final_risk") or {},
    }


def _sender_domain_fallback(
    *,
    extracted: dict[str, Any],
    checks: dict[str, Any],
    reason: str,
    classification: str = "unknown",
) -> dict[str, Any]:
    sender_domain = str(extracted.get("sender_domain") or "").strip()
    sender_email = str(extracted.get("sender_email") or "").strip()
    sender_domain_check = checks.get("sender_domain") or {}
    whois = sender_domain_check.get("whois") or {}
    urls = checks.get("urls") or []
    url_count = len(urls)
    suspicious_urls = sum(
        1
        for item in urls
        if str(((item or {}).get("vt") or {}).get("verdict") or "").lower() in {"malicious", "suspicious"}
    )

    if sender_domain:
        registrar = str(whois.get("registrar") or "").strip()
        domain_age_days = whois.get("domain_age_days")
        statuses = whois.get("statuses") or []
        whois_line_parts = []
        if registrar:
            whois_line_parts.append(f"registrar={registrar}")
        if isinstance(domain_age_days, int):
            whois_line_parts.append(f"age_days={domain_age_days}")
        if statuses:
            whois_line_parts.append(f"statuses={','.join(str(s) for s in statuses[:3])}")
        whois_line = f" WHOIS: {'; '.join(whois_line_parts)}." if whois_line_parts else ""

        reasoning = (
            f"Sender domain extracted: {sender_domain}."
            f" Sender email: {sender_email or 'Not present in the provided evidence.'}."
            f"{whois_line}"
            f" URL checks completed: {url_count} (suspicious/malicious: {suspicious_urls})."
            f" {reason}"
        )
        findings = [
            {
                "title": "Sender domain extracted from email headers",
                "severity": "low",
                "description": f"Sender domain value present in evidence: {sender_domain}.",
            },
            {
                "title": "Sender domain WHOIS evidence",
                "severity": "low",
                "description": (
                    f"Registrar: {registrar or 'Not present in the provided evidence.'}; "
                    f"Age days: {domain_age_days if isinstance(domain_age_days, int) else 'Not present in the provided evidence.'}; "
                    f"Statuses: {', '.join(str(s) for s in statuses) if statuses else 'Not present in the provided evidence.'}."
                ),
            },
            {
                "title": "Email-level URL context for sender assessment",
                "severity": "medium" if suspicious_urls > 0 else "low",
                "description": (
                    f"URLs analyzed: {url_count}; suspicious/malicious VT verdicts: {suspicious_urls}."
                ),
            },
        ]
    else:
        reasoning = "Not present in the provided evidence."
        findings = []

    return {
        "classification": classification,
        "primary_reasoning": reasoning,
        "findings": findings,
    }


def _render_template_resolution(
    *,
    extracted: dict[str, Any],
    checks: dict[str, Any],
    resolution: dict[str, Any],
    context: str,
) -> str:
    """
    Build the bullet-point investigation template, weaving AI narratives for
    suspicious/malicious attachments and URLs into each relevant bullet.
    """
    email_subject = _decode_header_text(str(extracted.get("email_subject") or NOT_PRESENT))
    sender_email = str(extracted.get("sender_email") or NOT_PRESENT)
    sender_name = str(extracted.get("sender_name") or "").strip()
    company_name, domain_description = _infer_sender_company_and_description(
        extracted=extracted,
        checks=checks,
        resolution=resolution,
    )

    # Sender IP
    sender_ip = str(extracted.get("sender_ip") or NOT_PRESENT)
    ip_result = checks.get("sender_ip") or {}
    abuse = ip_result.get("abuseipdb") or {}
    ipwhois = ip_result.get("ipwhois") or {}
    abuse_error = str(abuse.get("error") or "").strip()
    abuse_error_short = _short_error(abuse_error)
    isp = str(abuse.get("isp") or abuse.get("asn_org") or ipwhois.get("isp") or ipwhois.get("org") or "").strip()
    usage_type = str(abuse.get("usage_type") or abuse.get("usageType") or "").strip()
    if not usage_type and ipwhois.get("checked"):
        usage_type = "Inferred via ipwho.is"
    if not isp:
        isp = f"Unavailable ({abuse_error_short})" if abuse_error_short else NOT_PRESENT
    if not usage_type:
        usage_type = f"Unavailable ({abuse_error_short})" if abuse_error_short else NOT_PRESENT
    ip_summary = _summarize_ip_result(ip_result)

    # AI narratives index
    attachment_narratives_by_filename: dict[str, str] = {}
    for an in resolution.get("attachment_narratives") or []:
        if not isinstance(an, dict):
            continue
        fn = str(an.get("filename") or "").strip().lower()
        if fn:
            attachment_narratives_by_filename[fn] = str(an.get("narrative") or "").strip()

    url_narratives_by_url: dict[str, str] = {}
    for ua in resolution.get("url_assessments") or []:
        if not isinstance(ua, dict):
            continue
        url_key = str(ua.get("url") or "").strip().rstrip("/")
        narrative = str(ua.get("narrative") or ua.get("reasoning") or "").strip()
        if url_key and narrative and narrative != NOT_PRESENT:
            url_narratives_by_url[url_key] = narrative

    lines = [
        f'Email subject: "{email_subject}"',
        "",
        "After our investigation, we found:",
    ]

    # ── Sender bullet ──────────────────────────────────────────────
    sender_name_part = f" (Sender name: {sender_name})" if sender_name else ""
    sender_domain_check = checks.get("sender_domain") or {}
    whois = sender_domain_check.get("whois") or {}
    registrar = str(whois.get("registrar") or "").strip()
    domain_age = whois.get("domain_age_days")
    registrant_country = str(whois.get("registrant_country") or "").strip()

    if company_name and company_name != NOT_PRESENT:
        # Include description only when it's a real company description (not WHOIS noise)
        if domain_description and domain_description != NOT_PRESENT and not _is_weak_domain_description(domain_description):
            company_part = f"{company_name} — {domain_description}"
        else:
            company_part = company_name
    else:
        company_part = NOT_PRESENT

    # Email security spoofability
    es = checks.get("email_security") or {}
    spoofability = str(es.get("spoofability_score") or "").lower()
    auth_header = extracted.get("authentication") or {}
    spf_header = str(auth_header.get("spf") or "none").lower()
    dkim_header = str(auth_header.get("dkim") or "none").lower()
    dmarc_header = str(auth_header.get("dmarc") or "none").lower()

    # Only flag authentication issues that are actionable for the client
    auth_warnings: list[str] = []
    if spf_header == "fail":
        auth_warnings.append("the email failed SPF authentication")
    if dkim_header == "fail":
        auth_warnings.append("DKIM signature is invalid")
    if dmarc_header == "fail":
        auth_warnings.append("the email failed DMARC authentication")
    if spoofability == "high" and any(v == "fail" for v in (spf_header, dkim_header, dmarc_header)):
        auth_warnings.append("the sender domain can be trivially spoofed")

    # Only surface domain age when newly registered (suspicious signal)
    age_warning = ""
    if isinstance(domain_age, int) and domain_age < 30:
        age_warning = f" The domain was registered only {domain_age} days ago, which is a high-risk signal."

    sender_line = f"- The sender's email address {sender_email}{sender_name_part}."
    if company_part != NOT_PRESENT:
        sender_line += f" The domain belongs to {company_part}."
    else:
        sender_line += " No official information was found about the sender domain."
    if age_warning:
        sender_line = sender_line.rstrip(".") + "." + age_warning
    if auth_warnings:
        sender_line = sender_line.rstrip(".") + " Note: " + "; ".join(auth_warnings) + "."
    lines.append(sender_line)

    # ── Sender IP bullet ───────────────────────────────────────────
    lines.append(
        f"- The sender's IP address is {sender_ip} (ISP: {isp}, Usage Type: {usage_type}), "
        f"was checked and {ip_summary}."
    )

    # ── Attachments bullet(s) ──────────────────────────────────────
    attachment_items = (checks.get("attachments") or {}).get("items") or []
    if not attachment_items:
        lines.append("- No attachments were present in the email body.")
    else:
        for att in attachment_items:
            if not isinstance(att, dict):
                continue
            filename = str(att.get("filename") or "unnamed attachment")
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
            vt = att.get("vt") or {}
            anyrun = att.get("anyrun") or {}
            vt_verdict = str(vt.get("verdict") or "unknown").lower()
            anyrun_verdict = str(anyrun.get("verdict") or "").lower()

            # Pick the AI narrative if available
            ai_narrative = attachment_narratives_by_filename.get(filename.lower(), "")

            if vt_verdict in {"malicious", "suspicious"} or anyrun_verdict in {"malicious", "suspicious"}:
                source = "AnyRun" if anyrun_verdict in {"malicious", "suspicious"} else "VirusTotal"
                verdict_word = "malicious" if (vt_verdict == "malicious" or anyrun_verdict == "malicious") else "suspicious"
                if ai_narrative:
                    lines.append(
                        f"- One {verdict_word} attachment was found within the email body (.{ext}). "
                        f"{ai_narrative}"
                    )
                else:
                    lines.append(
                        f"- One {verdict_word} attachment was found within the email body (.{ext}). "
                        f"{source} flagged it as {verdict_word} "
                        f"(malicious={vt.get('malicious_count', 0)}, suspicious={vt.get('suspicious_count', 0)})."
                    )
            else:
                lines.append(
                    f"- The attachment in the email body (.{ext}) was found to be safe "
                    f"(VirusTotal: {vt_verdict})."
                )

    # ── URL bullet — single consolidated line ──────────────────────
    url_items = checks.get("urls") or []
    _RISKY = {"malicious", "suspicious"}
    ai_url_summary = str(resolution.get("url_summary") or "").strip()

    if not url_items:
        lines.append("- No URLs were found in the email body.")
    elif ai_url_summary:
        # AI provided a human-readable summary — use it directly, no count prefix
        lines.append(f"- {ai_url_summary}")
    else:
        # Fallback: build from deterministic data
        total_urls = len(url_items)
        risky_urls = [
            u for u in url_items
            if isinstance(u, dict) and (
                str(u.get("effective_verdict") or "").lower() in _RISKY
                or str((u.get("vt") or {}).get("verdict") or "").lower() in _RISKY
                or str((u.get("anyrun") or {}).get("verdict") or "").lower() in _RISKY
                or bool((u.get("url_behavior") or {}).get("credential_form_present"))
            )
        ]
        if risky_urls:
            risky_count = len(risky_urls)
            has_cred = any(
                bool((u.get("url_behavior") or {}).get("credential_form_present"))
                for u in risky_urls
            )
            cred_note = " A credential input form was detected at one of the destinations." if has_cred else ""
            lines.append(
                f"- {total_urls} URL(s) were found in the email body. "
                f"{risky_count} of them {'was' if risky_count == 1 else 'were'} found suspicious or malicious.{cred_note}"
            )
        else:
            lines.append(
                f"- {total_urls} URL(s) were found in the email body. "
                f"All were checked and no suspicious or malicious URLs were identified."
            )

    return "\n".join(lines)


def _build_sender_line(
    *,
    sender_email: str,
    sender_classification: str,
    company_name: str,
    domain_description: str,
) -> str:
    if sender_classification == "unknown" and company_name != NOT_PRESENT:
        return (
            f"The sender's email address {sender_email} appears associated with "
            f"{company_name} ({domain_description})."
        )
    if company_name == NOT_PRESENT and domain_description == NOT_PRESENT:
        return (
            f"The sender's email address {sender_email} is {sender_classification}. "
            f"Domain/company context: {NOT_PRESENT}."
        )
    return (
        f"The sender's email address {sender_email} is {sender_classification} and belongs to "
        f"{company_name} ({domain_description})."
    )


def _normalize_sender_legitimacy(classification: str) -> str:
    normalized = classification.strip().lower()
    if normalized in {"benign", "legitimate", "clean"}:
        return "legitimate"
    if normalized in {"malicious", "suspicious"}:
        return "suspicious"
    return "unknown"


def _infer_sender_company_and_description(
    *,
    extracted: dict[str, Any],
    checks: dict[str, Any],
    resolution: dict[str, Any],
) -> tuple[str, str]:
    sender_company = resolution.get("sender_company") or {}
    ai_name = str(sender_company.get("name") or "").strip()
    ai_desc = str(sender_company.get("description") or "").strip()
    sender_domain_check = checks.get("sender_domain") or {}
    whois = sender_domain_check.get("whois") or {}
    registrant_org = str(whois.get("registrant_org") or "").strip()
    sender_email = str(extracted.get("sender_email") or "").strip().lower()
    sender_email_domain = sender_email.split("@", 1)[1] if "@" in sender_email else ""
    query_domain = str(
        sender_domain_check.get("query_domain")
        or extracted.get("sender_domain")
        or sender_email_domain
        or ""
    ).strip()
    normalized_domain = normalize_domain(query_domain) if query_domain else ""
    registered_domain = (
        extract_registered_domain(normalized_domain) if normalized_domain else ""
    )
    known_name, known_desc = _known_company_profile(registered_domain or normalized_domain)

    if ai_name and not _is_not_present_value(ai_name):
        if ai_desc and not _is_weak_domain_description(ai_desc):
            return ai_name, ai_desc
        if known_desc:
            return ai_name, known_desc
        return ai_name, _generic_sender_domain_description(
            registered_domain or normalized_domain,
            checks=checks,
        )
    if known_name:
        return known_name, known_desc

    if registrant_org:
        desc_parts = []
        registrar = str(whois.get("registrar") or "").strip()
        country = str(whois.get("registrant_country") or "").strip()
        if registrar:
            desc_parts.append(f"registrar {registrar}")
        if country:
            desc_parts.append(f"registrant country {country}")
        description = ", ".join(desc_parts) if desc_parts else "WHOIS registrant organization"
        return registrant_org, description

    if normalized_domain:
        company = _company_from_domain(registered_domain or normalized_domain)
        return company, _generic_sender_domain_description(
            registered_domain or normalized_domain,
            checks=checks,
        )

    return NOT_PRESENT, NOT_PRESENT


def _company_from_domain(domain: str) -> str:
    lowered = domain.lower()
    known = {
        "microsoft.com": "Microsoft",
        "google.com": "Google",
        "amazon.com": "Amazon",
        "apple.com": "Apple",
        "w3.org": "World Wide Web Consortium (W3C)",
        "j2.email": "j2 Global",
    }
    for suffix, company in known.items():
        if lowered == suffix or lowered.endswith(f".{suffix}"):
            return company

    base = lowered.split(".")[0].replace("-", " ").strip()
    if not base:
        return NOT_PRESENT
    return " ".join(part.capitalize() for part in base.split())


def _known_company_profile(domain: str) -> tuple[str, str]:
    lowered = (domain or "").lower().strip()
    profiles: dict[str, tuple[str, str]] = {
        "j2.net": (
            "j2 Global (Ziff Davis)",
            "legitimate corporate domain associated with j2 Global (now part of Ziff Davis), focused on cloud communications and digital services",
        ),
        "j2.email": (
            "j2 Global (Ziff Davis)",
            "email campaign and routing infrastructure associated with j2 Global marketing operations",
        ),
        "w3.org": (
            "World Wide Web Consortium (W3C)",
            "standards organization domain used for web specifications and technical resources",
        ),
        "caseware.com": (
            "Caseware",
            "legitimate software company focused on audit, financial reporting, and analytics solutions",
        ),
        "em.caseware.com": (
            "Caseware",
            "email campaign/sending infrastructure associated with Caseware communications",
        ),
    }
    for suffix, value in profiles.items():
        if lowered == suffix or lowered.endswith(f".{suffix}"):
            return value
    return "", ""


def _summarize_ip_result(ip_result: dict[str, Any]) -> str:
    vt = ip_result.get("vt") or {}
    verdict = str(vt.get("verdict") or "unknown").lower()
    malicious = int(vt.get("malicious_count") or 0)
    suspicious = int(vt.get("suspicious_count") or 0)
    total = int(vt.get("total_vendors") or 0)

    if verdict == "clean":
        return "nothing suspicious was found"
    if verdict in {"suspicious", "malicious"}:
        return f"it was flagged as {verdict} by VirusTotal ({malicious} out of {total} engines)"
    return "its reputation could not be confidently established"


def _summarize_attachments(checks: dict[str, Any]) -> tuple[str, str]:
    attachments = checks.get("attachments") or {}
    items = attachments.get("items") or []
    if not items:
        return NOT_PRESENT, "no_attachments"

    types: list[str] = []
    malicious_like = 0
    clean_like = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        filename = str(item.get("filename") or "").strip()
        if "." in filename:
            types.append(filename.rsplit(".", 1)[-1].lower())
        vt = item.get("vt") or {}
        verdict = str(vt.get("verdict") or "unknown").lower()
        if verdict in {"malicious", "suspicious"}:
            malicious_like += 1
        elif verdict == "clean":
            clean_like += 1

    attachment_types = ", ".join(sorted(set(types))) if types else "unknown"
    if malicious_like > 0:
        return attachment_types, "malicious"
    if clean_like > 0 and malicious_like == 0:
        return attachment_types, "safe"
    return attachment_types, "unknown"


def _decode_header_text(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return raw
    try:
        parts: list[str] = []
        for chunk, charset in decode_header(raw):
            if isinstance(chunk, bytes):
                parts.append(chunk.decode(charset or "utf-8", errors="replace"))
            else:
                parts.append(str(chunk))
        return "".join(parts).strip()
    except Exception:
        return raw


def _summarize_urls(checks: dict[str, Any], resolution: dict[str, Any]) -> tuple[str, str]:
    items = checks.get("urls") or []
    if not items:
        return NOT_PRESENT, NOT_PRESENT

    destinations: list[str] = []
    suspicious_urls: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        vt = item.get("vt") or {}
        lexical = item.get("lexical_ml") or {}
        ss = item.get("screenshot") or {}
        verdict = str(vt.get("verdict") or "unknown").lower()
        lexical_label = str(lexical.get("label") or "unknown").lower()
        final_url = str(ss.get("final_url") or item.get("url") or NOT_PRESENT)
        if final_url and final_url != NOT_PRESENT:
            destinations.append(final_url)
        if verdict in {"suspicious", "malicious"} or lexical_label in {"high", "medium"}:
            suspicious_urls.append(str(item.get("url") or final_url))

    summary = _summarize_url_destinations(items)

    if suspicious_urls:
        chosen = suspicious_urls[0]
        assessment = f"be suspicious and should be treated as potentially unsafe ({chosen})"
    else:
        url_assessments = resolution.get("url_assessments") or []
        first = next((u for u in url_assessments if isinstance(u, dict)), None)
        if first:
            assessment = str(first.get("reasoning") or NOT_PRESENT)
        else:
            assessment = NOT_PRESENT
    return summary, assessment


def _summarize_url_destinations(items: list[dict[str, Any]]) -> str:
    if not items:
        return NOT_PRESENT

    counters = {
        "email_tracking": 0,
        "brevo_tracking": 0,
        "salesforce_tracking": 0,
        "outlook_safelinks": 0,
        "w3c_dtd": 0,
        "w3c_standards": 0,
    }
    domains_seen: dict[str, int] = {}
    for item in items:
        target_raw = str(((item.get("screenshot") or {}).get("final_url") or item.get("url") or "")).strip()
        if not target_raw:
            continue
        target = target_raw.lower()
        if "manage.j2.email" in target or "/t/j-" in target:
            counters["email_tracking"] += 1
        elif "sendibm3.com" in target or "sendinblue.com" in target or "brevo.com" in target:
            counters["brevo_tracking"] += 1
        elif "tracking.e360.salesforce.com" in target or ".salesforce.com/" in target:
            counters["salesforce_tracking"] += 1
        elif "safelinks.protection.outlook.com" in target:
            counters["outlook_safelinks"] += 1
        elif "w3.org/tr/" in target and ("dtd" in target or "xhtml1-transitional.dtd" in target):
            counters["w3c_dtd"] += 1
        elif "w3.org/" in target:
            counters["w3c_standards"] += 1
        # Parse domains from both the original URL and final URL to capture wrapped destinations.
        for source in {
            str(item.get("url") or "").strip(),
            target_raw,
        }:
            if not source:
                continue
            for domain in _domains_from_target_url(source):
                domains_seen[domain] = domains_seen.get(domain, 0) + 1

    parts: list[str] = []
    if counters["email_tracking"]:
        parts.append(
            "email tracking/campaign-routing infrastructure (j2.email)"
        )
    if counters["brevo_tracking"]:
        parts.append(
            "Brevo/Sendinblue campaign redirect or tracking infrastructure"
        )
    if counters["salesforce_tracking"]:
        parts.append(
            "Salesforce Marketing Cloud campaign redirect/tracking infrastructure"
        )
    if counters["outlook_safelinks"]:
        parts.append(
            "Microsoft Defender Safe Links rewriting infrastructure"
        )
    if counters["w3c_dtd"]:
        parts.append(
            "W3C XHTML/HTML DTD technical resources used by markup templates"
        )
    if counters["w3c_standards"]:
        parts.append(
            "W3C standards resources"
        )

    if domains_seen:
        described = []
        for domain, count in sorted(domains_seen.items(), key=lambda kv: kv[1], reverse=True)[:8]:
            described.append(f"{domain} ({_describe_destination_domain(domain)})")
        parts.append("Destinations observed: " + "; ".join(described))

    if not parts:
        return NOT_PRESENT
    return "; ".join(parts)


def _is_not_present_value(value: str) -> bool:
    return value.strip().lower().rstrip(".") == NOT_PRESENT.lower().rstrip(".")


def _short_error(error: str) -> str:
    text = (error or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if "401" in lowered and "unauthorized" in lowered:
        return "Unauthorized (401)"
    if "403" in lowered and "forbidden" in lowered:
        return "Forbidden (403)"
    if "429" in lowered:
        return "Rate limited (429)"
    if "timeout" in lowered:
        return "Request timeout"
    if ":" in text:
        return text.split(":", 1)[0].strip()
    return text


def _is_weak_domain_description(text: str) -> bool:
    value = (text or "").strip().lower()
    if not value:
        return True
    if _is_not_present_value(value):
        return True
    weak_markers = [
        "domain appears tied to",
        "not enough evidence",
        "unknown",
        "whois",
        "registrar",
        "registrant",
        "identity protection",
        "domain created",
        "registration",
    ]
    return any(marker in value for marker in weak_markers)


def _generic_sender_domain_description(domain: str, *, checks: dict[str, Any]) -> str:
    if not domain:
        return NOT_PRESENT
    lowered = domain.lower()
    if lowered.endswith(".org"):
        base = "organization domain likely used for brand communications, informational pages, or outreach campaigns"
    elif lowered.endswith(".edu"):
        base = "education-sector domain likely associated with an academic institution"
    elif lowered.endswith(".gov"):
        base = "government domain used by a public-sector entity"
    else:
        base = f"business/organizational domain associated with {lowered}"

    url_items = checks.get("urls") or []
    has_campaign_links = any(
        isinstance(item, dict)
        and "sendibm3.com" in str(((item.get("screenshot") or {}).get("final_url") or item.get("url") or "")).lower()
        for item in url_items
    )
    if has_campaign_links:
        return base + ", with evidence of email-campaign delivery links in the message"
    return base


def _extract_registered_domain_from_url(url_text: str) -> str:
    try:
        parsed = urlparse(url_text)
        host = (parsed.netloc or parsed.path or "").strip().lower()
        if ":" in host:
            host = host.split(":", 1)[0]
        if not host:
            return ""
        host = re.sub(r"[^a-z0-9.\-]", "", host)
        host = normalize_domain(host)
        return extract_registered_domain(host)
    except Exception:
        return ""


def _domains_from_target_url(url_text: str) -> list[str]:
    domains: list[str] = []
    primary = _extract_registered_domain_from_url(url_text)
    if primary:
        domains.append(primary)

    try:
        parsed = urlparse(url_text)
        query = parse_qs(parsed.query or "", keep_blank_values=True)
        redirect_keys = {"url", "u", "target", "redirect", "redirect_url", "destination", "dest"}
        jwt_keys = {"jwt", "correlation", "cstoken", "token"}
        for key in redirect_keys:
            for value in query.get(key, []):
                if not value:
                    continue
                decoded = unquote(str(value))
                nested = _extract_registered_domain_from_url(decoded)
                if nested:
                    domains.append(nested)
        for key in jwt_keys:
            for value in query.get(key, []):
                for nested_url in _extract_urls_from_jwt_value(str(value)):
                    nested = _extract_registered_domain_from_url(nested_url)
                    if nested:
                        domains.append(nested)
    except Exception:
        pass

    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _extract_urls_from_jwt_value(token: str) -> list[str]:
    """
    Best-effort decode of JWT payloads used in tracking links.
    Extracts redirect_url/url-like fields without signature validation.
    """
    value = (token or "").strip()
    if value.count(".") < 2:
        return []
    parts = value.split(".")
    payload_part = parts[1]
    # Base64URL padding
    payload_part += "=" * ((4 - len(payload_part) % 4) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_part.encode("ascii", errors="ignore"))
        payload_obj = json.loads(payload_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        return []

    out: list[str] = []
    if not isinstance(payload_obj, dict):
        return out
    for key in ("redirect_url", "url", "target", "destination"):
        v = payload_obj.get(key)
        if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
            out.append(v)
    return out


def _compact_suspicious_checks_for_ai(checks: dict[str, Any]) -> dict[str, Any]:
    """
    Build a compact AI payload containing ONLY suspicious/malicious URLs and attachments.
    Clean items are excluded — they add tokens without analytical value.
    """
    _RISKY = {"malicious", "suspicious"}

    sender_domain = checks.get("sender_domain") or {}
    whois = sender_domain.get("whois") or {}

    # Filter URLs: include if effective_verdict is risky, OR if lexical/behavior signals are strong
    suspicious_urls: list[dict[str, Any]] = []
    for item in checks.get("urls") or []:
        if not isinstance(item, dict):
            continue
        ev = str(item.get("effective_verdict") or "").lower()
        vt_v = str((item.get("vt") or {}).get("verdict") or "").lower()
        anyrun_v = str((item.get("anyrun") or {}).get("verdict") or "").lower()
        anyrun_score = float((item.get("anyrun") or {}).get("threat_score") or 0)
        lexical_label = str((item.get("lexical_ml") or {}).get("label") or "").lower()
        cred_form = bool((item.get("url_behavior") or {}).get("credential_form_present"))
        # Only treat AnyRun "malicious" as a risky signal if threat_score >= 95
        # Below that threshold it is treated as suspicious (cross-validation with VT required)
        anyrun_is_risky = anyrun_v in _RISKY and (anyrun_v != "malicious" or anyrun_score >= 95)
        if ev in _RISKY or vt_v in _RISKY or anyrun_is_risky or cred_form:
            vt = item.get("vt") or {}
            anyrun = item.get("anyrun") or {}
            ss = item.get("screenshot") or {}
            lexical = item.get("lexical_ml") or {}
            behavior = item.get("url_behavior") or {}
            suspicious_urls.append(
                {
                    "url": item.get("url"),
                    "effective_verdict": ev or vt_v or anyrun_v or "unknown",
                    "vt": {
                        "verdict": vt.get("verdict"),
                        "malicious_count": vt.get("malicious_count"),
                        "suspicious_count": vt.get("suspicious_count"),
                        "total_vendors": vt.get("total_vendors"),
                    },
                    "anyrun": {
                        "checked": anyrun.get("checked"),
                        "verdict": anyrun.get("verdict"),
                        "threat_score": anyrun.get("threat_score"),
                    },
                    "final_url": ss.get("final_url") or behavior.get("final_url"),
                    "lexical_ml": {"label": lexical.get("label"), "score": lexical.get("score")},
                    "url_behavior": {
                        "redirect_count": behavior.get("redirect_count"),
                        "credential_form_present": behavior.get("credential_form_present"),
                        "ua_cloaking_detected": behavior.get("ua_cloaking_detected"),
                        "unique_domains_in_chain": (behavior.get("unique_domains_in_chain") or [])[:5],
                    },
                }
            )

    # Filter attachments: include if VT or AnyRun flagged it
    suspicious_atts: list[dict[str, Any]] = []
    for att in (checks.get("attachments") or {}).get("items") or []:
        if not isinstance(att, dict):
            continue
        vt_v = str((att.get("vt") or {}).get("verdict") or "").lower()
        anyrun_v = str((att.get("anyrun") or {}).get("verdict") or "").lower()
        static_risk = str(((checks.get("attachment_analysis") or {}).get("items") or []))
        if vt_v in _RISKY or anyrun_v in _RISKY:
            vt = att.get("vt") or {}
            anyrun = att.get("anyrun") or {}
            suspicious_atts.append(
                {
                    "filename": att.get("filename"),
                    "sha256": att.get("sha256"),
                    "vt": {
                        "verdict": vt.get("verdict"),
                        "malicious_count": vt.get("malicious_count"),
                        "suspicious_count": vt.get("suspicious_count"),
                        "total_vendors": vt.get("total_vendors"),
                    },
                    "anyrun": {
                        "checked": anyrun.get("checked"),
                        "verdict": anyrun.get("verdict"),
                        "threat_score": anyrun.get("threat_score"),
                    },
                }
            )

    sender_ip = checks.get("sender_ip") or {}
    ip_vt = sender_ip.get("vt") or {}
    return {
        "sender_domain": {
            "domain": sender_domain.get("domain"),
            "whois": {
                "registrar": whois.get("registrar"),
                "created_date": whois.get("created_date"),
                "domain_age_days": whois.get("domain_age_days"),
                "statuses": whois.get("statuses") or [],
                "registrant_org": whois.get("registrant_org"),
                "registrant_country": whois.get("registrant_country"),
            },
        },
        "sender_ip": {
            "ip": sender_ip.get("ip"),
            "vt": {
                "verdict": ip_vt.get("verdict"),
                "malicious_count": ip_vt.get("malicious_count"),
                "suspicious_count": ip_vt.get("suspicious_count"),
                "total_vendors": ip_vt.get("total_vendors"),
            },
            "abuseipdb": sender_ip.get("abuseipdb"),
        },
        "suspicious_urls": suspicious_urls,
        "suspicious_attachments": suspicious_atts,
        # All unique URL domains (not full URLs) — used by AI to write url_summary
        "all_url_domains": list(dict.fromkeys(
            str((item.get("vt") or {}).get("url") or item.get("url") or "")
            .split("/")[2].split(":")[0].lower()
            for item in (checks.get("urls") or [])
            if isinstance(item, dict) and item.get("url")
        )),
        "content_ml": checks.get("content_ml") or {},
        "email_anyrun": checks.get("email_anyrun") or {},
        "final_risk": checks.get("final_risk") or {},
    }


def _compact_email_security_for_ai(es: dict[str, Any]) -> dict[str, Any]:
    """Extract key email security signals for the AI payload."""
    if not es or es.get("checked") is False:
        return {"available": False}
    return {
        "available": True,
        "dmarc_policy": es.get("dmarc_policy"),
        "dmarc_record": es.get("dmarc_record"),
        "spf_record": es.get("spf_record"),
        "spf_all_qualifier": es.get("spf_all_qualifier"),
        "dkim_selectors_found": es.get("dkim_selectors_found") or [],
        "spoofability_score": es.get("spoofability_score"),
        "spoofability_reasons": es.get("spoofability_reasons") or [],
        "email_security_score": es.get("email_security_score"),
        "mx_blocklist_hits": sum(
            len(mx.get("blocklist_hits") or [])
            for mx in (es.get("mx_records") or [])
            if isinstance(mx, dict)
        ),
    }


def _deterministic_overall_verdict(checks: dict[str, Any]) -> tuple[str, list[str]]:
    """Compute an overall verdict from deterministic check results when AI is unavailable."""
    signals: list[str] = []
    verdict = "inconclusive"

    # Attachment VT malicious → definitive malicious
    for att in (checks.get("attachments") or {}).get("items") or []:
        vt = (att or {}).get("vt") or {}
        if int(vt.get("malicious_count") or 0) > 0:
            signals.append(f"Attachment VT malicious ({vt.get('malicious_count')} engines)")
            verdict = "malicious"
        anyrun = (att or {}).get("anyrun") or {}
        if str(anyrun.get("verdict") or "").lower() == "malicious":
            signals.append("AnyRun hash verdict: malicious")
            verdict = "malicious"

    # AnyRun email-level verdict
    email_anyrun = checks.get("email_anyrun") or {}
    anyrun_v = str(email_anyrun.get("verdict") or "").lower()
    if anyrun_v == "malicious":
        signals.append("AnyRun email verdict: malicious")
        verdict = "malicious"
    elif anyrun_v == "suspicious" and verdict != "malicious":
        signals.append("AnyRun email verdict: suspicious")
        verdict = "suspicious"

    # URL signals
    for url_item in checks.get("urls") or []:
        if not isinstance(url_item, dict):
            continue
        ev = str(url_item.get("effective_verdict") or "").lower()
        url_val = str(url_item.get("url") or "")[:60]
        if ev == "malicious" and verdict != "malicious":
            signals.append(f"URL verdict malicious: {url_val}")
            verdict = "malicious"
        elif ev == "suspicious" and verdict not in {"malicious"}:
            signals.append(f"URL verdict suspicious: {url_val}")
            if verdict == "inconclusive":
                verdict = "suspicious"
        behavior = url_item.get("url_behavior") or {}
        if behavior.get("credential_form_present"):
            signals.append(f"Credential form detected on URL: {url_val}")
            if verdict == "inconclusive":
                verdict = "suspicious"

    # Email security
    es = checks.get("email_security") or {}
    spf_all = str(es.get("spf_all_qualifier") or "").lower()
    dmarc_policy = str(es.get("dmarc_policy") or "").lower()
    spoofability = str(es.get("spoofability_score") or "").lower()
    if spoofability == "high" and _email_security_has_concrete_auth_failure(es):
        signals.append(f"Domain spoofability: HIGH (DMARC={dmarc_policy or 'none'}, SPF={spf_all or 'none'})")
        if verdict == "inconclusive":
            verdict = "suspicious"

    # Domain age
    age_days = (checks.get("sender_domain") or {}).get("whois", {}).get("domain_age_days")
    if isinstance(age_days, int) and age_days < 30:
        signals.append(f"Sender domain age: {age_days} days (newly registered)")
        if verdict == "inconclusive":
            verdict = "suspicious"

    # Content ML
    content_ml = checks.get("content_ml") or {}
    social_prob = float(content_ml.get("social_engineering_probability") or 0.0)
    urgency_prob = float(content_ml.get("urgency_probability") or 0.0)
    if social_prob > 0.7:
        signals.append(f"Content ML social engineering probability: {social_prob:.2f}")
        if verdict == "inconclusive":
            verdict = "suspicious"
    elif urgency_prob > 0.8:
        signals.append(f"Content ML urgency probability: {urgency_prob:.2f}")
        if verdict == "inconclusive":
            verdict = "suspicious"

    # Final risk
    final_risk = checks.get("final_risk") or {}
    risk_level = str(final_risk.get("risk_level") or "").lower()
    if not signals and risk_level in {"high", "critical"}:
        signals.append(f"Aggregate risk score: {risk_level}")
        verdict = "suspicious"

    if not signals:
        if _has_positive_clean_evidence(checks):
            verdict = "clean"
            signals.append("Checked URLs, attachments, sandbox, or reputation sources returned clean results.")
        else:
            verdict = "inconclusive"

    return verdict, signals[:5]


def _describe_destination_domain(domain: str) -> str:
    lowered = (domain or "").lower()
    known = {
        "sendibm3.com": "Brevo/Sendinblue email campaign infrastructure",
        "sendinblue.com": "Brevo/Sendinblue email campaign infrastructure",
        "brevo.com": "Brevo email marketing platform",
        "salesforce.com": "Salesforce cloud and marketing infrastructure",
        "salesforce-experience.com": "Salesforce Experience Cloud hosted content",
        "e360.salesforce.com": "Salesforce Marketing Cloud tracking infrastructure",
        "outlook.com": "Microsoft Outlook-related destination",
        "protection.outlook.com": "Microsoft Defender Safe Links rewriting infrastructure",
        "caseware.com": "Caseware corporate website and resources",
        "w3.org": "W3C standards and technical documentation resources",
        "j2.email": "email routing/tracking infrastructure tied to j2 campaigns",
    }
    for suffix, desc in known.items():
        if lowered == suffix or lowered.endswith(f".{suffix}"):
            return desc
    if lowered.endswith(".org"):
        return "organizational website/resources"
    if lowered.endswith(".gov"):
        return "government/public-sector destination"
    if lowered.endswith(".edu"):
        return "education/academic destination"
    return "general web destination"


def _email_security_has_concrete_auth_failure(email_security: dict[str, Any]) -> bool:
    if not isinstance(email_security, dict):
        return False
    values = [
        str(email_security.get("spf_result") or "").lower(),
        str(email_security.get("dkim_result") or "").lower(),
        str(email_security.get("dmarc_result") or "").lower(),
        str(email_security.get("spf_all_qualifier") or "").lower(),
        str(email_security.get("dmarc_policy") or "").lower(),
    ]
    return any(value in {"fail", "softfail", "permerror", "temperror", "+all"} for value in values)


def _has_positive_clean_evidence(checks: dict[str, Any]) -> bool:
    """True when at least one meaningful detector actually ran and returned clean."""
    email_anyrun = checks.get("email_anyrun") or {}
    if email_anyrun.get("checked") and str(email_anyrun.get("verdict") or "").lower() == "clean":
        return True

    for item in checks.get("urls") or []:
        if not isinstance(item, dict):
            continue
        verdicts = {
            str(item.get("effective_verdict") or "").lower(),
            str((item.get("vt") or {}).get("verdict") or "").lower(),
            str((item.get("anyrun") or {}).get("verdict") or "").lower(),
            str((item.get("urlscan") or {}).get("verdict") or "").lower(),
        }
        if "clean" in verdicts:
            return True

    for att in (checks.get("attachments") or {}).get("items") or []:
        if not isinstance(att, dict):
            continue
        verdicts = {
            str((att.get("vt") or {}).get("verdict") or "").lower(),
            str((att.get("anyrun") or {}).get("verdict") or "").lower(),
            str((att.get("hybrid_analysis") or {}).get("verdict") or "").lower(),
        }
        if "clean" in verdicts:
            return True

    for section_name in ("sender_domain", "sender_ip"):
        section = checks.get(section_name) or {}
        verdicts = {
            str((section.get("vt") or {}).get("verdict") or "").lower(),
            str((section.get("urlscan") or {}).get("verdict") or "").lower(),
        }
        if "clean" in verdicts:
            return True

    final_risk = checks.get("final_risk") or {}
    risk_level = str(final_risk.get("risk_level") or final_risk.get("verdict") or "").lower()
    if risk_level in {"clean", "low"} and (
        final_risk.get("risk_score") is not None or final_risk.get("score") is not None
    ):
        return True

    return False


def _infer_url_purpose(items: list[dict[str, Any]]) -> str:
    purpose_counts: dict[str, int] = {
        "email tracking or campaign-routing links": 0,
        "standards or technical documentation resources": 0,
        "general web destinations": 0,
    }
    for item in items:
        url = str(item.get("url") or "").lower()
        final_url = str(((item.get("screenshot") or {}).get("final_url") or "")).lower()
        target = f"{url} {final_url}"
        if "manage.j2.email" in target or "/t/j-" in target:
            purpose_counts["email tracking or campaign-routing links"] += 1
        elif "w3.org/tr/" in target or "xhtml" in target or "dtd" in target:
            purpose_counts["standards or technical documentation resources"] += 1
        else:
            purpose_counts["general web destinations"] += 1

    best = max(purpose_counts, key=purpose_counts.get)
    if purpose_counts[best] <= 0:
        return NOT_PRESENT
    return best
