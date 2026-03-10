"""Email investigation processing helpers shared by API and Celery tasks."""

from __future__ import annotations

import asyncio
from typing import Any
import base64
import json
import re
from email.header import decode_header
from urllib.parse import parse_qs, unquote, urlparse

from app.services.email_ai_interpreter_service import interpret_email_results_with_ai
from app.services.email_indicator_checks_service import run_email_indicator_checks
from app.services.email_ioc_service import extract_email_iocs
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
    run_ai: bool = True,
    ml_phishing_score: str | None = None,
) -> dict[str, Any]:
    extracted = extract_email_iocs(payload, filename=filename)

    checks = await asyncio.to_thread(
        run_email_indicator_checks,
        extracted,
        include_url_screenshots=include_url_screenshots,
        max_urls=max_urls,
        max_attachment_hashes=max_attachment_hashes,
    )

    parsed_ml_score: float | None = None
    if ml_phishing_score not in (None, ""):
        try:
            parsed_ml_score = float(ml_phishing_score)
        except ValueError:
            parsed_ml_score = None

    interpretation_payload = {
        "email_subject": extracted.get("email_subject"),
        "sender_email": extracted.get("sender_email"),
        "sender_domain": extracted.get("sender_domain"),
        "sender_ip": extracted.get("sender_ip"),
        "authentication": extracted.get("authentication"),
        "urls": extracted.get("urls") or [],
        "url_domains": extracted.get("url_domains") or [],
        "attachments": extracted.get("attachments") or [],
        "indicator_checks": _compact_checks_for_ai(checks),
        "context": context or None,
        "ml_phishing_score": parsed_ml_score,
    }

    if run_ai:
        try:
            resolution = await interpret_email_results_with_ai(interpretation_payload)
            resolution["url_assessments"] = _merge_url_assessments(
                ai_items=resolution.get("url_assessments"),
                checks=checks,
            )
            if not isinstance(resolution.get("sender_domain_analysis"), dict):
                resolution["sender_domain_analysis"] = _sender_domain_fallback(
                    extracted=extracted,
                    checks=checks,
                    reason="AI response did not include sender-domain analysis.",
                    classification="unknown",
                )
            resolution_source = "ai"
        except Exception as exc:  # pragma: no cover - fallback path
            resolution = {
                "formatted_resolution": (
                    "AI interpretation failed. Not present in the provided evidence.\n"
                    f"Error: {type(exc).__name__}: {exc}"
                ),
                "url_assessments": _build_url_assessments_fallback(checks),
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
            "formatted_resolution": f"AI interpretation disabled. {NOT_PRESENT}",
            "url_assessments": _build_url_assessments_fallback(checks),
            "sender_domain_analysis": _sender_domain_fallback(
                extracted=extracted,
                checks=checks,
                reason="AI interpretation disabled for this run.",
                classification="unknown",
            ),
        }
        resolution_source = "disabled"

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
                "screenshot": ss,
            }
        )
    checks["urls"] = urls

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
                "urlscan": item.get("urlscan") or {},
                "lexical_ml": {
                    "target_url": lexical.get("target_url"),
                    "model_source": lexical.get("model_source"),
                    "score": lexical.get("score"),
                    "label": lexical.get("label"),
                    "top_features": lexical.get("top_features") or [],
                    "error": lexical.get("error"),
                },
                "screenshot": {
                    "captured": ss.get("captured"),
                    "final_url": ss.get("final_url"),
                    "error": ss.get("error"),
                },
            }
        )

    attachments = checks.get("attachments") or {}
    att_items = []
    for att in attachments.get("items") or []:
        vt = att.get("vt") or {}
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
    email_subject = _decode_header_text(str(extracted.get("email_subject") or NOT_PRESENT))
    sender_email = str(extracted.get("sender_email") or NOT_PRESENT)
    sender_domain_analysis = resolution.get("sender_domain_analysis") or {}
    sender_classification = _normalize_sender_legitimacy(
        str(sender_domain_analysis.get("classification") or "unknown")
    )
    company_name, domain_description = _infer_sender_company_and_description(
        extracted=extracted,
        checks=checks,
        resolution=resolution,
    )

    sender_ip = str(extracted.get("sender_ip") or NOT_PRESENT)
    ip_result = checks.get("sender_ip") or {}
    abuse = ip_result.get("abuseipdb") or {}
    ipwhois = ip_result.get("ipwhois") or {}
    abuse_error = str(abuse.get("error") or "").strip()
    abuse_error_short = _short_error(abuse_error)
    isp = str(abuse.get("isp") or abuse.get("asn_org") or ipwhois.get("isp") or ipwhois.get("org") or "").strip()
    usage_type = str(abuse.get("usage_type") or abuse.get("usageType") or "").strip()
    if not usage_type and ipwhois.get("checked"):
        usage_type = "Inferred network/service provider (ipwho.is)"
    if not isp:
        isp = f"Unavailable ({abuse_error_short})" if abuse_error_short else NOT_PRESENT
    if not usage_type:
        usage_type = f"Unavailable ({abuse_error_short})" if abuse_error_short else NOT_PRESENT
    ip_summary = _summarize_ip_result(ip_result)

    attachment_types, attachment_verdict = _summarize_attachments(checks)
    url_summary, _ = _summarize_urls(checks, resolution)
    attachments_line = (
        "No attachments present in the email body."
        if attachment_verdict == "no_attachments"
        else (
            f"The attachments present in the email body ({attachment_types}) were found to be "
            f"{attachment_verdict}."
        )
    )

    lines = [
        f'Email subject: "{email_subject}"',
        "",
        "After our investigation, we found:",
        "",
        _build_sender_line(
            sender_email=sender_email,
            sender_classification=sender_classification,
            company_name=company_name,
            domain_description=domain_description,
        ),
        (
            f"The sender's IP address {sender_ip} (ISP: {isp}, Usage Type: {usage_type}) "
            f"was checked and {ip_summary}."
        ),
        attachments_line,
        f"URL destinations: {url_summary}.",
    ]

    findings = sender_domain_analysis.get("findings")
    if isinstance(findings, list) and findings:
        lines.append("")
        lines.append("Additional findings:")
        for finding in findings[:4]:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "Finding")
            description = str(finding.get("description") or NOT_PRESENT)
            lines.append(f"- {title}: {description}")
    else:
        lines.append("")
        lines.append(f"Additional findings: {NOT_PRESENT}")

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
        return f"VirusTotal marked it clean ({malicious} malicious, {suspicious} suspicious out of {total} engines)"
    if verdict in {"suspicious", "malicious"}:
        return f"VirusTotal marked it {verdict} ({malicious} malicious, {suspicious} suspicious out of {total} engines)"
    return "its reputation could not be confidently established by VirusTotal"


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
