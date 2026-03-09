"""
Email investigation intake endpoints.

Design:
- Extract indicators from uploaded .eml/.msg
- Run lightweight checks only:
  - URLs -> VT (+ optional screenshot/final URL)
  - IP -> VT + AbuseIPDB
  - attachments -> hash + VT
- Call AI once at the final phase to interpret the aggregated results
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from urllib.parse import urlparse
import uuid
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Path, Query, UploadFile
from sqlalchemy import select

from app.dependencies import DBSession
from app.models.database import EmailInvestigationRun
from app.services.email_ai_interpreter_service import interpret_email_results_with_ai
from app.services.email_indicator_checks_service import run_email_indicator_checks
from app.services.email_ioc_service import extract_email_iocs

router = APIRouter(prefix="/api/email-investigations", tags=["email-investigations"])
logger = logging.getLogger(__name__)
NOT_PRESENT = "Not present in the provided evidence."


@router.get("/upload")
async def email_upload_info() -> dict[str, Any]:
    return {
        "message": "Use POST multipart/form-data with field 'file' (.eml or .msg).",
        "supported_methods": ["POST"],
        "endpoint": "/api/email-investigations/upload",
    }


@router.post("/upload")
async def upload_email_investigation(
    db: DBSession,
    file: UploadFile = File(...),
    context: str = Form(default=""),
    max_urls: int = Form(default=20),
    max_attachment_hashes: int = Form(default=5),
    include_url_screenshots: bool = Form(default=True),
    run_ai: bool = Form(default=True),
    ml_phishing_score: str | None = Form(default=None),
) -> dict[str, Any]:
    """
    Upload an email file and return structured investigation result.
    """
    name = (file.filename or "").strip()
    lowered = name.lower()
    if not (lowered.endswith(".eml") or lowered.endswith(".msg")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Supported types: .eml, .msg",
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded email file is empty.")

    try:
        extracted = extract_email_iocs(payload, filename=name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        "url_destination_context": _build_url_destination_context(checks),
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
            resolution["formatted_resolution"] = _render_email_template_resolution(
                extracted=extracted,
                checks=checks,
                url_destination_context=interpretation_payload.get("url_destination_context"),
                resolution=resolution,
            )
            resolution_source = "ai"
        except Exception as exc:
            resolution = {
                "formatted_resolution": (
                    "AI interpretation failed. Not present in the provided evidence.\n"
                    f"Error: {type(exc).__name__}: {exc}"
                ),
                "sender_domain_analysis": _sender_domain_fallback(
                    extracted=extracted,
                    checks=checks,
                    reason=f"AI interpretation failed: {type(exc).__name__}",
                    classification="unknown",
                ),
            }
            resolution["formatted_resolution"] = _render_email_template_resolution(
                extracted=extracted,
                checks=checks,
                url_destination_context=interpretation_payload.get("url_destination_context"),
                resolution=resolution,
            )
            resolution_source = "fallback_error"
    else:
        resolution = {
            "formatted_resolution": "AI interpretation disabled. Not present in the provided evidence.",
            "sender_domain_analysis": _sender_domain_fallback(
                extracted=extracted,
                checks=checks,
                reason="AI interpretation disabled for this run.",
                classification="unknown",
            ),
        }
        resolution["formatted_resolution"] = _render_email_template_resolution(
            extracted=extracted,
            checks=checks,
            url_destination_context=interpretation_payload.get("url_destination_context"),
            resolution=resolution,
        )
        resolution_source = "disabled"

    response_payload = {
        "filename": name,
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
        "url_destination_context": interpretation_payload.get("url_destination_context"),
        "resolution_source": resolution_source,
        "resolution": resolution,
    }

    try:
        history_payload = _prepare_history_payload(response_payload)
        run = EmailInvestigationRun(
            filename=name,
            email_subject=str(response_payload.get("email_subject") or "")[:512] or None,
            sender_email=response_payload.get("sender_email"),
            sender_domain=response_payload.get("sender_domain"),
            sender_ip=response_payload.get("sender_ip"),
            resolution_source=resolution_source,
            result_json=history_payload,
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)
        response_payload["history_id"] = str(run.id)
    except Exception as exc:
        await db.rollback()
        logger.warning("Email history persistence failed; returning live response only: %s", exc)
        response_payload["history_id"] = None
    return response_payload


@router.get("/history")
async def list_email_investigation_history(
    db: DBSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    try:
        rows = (
            (
                await db.execute(
                    select(EmailInvestigationRun)
                    .order_by(EmailInvestigationRun.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
    except Exception as exc:
        logger.warning("Email history list unavailable: %s", exc)
        return {"items": [], "limit": limit, "offset": offset}
    items = [
        {
            "id": str(r.id),
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "filename": r.filename,
            "email_subject": r.email_subject,
            "sender_email": r.sender_email,
            "sender_domain": r.sender_domain,
            "sender_ip": r.sender_ip,
            "resolution_source": r.resolution_source,
            "urls_count": int((r.result_json or {}).get("urls_count") or 0),
            "attachments_count": int((r.result_json or {}).get("attachments_count") or 0),
        }
        for r in rows
    ]
    return {"items": items, "limit": limit, "offset": offset}


@router.get("/history/{run_id}")
async def get_email_investigation_history_item(
    db: DBSession,
    run_id: str = Path(...),
) -> dict[str, Any]:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid history id format.") from exc

    try:
        row = (
            (
                await db.execute(
                    select(EmailInvestigationRun).where(EmailInvestigationRun.id == parsed_id)
                )
            )
            .scalars()
            .first()
        )
    except Exception as exc:
        logger.warning("Email history item unavailable for %s: %s", parsed_id, exc)
        raise HTTPException(status_code=404, detail="Email investigation history is unavailable.") from exc
    if not row:
        raise HTTPException(status_code=404, detail="Email investigation history item not found.")

    payload = dict(row.result_json or {})
    payload["history_id"] = str(row.id)
    payload["created_at"] = row.created_at.isoformat() if row.created_at else None
    return payload


def _compact_checks_for_ai(checks: dict[str, Any]) -> dict[str, Any]:
    """Shrink checks payload for AI prompt budget (no image blobs)."""
    sender_domain = checks.get("sender_domain") or {}
    whois = sender_domain.get("whois") or {}
    urls_compact: list[dict[str, Any]] = []
    for item in checks.get("urls") or []:
        vt = item.get("vt") or {}
        ss = item.get("screenshot") or {}
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
                "fallback_feeds": item.get("fallback_feeds") or {},
                "google_safe_browsing": item.get("google_safe_browsing") or {},
                "urlscan": item.get("urlscan") or {},
                "lexical_ml": item.get("lexical_ml") or {},
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
        },
        "urls": urls_compact,
        "attachments": {
            "present": attachments.get("present"),
            "items": att_items,
            "message": attachments.get("message"),
        },
    }


def _prepare_history_payload(response_payload: dict[str, Any]) -> dict[str, Any]:
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
                "fallback_feeds": item.get("fallback_feeds") or {},
                "google_safe_browsing": item.get("google_safe_browsing") or {},
                "urlscan": item.get("urlscan") or {},
                "lexical_ml": item.get("lexical_ml") or {},
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
        "url_destination_context": response_payload.get("url_destination_context"),
        "resolution_source": response_payload.get("resolution_source"),
        "resolution": response_payload.get("resolution") or {},
    }


def _build_url_destination_context(checks: dict[str, Any]) -> str:
    """
    Build a concise destination-purpose hint for AI formatting.
    This is deterministic and avoids vague labels like "other web destinations".
    """
    urls = checks.get("urls") or []
    if not urls:
        return "Not present in the provided evidence."

    grouped_domains: dict[str, set[str]] = defaultdict(set)
    domain_descriptions: dict[str, str] = {}
    for item in urls:
        if not isinstance(item, dict):
            continue
        screenshot = item.get("screenshot") or {}
        urlscan = item.get("urlscan") or {}
        candidate = str(
            screenshot.get("final_url")
            or urlscan.get("page_url")
            or item.get("url")
            or ""
        ).strip()
        if not candidate:
            continue
        host = (urlparse(candidate).hostname or "").lower().strip(".")
        if not host:
            continue
        root = _root_domain(host)
        purpose = _infer_domain_purpose(
            host=host,
            full_url=candidate.lower(),
            lexical_ml=(item.get("lexical_ml") or {}),
        )
        domain_key = root or host
        grouped_domains[purpose].add(domain_key)
        domain_descriptions[domain_key] = _destination_domain_description(
            domain=domain_key,
            host=host,
            purpose=purpose,
            full_url=candidate.lower(),
        )

    if not grouped_domains:
        return "Not present in the provided evidence."

    purpose_text = "; ".join(sorted(grouped_domains.keys()))
    observed_domains = sorted({d for ds in grouped_domains.values() for d in ds})
    observed_text = "; ".join(
        f"{domain} ({domain_descriptions.get(domain) or 'general web destination'})"
        for domain in observed_domains
    )
    return f"{purpose_text}; Destinations observed: {observed_text}"


def _infer_domain_purpose(*, host: str, full_url: str, lexical_ml: dict[str, Any]) -> str:
    if "sendibm3.com" in host or "sendinblue.com" in host or "brevo.com" in host:
        return "Brevo/Sendinblue campaign redirect or tracking infrastructure"
    if "salesforce.com" in host and any(t in full_url for t in ("/click", "/open", "/unsubscribe", "tracking")):
        return "Salesforce Marketing Cloud campaign redirect/tracking infrastructure"
    if "safelinks.protection.outlook.com" in host:
        return "Microsoft Defender/Outlook Safe Links rewrite gateway"
    if host.endswith("outlook.com"):
        return "Microsoft Outlook-related destination"
    if host.endswith("salesforce-experience.com"):
        return "Salesforce Experience Cloud hosted content"
    if host.endswith("caseware.com"):
        return "Caseware corporate website/resources"
    if host.endswith("aka.ms"):
        return "Microsoft short-link redirection service"
    if host.endswith("microsoft.com"):
        return "Microsoft web destination"
    if host.endswith("w3.org"):
        return "W3C standards/DTD technical resource"

    label = str((lexical_ml or {}).get("label") or "").lower()
    if label == "high":
        return "high-risk URL lexical pattern destination"
    if label == "medium":
        return "medium-risk URL lexical pattern destination"
    return "web destination with low-risk lexical pattern"


def _destination_domain_description(*, domain: str, host: str, purpose: str, full_url: str) -> str:
    d = (domain or "").lower()
    h = (host or "").lower()
    if "sendibm3.com" in d or "sendinblue.com" in d or "brevo.com" in d:
        return "Brevo/Sendinblue email campaign infrastructure"
    if "salesforce.com" in d:
        return "Salesforce cloud and marketing infrastructure"
    if "salesforce-experience.com" in d:
        return "Salesforce Experience Cloud hosted content"
    if "caseware.com" in d:
        return "Caseware corporate website and resources"
    if "outlook.com" in d:
        return "Microsoft Outlook-related destination"
    if "aka.ms" in d:
        return "Microsoft short-link redirection service"
    if "microsoft.com" in d:
        return "Microsoft web destination"
    if "w3.org" in d:
        if "/dtd/" in (full_url or ""):
            return "W3C XHTML/HTML DTD technical resources used by markup templates"
        return "W3C standards and technical documentation resources"
    if "googleapis.com" in d:
        return "Google APIs and hosted web resources"
    if "high-risk URL lexical pattern" in purpose:
        return "high-risk destination pattern"
    if "medium-risk URL lexical pattern" in purpose:
        return "medium-risk destination pattern"
    return "general web destination"


def _root_domain(host: str) -> str:
    parts = [p for p in (host or "").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


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


def _render_email_template_resolution(
    *,
    extracted: dict[str, Any],
    checks: dict[str, Any],
    url_destination_context: str | None,
    resolution: dict[str, Any],
) -> str:
    subject = str(extracted.get("email_subject") or "").strip() or NOT_PRESENT
    sender_email = str(extracted.get("sender_email") or "").strip() or NOT_PRESENT

    sender_line_context = _sender_domain_context_text(extracted, checks, resolution)
    sender_ip_line = _sender_ip_summary_text(extracted, checks)
    attachment_line = _attachment_summary_text(extracted, checks)
    url_line = _url_summary_text(extracted, checks, url_destination_context)

    additional = _additional_findings_text(resolution, sender_line_context)
    lines = [
        f'Email subject: "{subject}"',
        "",
        "After our investigation, we found:",
        "",
        f"The sender's email address {sender_email} appears associated with {sender_line_context}.",
        sender_ip_line,
        attachment_line,
        f"All URLs found in the email body were checked and {url_line}.",
    ]
    if additional and additional != NOT_PRESENT:
        lines.extend(["", f"Additional findings: {additional}."])
    return "\n".join(lines)


def _sender_domain_context_text(
    extracted: dict[str, Any],
    checks: dict[str, Any],
    resolution: dict[str, Any],
) -> str:
    sender_domain = str(extracted.get("sender_domain") or "").strip()
    if sender_domain:
        mapped = _known_domain_context(sender_domain)
        if mapped:
            return mapped

    whois = ((checks.get("sender_domain") or {}).get("whois") or {})
    registrant_org = _clean_text(whois.get("registrant_org"))
    registrar = _clean_text(whois.get("registrar"))
    if registrant_org:
        return f"{registrant_org} (organization indicated by WHOIS)"
    if sender_domain and registrar:
        return f"{sender_domain} (registrar: {registrar})"
    return sender_domain or NOT_PRESENT


def _sender_ip_summary_text(extracted: dict[str, Any], checks: dict[str, Any]) -> str:
    sender_ip = str(extracted.get("sender_ip") or "").strip() or NOT_PRESENT
    if sender_ip == NOT_PRESENT:
        return "No sender IP address was extracted from the provided headers."
    sender_ip_check = checks.get("sender_ip") or {}
    abuse = sender_ip_check.get("abuseipdb") or {}
    vt = sender_ip_check.get("vt") or {}
    isp = _clean_text(abuse.get("isp")) or NOT_PRESENT
    usage = _clean_text(abuse.get("usage_type")) or NOT_PRESENT
    verdict = str(vt.get("verdict") or "").lower()
    m = int(vt.get("malicious_count") or 0)
    s = int(vt.get("suspicious_count") or 0)
    t = int(vt.get("total_vendors") or 0)
    if verdict in {"clean", "suspicious", "malicious"}:
        rep = f"VirusTotal marked it {verdict} ({m} malicious, {s} suspicious out of {t} engines)"
    else:
        rep = "its reputation could not be confidently established by VirusTotal"
    return (
        f"The sender's IP address {sender_ip} (ISP: {isp}, Usage Type: {usage}) "
        f"was checked and {rep}."
    )


def _attachment_summary_text(extracted: dict[str, Any], checks: dict[str, Any]) -> str:
    attachments = extracted.get("attachments") or []
    if not attachments:
        return "No attachments present in the email body."
    types: list[str] = []
    for att in attachments:
        if not isinstance(att, dict):
            continue
        f = str(att.get("filename") or "").lower()
        if "." in f:
            types.append(f.rsplit(".", 1)[-1])
    attachment_types = ", ".join(sorted(set(types))) if types else "unknown type"
    items = ((checks.get("attachments") or {}).get("items") or [])
    verdicts = [str(((i.get("vt") or {}).get("verdict") or "")).lower() for i in items if isinstance(i, dict)]
    if any(v == "malicious" for v in verdicts):
        status = "malicious"
    elif any(v == "suspicious" for v in verdicts):
        status = "suspicious"
    elif any(v == "clean" for v in verdicts):
        status = "safe"
    else:
        status = "unknown"
    return f"The attachments present in the email body ({attachment_types}) were found to be {status}."


def _url_summary_text(
    extracted: dict[str, Any],
    checks: dict[str, Any],
    url_destination_context: str | None,
) -> str:
    urls = extracted.get("urls") or []
    checked = checks.get("urls") or []
    context = _clean_text(url_destination_context) or NOT_PRESENT
    return f"URLs checked: {len(checked)}/{len(urls)}. {context}"


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _known_domain_context(sender_domain: str) -> str | None:
    d = sender_domain.lower()
    if d.endswith("caseware.com") or d.endswith("em.caseware.com"):
        return "Caseware (legitimate software company focused on audit, financial reporting, and analytics solutions)"
    if d.endswith("j2.net"):
        return "j2 Global (Ziff Davis) (legitimate corporate domain associated with cloud communications and digital services)"
    return None


def _additional_findings_text(resolution: dict[str, Any], sender_line_context: str) -> str | None:
    sda = resolution.get("sender_domain_analysis") or {}
    reasoning = _clean_text(sda.get("primary_reasoning"))
    if not reasoning or reasoning == NOT_PRESENT:
        return None
    if sender_line_context and reasoning.lower() in sender_line_context.lower():
        return None
    if len(reasoning) > 260:
        return None
    return reasoning.rstrip(".")
