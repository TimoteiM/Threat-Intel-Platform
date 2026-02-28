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
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.email_ai_interpreter_service import interpret_email_results_with_ai
from app.services.email_indicator_checks_service import run_email_indicator_checks
from app.services.email_ioc_service import extract_email_iocs

router = APIRouter(prefix="/api/email-investigations", tags=["email-investigations"])


@router.get("/upload")
async def email_upload_info() -> dict[str, Any]:
    return {
        "message": "Use POST multipart/form-data with field 'file' (.eml or .msg).",
        "supported_methods": ["POST"],
        "endpoint": "/api/email-investigations/upload",
    }


@router.post("/upload")
async def upload_email_investigation(
    file: UploadFile = File(...),
    context: str = Form(default=""),
    max_urls: int = Form(default=5),
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
        "context": context or None,
        "ml_phishing_score": parsed_ml_score,
    }

    if run_ai:
        try:
            resolution = await interpret_email_results_with_ai(interpretation_payload)
            resolution_source = "ai"
        except Exception as exc:
            resolution = {
                "formatted_resolution": (
                    "AI interpretation failed. Not present in the provided evidence.\n"
                    f"Error: {type(exc).__name__}: {exc}"
                )
            }
            resolution_source = "fallback_error"
    else:
        resolution = {
            "formatted_resolution": "AI interpretation disabled. Not present in the provided evidence."
        }
        resolution_source = "disabled"

    return {
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
        "resolution_source": resolution_source,
        "resolution": resolution,
    }


def _compact_checks_for_ai(checks: dict[str, Any]) -> dict[str, Any]:
    """Shrink checks payload for AI prompt budget (no image blobs)."""
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
