"""
Email IOC extraction service.

Parses raw .eml/.msg messages and extracts deterministic indicators:
- subject
- sender email/domain
- sender IP (from Received chain)
- SPF/DKIM/DMARC result tokens (from Authentication-Results)
- URLs and URL domains from body parts
- attachment hashes (sha256/md5)
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import tempfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SPF_RE = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DKIM_RE = re.compile(r"\bdkim=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE)
DMARC_RE = re.compile(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE)


def extract_email_iocs(raw_email: bytes, filename: str | None = None) -> dict[str, Any]:
    """Return a deterministic indicator bundle from a raw .eml/.msg byte payload."""
    name = (filename or "").lower()
    if name.endswith(".msg"):
        return _extract_msg_iocs(raw_email)

    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    subject = _safe_header(msg.get("Subject"))
    _, sender_email = parseaddr(_safe_header(msg.get("From")))
    sender_email = (sender_email or "").strip().lower()
    sender_domain = sender_email.split("@", 1)[1] if "@" in sender_email else None

    auth_blob = " ".join((msg.get_all("Authentication-Results") or [])).strip()
    spf_result = _extract_token(SPF_RE, auth_blob) or "none"
    dkim_result = _extract_token(DKIM_RE, auth_blob) or "none"
    dmarc_result = _extract_token(DMARC_RE, auth_blob) or "none"

    received_headers = msg.get_all("Received") or []
    sender_ip = _extract_sender_ip(received_headers)

    urls = _extract_urls(msg, raw_email)
    url_domains = sorted({d for d in (_url_domain(u) for u in urls) if d})

    attachments = _extract_attachments(msg)

    return {
        "email_subject": subject or "",
        "sender_email": sender_email or None,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "authentication": {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "authentication_results_header": auth_blob or None,
        },
        "urls": urls,
        "url_domains": url_domains,
        "attachments": attachments,
    }


def _extract_msg_iocs(raw_email: bytes) -> dict[str, Any]:
    try:
        import extract_msg  # type: ignore
    except Exception as exc:
        raise ValueError(
            "MSG parsing dependency missing. Install backend requirements (extract-msg)."
        ) from exc

    tmp_path = ""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
        tmp.write(raw_email)
        tmp_path = tmp.name

    try:
        try:
            msg_obj = extract_msg.Message(tmp_path)
        except Exception as exc:
            raise ValueError(f"Unable to parse .msg file: {exc}") from exc
        subject = _safe_header(getattr(msg_obj, "subject", ""))
        sender_raw = _safe_header(getattr(msg_obj, "sender", ""))
        _, sender_email = parseaddr(sender_raw)
        sender_email = (sender_email or "").strip().lower()
        sender_domain = sender_email.split("@", 1)[1] if "@" in sender_email else None

        headers_blob = _safe_header(getattr(msg_obj, "header", ""))
        auth_blob = " ".join(_extract_headers(headers_blob, "Authentication-Results")).strip()
        received_headers = _extract_headers(headers_blob, "Received")
        sender_ip = _extract_sender_ip(received_headers)

        spf_result = _extract_token(SPF_RE, auth_blob) or "none"
        dkim_result = _extract_token(DKIM_RE, auth_blob) or "none"
        dmarc_result = _extract_token(DMARC_RE, auth_blob) or "none"

        body_parts = [
            _safe_header(getattr(msg_obj, "body", "")),
            _safe_header(getattr(msg_obj, "htmlBody", "")),
        ]
        text_blob = "\n".join(part for part in body_parts if part)
        urls = _extract_urls_from_text(text_blob)
        url_domains = sorted({d for d in (_url_domain(u) for u in urls) if d})

        attachments = _extract_msg_attachments(getattr(msg_obj, "attachments", []) or [])

        return {
            "email_subject": subject or "",
            "sender_email": sender_email or None,
            "sender_domain": sender_domain,
            "sender_ip": sender_ip,
            "authentication": {
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result,
                "authentication_results_header": auth_blob or None,
            },
            "urls": urls,
            "url_domains": url_domains,
            "attachments": attachments,
        }
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _extract_urls(msg: Any, raw_email: bytes) -> list[str]:
    values: list[str] = []
    for part in msg.walk():
        ctype = (part.get_content_type() or "").lower()
        if ctype not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            try:
                payload = str(part.get_payload()).encode("utf-8", errors="ignore")
            except Exception:
                payload = b""
        text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
        values.extend(URL_RE.findall(text))

    if not values:
        values.extend(URL_RE.findall(raw_email.decode("utf-8", errors="ignore")))

    return _normalize_urls(values)


def _extract_urls_from_text(text: str) -> list[str]:
    return _normalize_urls(URL_RE.findall(text or ""))


def _normalize_urls(values: list[str]) -> list[str]:
    clean: list[str] = []
    seen: set[str] = set()
    for url in values:
        normalized = (url or "").rstrip(").,;]}>\"'")
        if normalized and normalized not in seen:
            seen.add(normalized)
            clean.append(normalized)
    return clean


def _extract_attachments(msg: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for part in msg.walk():
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue

        data = part.get_payload(decode=True) or b""
        items.append(
            {
                "filename": filename or "unnamed_attachment",
                "content_type": part.get_content_type() or "application/octet-stream",
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC compatibility
            }
        )
    return items


def _extract_msg_attachments(attachments: list[Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for att in attachments:
        data = _attachment_bytes(att)
        filename = (
            _safe_header(getattr(att, "longFilename", ""))
            or _safe_header(getattr(att, "filename", ""))
            or "unnamed_attachment"
        )
        content_type = _safe_header(getattr(att, "mimetype", "")) or "application/octet-stream"
        items.append(
            {
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC compatibility
            }
        )
    return items


def _attachment_bytes(att: Any) -> bytes:
    raw = getattr(att, "data", b"")
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="ignore")
    return b""


def _extract_sender_ip(received_headers: list[str]) -> str | None:
    # Received headers are top-down; earliest sender-side hops are usually near the end.
    for header in reversed(received_headers):
        for candidate in IPV4_RE.findall(header or ""):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if getattr(ip, "is_global", False):
                return str(ip)
    return None


def _extract_token(pattern: re.Pattern[str], blob: str) -> str | None:
    if not blob:
        return None
    m = pattern.search(blob)
    return m.group(1).lower() if m else None


def _url_domain(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except Exception:
        return None
    return host.lower() if host else None


def _safe_header(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _extract_headers(blob: str, name: str) -> list[str]:
    if not blob.strip():
        return []
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(
            (blob + "\n\n").encode("utf-8", errors="ignore")
        )
        return [str(v) for v in (parsed.get_all(name) or [])]
    except Exception:
        return []
