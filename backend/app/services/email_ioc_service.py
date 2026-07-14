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
import quopri
import re
import tempfile
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SPF_RE = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
DKIM_RE = re.compile(r"\bdkim=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE)
DMARC_RE = re.compile(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE)
URL_SAFE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%"
)


def extract_email_iocs(raw_email: bytes, filename: str | None = None) -> dict[str, Any]:
    """Return a deterministic indicator bundle from a raw .eml/.msg byte payload."""
    name = (filename or "").lower()
    if name.endswith(".msg"):
        return _extract_msg_iocs(raw_email)

    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    subject_values = [str(v) for v in (msg.get_all("Subject") or []) if v is not None]
    subject = " ".join(_safe_header(v) for v in subject_values if _safe_header(v)).strip()
    if not subject:
        subject = _safe_header(msg.get("Subject"))

    raw_subject_values = _extract_headers_from_raw(raw_email, "Subject")
    decoded_raw_subject = " ".join(
        _safe_header(v) for v in raw_subject_values if _safe_header(v)
    ).strip()
    if not decoded_raw_subject:
        raw_subject = _fallback_header_value(raw_email, "Subject")
        decoded_raw_subject = _safe_header(raw_subject) if raw_subject else ""
    if decoded_raw_subject and (
        not subject
        or "=?utf-8?" in subject.lower()
        or len(decoded_raw_subject) > len(subject)
    ):
        subject = decoded_raw_subject
    _from_display, sender_email = parseaddr(_safe_header(msg.get("From")))
    sender_name = _safe_header(str(_from_display or "")).strip() or None
    sender_email = (sender_email or "").strip().lower()
    if not subject:
        subject = _fallback_header_value(raw_email, "Subject")
    if not sender_email:
        sender_email = _fallback_sender_email(raw_email)
    sender_domain = sender_email.split("@", 1)[1] if "@" in sender_email else None

    auth_blob = " ".join((msg.get_all("Authentication-Results") or [])).strip()
    spf_result = _extract_token(SPF_RE, auth_blob) or "none"
    dkim_result = _extract_token(DKIM_RE, auth_blob) or "none"
    dmarc_result = _extract_token(DMARC_RE, auth_blob) or "none"

    received_headers = msg.get_all("Received") or []
    if not received_headers:
        received_headers = _extract_headers_from_raw(raw_email, "Received")
    sender_ip = _extract_sender_ip(received_headers)

    urls = _extract_urls(msg, raw_email)
    url_domains = sorted({d for d in (_url_domain(u) for u in urls) if d})

    attachments = _extract_attachments(msg)

    return {
        "email_subject": subject or "",
        "sender_email": sender_email or None,
        "sender_name": sender_name,
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
        _msg_display, sender_email = parseaddr(sender_raw)
        sender_name = _safe_header(str(_msg_display or "")).strip() or None
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
            "sender_name": sender_name,
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
        values.extend(URL_RE.findall(_preprocess_text_for_url_scan(text)))

    if not values:
        raw_text = raw_email.decode("utf-8", errors="ignore")
        values.extend(URL_RE.findall(_preprocess_text_for_url_scan(raw_text)))
        # Quoted-printable fallback for malformed/marketing MIME payloads.
        qp_text = quopri.decodestring(raw_email).decode("utf-8", errors="ignore")
        values.extend(URL_RE.findall(_preprocess_text_for_url_scan(qp_text)))

    return _normalize_urls(values)


def _extract_urls_from_text(text: str) -> list[str]:
    return _normalize_urls(URL_RE.findall(_preprocess_text_for_url_scan(text or "")))


def _normalize_urls(values: list[str]) -> list[str]:
    clean: list[str] = []
    seen: set[str] = set()
    for url in values:
        normalized = (url or "")
        # Handle quoted-printable artifacts commonly seen in HTML emails.
        normalized = normalized.replace("=3D", "=").replace("=\r\n", "").replace("=\n", "")
        normalized = normalized.rstrip(").,;]}>\"'")
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
    fallback_ip: str | None = None
    for header in reversed(received_headers):
        for candidate in IPV4_RE.findall(header or ""):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if getattr(ip, "is_global", False):
                return str(ip)
            if fallback_ip is None:
                fallback_ip = str(ip)
    return fallback_ip


def _extract_sender_ip_from_sources(
    *,
    received_headers: list[str],
    direct_header_values: list[str] | None = None,
) -> str | None:
    sender_ip = _extract_sender_ip(received_headers)
    if sender_ip:
        return sender_ip

    fallback_ip: str | None = None
    for header in direct_header_values or []:
        for candidate in IPV4_RE.findall(header or ""):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if getattr(ip, "is_global", False):
                return str(ip)
            if fallback_ip is None:
                fallback_ip = str(ip)
    return fallback_ip


def _extract_sender_email_from_header_blob(headers_blob: str) -> str | None:
    for header in ("From", "Return-Path", "Sender", "Reply-To"):
        for value in _extract_headers(headers_blob or "", header):
            _, email = parseaddr(_safe_header(value))
            email = (email or "").strip().lower()
            if email:
                return email
    return None


def _extract_header_value_from_raw(raw_email: bytes, name: str) -> str:
    values = _extract_headers_from_raw(raw_email, name)
    if not values:
        return ""
    return _safe_header(values[0])


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
    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
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


def _fallback_header_value(raw_email: bytes, name: str) -> str:
    headers = _parse_raw_header_lines(raw_email)
    key = name.lower()
    values = headers.get(key) or []
    return values[0] if values else ""


def _fallback_sender_email(raw_email: bytes) -> str:
    for header in ("From", "Return-Path", "Sender", "Reply-To"):
        value = _fallback_header_value(raw_email, header)
        if not value:
            continue
        _, email = parseaddr(value)
        email = (email or "").strip().lower()
        if email:
            return email
    return ""


def _extract_headers_from_raw(raw_email: bytes, name: str) -> list[str]:
    headers = _parse_raw_header_lines(raw_email)
    return headers.get(name.lower()) or []


def _parse_raw_header_lines(raw_email: bytes) -> dict[str, list[str]]:
    """
    Parse raw RFC822 headers with folded continuation lines.
    Returns lower-cased header-name -> list of unfolded values.
    """
    text = raw_email.decode("utf-8", errors="ignore")
    # Keep only header section.
    if "\r\n\r\n" in text:
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
    else:
        head = text.split("\n\n", 1)[0]
        lines = head.split("\n")

    unfolded: list[str] = []
    current = ""
    for line in lines:
        if not line:
            continue
        if line.startswith((" ", "\t")) and current:
            current += " " + line.strip()
            continue
        if current:
            unfolded.append(current)
        current = line.strip()
    if current:
        unfolded.append(current)

    result: dict[str, list[str]] = {}
    for line in unfolded:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        k = key.strip().lower()
        v = value.strip()
        if not k:
            continue
        result.setdefault(k, []).append(v)
    return result


def _preprocess_text_for_url_scan(text: str) -> str:
    if not text:
        return ""
    # Decode common quoted-printable URL escapes before matching.
    normalized = text.replace("=3D", "=")
    # Join hard-wrapped URLs split by quoted-printable soft breaks.
    normalized = normalized.replace("=\r\n", "").replace("=\n", "")
    return _join_wrapped_url_lines(normalized)


def _join_wrapped_url_lines(text: str) -> str:
    """
    Re-join URLs wrapped across lines in email bodies.
    Keeps normal paragraph breaks, but removes line breaks when the
    break occurs between URL-safe characters.
    """
    out: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch in "\r\n":
            prev_ch = out[-1] if out else ""
            j = i + 1
            while j < length and text[j] in "\r\n \t":
                j += 1
            next_ch = text[j] if j < length else ""
            if prev_ch in URL_SAFE_CHARS and next_ch in URL_SAFE_CHARS:
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)
