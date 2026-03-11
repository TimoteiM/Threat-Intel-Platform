"""
Local email content-risk classifier.

Security policy:
- No external API calls.
- Operates on non-sensitive transformed indicators (subject/header tokens and metadata only).
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any

SUSPICIOUS_TERMS = {
    "urgency": ("urgent", "immediately", "asap", "today", "now", "deadline", "final notice", "action required"),
    "social_engineering": ("click", "verify", "validate", "confirm", "reset", "suspend", "locked", "security alert"),
    "impersonation": ("ceo", "cfo", "finance", "payroll", "microsoft", "google", "it support", "helpdesk"),
    "bec": ("wire", "invoice", "payment", "bank transfer", "gift card", "beneficiary", "swift"),
}


def classify_email_content_locally(extracted: dict[str, Any]) -> dict[str, Any]:
    subject = str(extracted.get("email_subject") or "")
    sender = str(extracted.get("sender_email") or "")
    sender_domain = str(extracted.get("sender_domain") or "")
    auth = extracted.get("authentication") or {}
    urls = extracted.get("urls") or []

    normalized_subject = _normalize_text(subject)
    tokens = _tokens(normalized_subject)
    token_counts = Counter(tokens)

    auth_penalty = 0.0
    if str(auth.get("spf") or "").lower() in {"fail", "softfail", "none"}:
        auth_penalty += 0.08
    if str(auth.get("dkim") or "").lower() in {"fail", "none"}:
        auth_penalty += 0.08
    if str(auth.get("dmarc") or "").lower() in {"fail", "none"}:
        auth_penalty += 0.08

    social = _term_score(tokens, "social_engineering") + auth_penalty + min(0.12, len(urls) * 0.02)
    urgency = _term_score(tokens, "urgency") + min(0.10, _exclamation_score(subject))
    impersonation = _term_score(tokens, "impersonation") + _sender_mismatch_score(sender, sender_domain, tokens)
    bec = _term_score(tokens, "bec") + (0.1 if any(t in {"invoice", "payment"} for t in tokens) else 0.0)

    top_terms = [t for t, _ in token_counts.most_common(10)]
    return {
        "social_engineering_probability": _clip01(social),
        "urgency_probability": _clip01(urgency),
        "impersonation_probability": _clip01(impersonation),
        "bec_probability": _clip01(bec),
        "top_content_terms": top_terms,
        "model_source": "local-header-heuristic-v1",
        "feature_hash": hashlib.sha256((" ".join(sorted(top_terms))).encode("utf-8")).hexdigest()[:16],
    }


def _normalize_text(text: str) -> str:
    lowered = (text or "").lower()
    lowered = re.sub(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "<email>", lowered)
    lowered = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", lowered)
    lowered = re.sub(r"\d+", "0", lowered)
    return lowered


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z][a-z0-9_+-]{1,30}", text or "")


def _term_score(tokens: list[str], category: str) -> float:
    vocab = SUSPICIOUS_TERMS.get(category, ())
    if not tokens:
        return 0.0
    hits = 0
    normalized = " ".join(tokens)
    for v in vocab:
        if " " in v:
            if v in normalized:
                hits += 1
        elif v in tokens:
            hits += 1
    return min(0.85, hits * 0.16)


def _exclamation_score(subject: str) -> float:
    s = str(subject or "")
    if not s:
        return 0.0
    return min(1.0, s.count("!") * 0.2)


def _sender_mismatch_score(sender_email: str, sender_domain: str, subject_tokens: list[str]) -> float:
    sender = str(sender_email or "").lower()
    domain = str(sender_domain or "").lower()
    if not sender or not domain:
        return 0.0
    score = 0.0
    for brand in ("microsoft", "google", "paypal", "apple", "amazon"):
        if brand in subject_tokens and brand not in domain:
            score += 0.15
    if "noreply" in sender and any(k in subject_tokens for k in ("invoice", "payment", "wire")):
        score += 0.1
    return min(0.8, score)


def _clip01(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 4)

