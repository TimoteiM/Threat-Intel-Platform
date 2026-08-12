"""
Who the email claims to be from, versus who it is actually from.

The pipeline checked the sender domain's reputation and its SPF/DKIM/DMARC
results, which answers "did this domain authorise this message". It never asked
the question business email compromise turns on: **does the message claim to be
from someone it is not?**

A BEC email frequently passes authentication perfectly. It is sent from a real,
newly-registered, correctly-configured mailbox — so SPF passes, DKIM passes,
DMARC passes, and the domain has no reputation because nobody has reported it
yet. Every reputation check comes back clean. What gives it away is the shape of
the identity:

    From: "Microsoft Account Team" <billing@random-domain.test>
    Reply-To: accounts-payable@another-domain.test

Both facts are sitting in headers the extractor already parses. They were used
only to find *an* address when `From` was missing, and the relationship between
them — the part that carries the signal — was discarded.

Nothing here makes a network call.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.utils.domain_utils import extract_registered_domain

# Brands impersonated often enough that a display name claiming one, from a
# domain that is not theirs, is worth saying out loud. Deliberately short: a long
# list produces false positives on legitimate mail that merely mentions a vendor.
_IMPERSONATED_BRANDS = {
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com", "sharepoint.com", "onedrive.com"),
    "office 365": ("microsoft.com", "office.com"),
    "outlook": ("microsoft.com", "outlook.com", "live.com"),
    "onedrive": ("microsoft.com", "onedrive.com"),
    "sharepoint": ("microsoft.com", "sharepoint.com"),
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "gmail": ("google.com", "gmail.com", "googlemail.com"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazonaws.com"),
    "aws": ("amazon.com", "amazonaws.com"),
    "paypal": ("paypal.com", "paypal.co.uk"),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "adobe": ("adobe.com",),
    "linkedin": ("linkedin.com",),
    "facebook": ("facebook.com", "facebookmail.com"),
    "meta": ("facebook.com", "meta.com"),
    "netflix": ("netflix.com",),
    "hmrc": ("hmrc.gov.uk", "gov.uk"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
}

# An address inside the display name is the crudest and most common spoof:
# the mail client shows the friendly name, and the real address is easy to miss.
_ADDRESS_IN_NAME = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

# Characters that render like Latin letters but are not. Restricted to the ones
# that actually appear in registered lookalike domains.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ο": "o",
    "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ѵ": "v", "ᴏ": "o", "ɑ": "a",
}

# Free/consumer mail providers. A display name claiming a corporate identity
# from one of these is a different (weaker) signal than a lookalike domain.
_CONSUMER_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com", "proton.me",
    "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com", "icloud.com",
}


def _domain_of(address: str | None) -> str:
    address = str(address or "").strip().lower()
    return address.split("@", 1)[1] if "@" in address else ""


def _skeleton(value: str) -> str:
    """The domain with confusable characters folded to their Latin lookalike."""
    decomposed = unicodedata.normalize("NFKD", str(value or "").lower())
    return "".join(_CONFUSABLES.get(char, char) for char in decomposed)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ch_a != ch_b)))
        previous = current
    return previous[-1]


def analyse_sender_identity(extracted: dict[str, Any]) -> dict[str, Any]:
    """
    Findings about the claimed identity, each with the evidence behind it.

    Returns a `risk` of none/low/medium/high. These are *identity* signals, not
    a verdict on the email — the caller decides what weight they carry, in the
    same way authentication results are treated as context rather than proof.
    """
    sender_email = str(extracted.get("sender_email") or "").strip().lower()
    display_name = str(extracted.get("sender_name") or "").strip()
    from_domain = _domain_of(sender_email) or str(extracted.get("sender_domain") or "").lower()
    reply_to = str(extracted.get("reply_to") or "").strip().lower()
    return_path = str(extracted.get("return_path") or "").strip().lower()

    from_registered = extract_registered_domain(from_domain) or from_domain
    findings: list[dict[str, str]] = []

    # ── An address hidden in the display name ────────────────────────────────
    embedded = _ADDRESS_IN_NAME.search(display_name or "")
    if embedded and embedded.group(0).lower() != sender_email:
        findings.append({
            "id": "display_name_contains_address",
            "severity": "high",
            "title": "Display name contains a different email address",
            "detail": (
                f"The name shown to the recipient reads \"{display_name}\", which embeds "
                f"{embedded.group(0)}, but the message was actually sent by {sender_email or 'an unknown address'}. "
                "Mail clients show the display name, so the real sender is easy to miss."
            ),
        })

    # ── A display name claiming a brand it does not own ──────────────────────
    lowered_name = (display_name or "").lower()
    for brand, legitimate in _IMPERSONATED_BRANDS.items():
        if brand not in lowered_name:
            continue
        if any(from_registered == d or from_registered.endswith("." + d) for d in legitimate):
            break
        severity = "medium" if from_registered in _CONSUMER_DOMAINS else "high"
        findings.append({
            "id": "display_name_brand_mismatch",
            "severity": severity,
            "title": f"Display name claims {brand.title()}, sender domain does not belong to it",
            "detail": (
                f"The display name \"{display_name}\" claims to be {brand.title()}, but the message "
                f"came from {from_domain or 'an unknown domain'}, which is not one of "
                f"{brand.title()}'s domains ({', '.join(legitimate[:3])})."
            ),
        })
        break

    # ── Replies going somewhere else ─────────────────────────────────────────
    reply_domain = _domain_of(reply_to)
    reply_registered = extract_registered_domain(reply_domain) or reply_domain
    if reply_to and reply_registered and reply_registered != from_registered:
        findings.append({
            "id": "reply_to_divergence",
            "severity": "high",
            "title": "Replies would go to a different domain than the sender",
            "detail": (
                f"The message is from {sender_email}, but a reply would be sent to {reply_to}. "
                f"The reply domain ({reply_registered}) is not the sending domain ({from_registered}). "
                "Redirecting the conversation to an attacker-controlled mailbox is the core mechanic "
                "of business email compromise."
            ),
        })

    # ── Bounce address disagreeing with the visible sender ───────────────────
    rp_domain = _domain_of(return_path)
    rp_registered = extract_registered_domain(rp_domain) or rp_domain
    if return_path and rp_registered and rp_registered != from_registered:
        findings.append({
            "id": "return_path_divergence",
            "severity": "low",
            "title": "Bounce address is on a different domain than the sender",
            "detail": (
                f"Return-Path is {return_path} while From is {sender_email}. This is normal for "
                "mailing lists and bulk senders, and is only meaningful alongside another signal."
            ),
        })

    # ── A sending domain built to be misread ─────────────────────────────────
    lookalike = _lookalike_finding(from_registered, display_name)
    if lookalike:
        findings.append(lookalike)

    severities = [f["severity"] for f in findings]
    if "high" in severities:
        risk = "high"
    elif "medium" in severities:
        risk = "medium"
    elif severities:
        risk = "low"
    else:
        risk = "none"

    return {
        "checked": True,
        "risk": risk,
        "findings": findings,
        "observed": {
            "from": sender_email or None,
            "display_name": display_name or None,
            "reply_to": reply_to or None,
            "return_path": return_path or None,
        },
    }


def _lookalike_finding(from_registered: str, display_name: str) -> dict[str, str] | None:
    """A sending domain that imitates a brand's domain rather than being it."""
    if not from_registered:
        return None

    if from_registered.startswith("xn--") or ".xn--" in from_registered:
        return {
            "id": "punycode_sender_domain",
            "severity": "high",
            "title": "Sender domain uses punycode",
            "detail": (
                f"{from_registered} is an internationalised domain. These render as ordinary Latin "
                "text in a mail client, which is how a lookalike domain passes visual inspection."
            ),
        }

    folded = _skeleton(from_registered)
    if folded != from_registered:
        return {
            "id": "confusable_sender_domain",
            "severity": "high",
            "title": "Sender domain contains look-alike characters",
            "detail": (
                f"{from_registered} contains characters that render like Latin letters but are not; "
                f"it reads as \"{folded}\"."
            ),
        }

    label = from_registered.split(".", 1)[0]
    for brand, legitimate in _IMPERSONATED_BRANDS.items():
        for legit in legitimate:
            legit_label = legit.split(".", 1)[0]
            if label == legit_label:
                return None
            # One or two edits from a well-known brand label, on a domain that is
            # not that brand's, is a typosquat. Requiring length >= 5 keeps short
            # generic words from matching everything.
            if len(legit_label) >= 5 and 0 < _levenshtein(label, legit_label) <= 2:
                return {
                    "id": "lookalike_sender_domain",
                    "severity": "high",
                    "title": f"Sender domain closely resembles {legit}",
                    "detail": (
                        f"{from_registered} is {_levenshtein(label, legit_label)} character(s) away from "
                        f"{legit}, which it does not belong to."
                    ),
                }
    return None
