"""
Decide which URLs in an email are worth spending a reputation lookup on.

An email is not a list of destinations. A single marketing message in this
platform's own corpus carried 106 URLs across 5 domains; another carried 98
across 5. Checking each one sent ~20 VirusTotal requests per email — enough to
exhaust a free tier in a dozen messages — to re-learn the same handful of facts.

Measured over the 98 emails already investigated here: 1,706 URL instances, 449
domain mentions, **39 unique domains in total**, of which 15 are things an
external service could say anything useful about. The rest are markup artefacts,
Safe Links wrappers, and bulk-mail infrastructure.

So this module answers four questions before any request is made:

    unwrap        is this a rewritten link hiding the real destination?
    artefact      is this a URL at all, or a namespace declaration?
    infrastructure is this the sender's ESP rather than a destination?
    rank          of what is left, which few are worth the budget?

The order matters. Unwrapping first is not only cheaper but *more correct*: a
phishing link wrapped by Microsoft Defender was previously checked as
`safelinks.protection.outlook.com`, and VirusTotal will always say Microsoft is
clean. 44 of those 98 emails contained wrapped links.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from app.utils.domain_utils import extract_registered_domain

# ── Markup artefacts ─────────────────────────────────────────────────────────
# Namespace URIs and DTD references from Office/Outlook HTML. They appear in the
# body as `http://...` and are never fetched by anything. Present in 44 of the
# corpus's 449 domain mentions.
_ARTEFACT_HOSTS = (
    "www.w3.org",
    "w3.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "purl.org",
    "www.w3.org/1999/xhtml",
)

# ── Link rewriters ───────────────────────────────────────────────────────────
# Security gateways and mailers rewrite links. The wrapper tells you about the
# gateway; the parameter inside tells you about the threat.
_WRAPPER_PARAMS = ("url", "u", "q", "target", "redirect", "redirect_url", "dest", "destination")
_WRAPPER_HOSTS = (
    "safelinks.protection.outlook.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "protect-eu.mimecast.com",
    "protect-us.mimecast.com",
    "clicktime.symantec.com",
    "linkprotect.cudasvc.com",
    "www.google.com/url",
)

# ── Bulk-mail and asset infrastructure ───────────────────────────────────────
# A verdict on these describes the sender's mail provider, not the email. They
# are reported as recognised infrastructure rather than looked up. Anything that
# is genuinely a redirector still gets unwrapped first, so a malicious final
# destination is not hidden by its carrier.
_INFRASTRUCTURE_PATTERNS = (
    (r"(^|\.)salesforce(-experience)?\.com$", "Salesforce Marketing Cloud"),
    (r"(^|\.)sendibm\d*\.com$|(^|\.)sendinblue\.com$|(^|\.)brevo\.com$", "Brevo/Sendinblue"),
    (r"(^|\.)cmail\d+\.com$|(^|\.)createsend\.com$", "Campaign Monitor"),
    (r"(^|\.)list-manage\.com$|(^|\.)mailchimp\.com$|(^|\.)mcusercontent\.com$", "Mailchimp"),
    (r"(^|\.)sendgrid\.net$|(^|\.)sendgrid\.com$", "SendGrid"),
    (r"(^|\.)mandrillapp\.com$", "Mandrill"),
    (r"(^|\.)hubspot(links|email)?\.(com|net)$", "HubSpot"),
    (r"(^|\.)marketo\.com$|(^|\.)mktoresp\.com$", "Marketo"),
    (r"(^|\.)constantcontact\.com$|(^|\.)rs6\.net$", "Constant Contact"),
    (r"(^|\.)j2\.email$", "j2 campaign routing"),
    (r"(^|\.)fonts\.googleapis\.com$|(^|\.)gstatic\.com$", "Google Fonts/static assets"),
    (r"(^|\.)cloudfront\.net$|(^|\.)akamaized\.net$|(^|\.)akamai\.net$", "CDN assets"),
    (r"(^|\.)bootstrapcdn\.com$|(^|\.)jsdelivr\.net$|(^|\.)unpkg\.com$", "JS/CSS CDN"),
)

# ── Priority signals ─────────────────────────────────────────────────────────
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in",
    "aka.ms",
}

# Words that appear in the path of a credential-harvesting page far more often
# than in ordinary marketing links.
_CREDENTIAL_PATH = re.compile(
    r"(login|signin|sign-in|verify|verification|account|secure|update|confirm|"
    r"password|credential|authenticate|billing|invoice|payment|unlock|recover)",
    re.IGNORECASE,
)

# TLDs disproportionately represented in phishing relative to legitimate mail.
_RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "live", "rest", "cfd", "sbs",
    "icu", "cyou", "quest", "monster", "buzz", "surf", "bar", "gq", "ml", "cf",
    "tk", "ga", "work", "fit", "beauty", "hair", "skin", "makeup",
}


@dataclass
class TriagedUrl:
    """One deduplicated destination, and why it did or did not earn a lookup."""

    url: str
    domain: str
    registered_domain: str
    occurrences: int = 1
    original_urls: list[str] = field(default_factory=list)
    unwrapped_from: str | None = None
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    # Set when a local rule answers the question and no external call is needed.
    local_verdict: str | None = None
    local_detail: str | None = None

    @property
    def needs_lookup(self) -> bool:
        return self.local_verdict is None


def unwrap_url(url: str, *, depth: int = 3) -> tuple[str, str | None]:
    """
    The real destination behind a rewritten link, and the wrapper it came from.

    Decoding the parameter is free, instant, and does not depend on the gateway
    being reachable — unlike following the redirect, which for Safe Links often
    requires a session the platform does not have.
    """
    current = (url or "").strip()
    wrapper: str | None = None

    for _ in range(max(1, depth)):
        try:
            parsed = urlparse(current)
        except ValueError:
            break
        host = (parsed.hostname or "").lower()
        if not any(marker in f"{host}{parsed.path}".lower() for marker in _WRAPPER_HOSTS):
            break

        params = parse_qs(parsed.query or "")
        target = ""
        for key in _WRAPPER_PARAMS:
            values = params.get(key) or params.get(key.upper()) or []
            if values and str(values[0]).lower().startswith(("http://", "https://")):
                target = unquote(str(values[0]))
                break

        if not target:
            # Proofpoint v2 encodes the destination in the path rather than a
            # query parameter: https://urldefense.com/v3/__https://real/__;!!...
            match = re.search(r"/v\d/__(https?://[^_]+)__", current)
            if match:
                target = unquote(match.group(1))

        if not target or target == current:
            break
        wrapper = wrapper or host
        current = target

    return current, wrapper


def _is_artefact(url: str, host: str) -> bool:
    lowered = url.lower()
    if host in _ARTEFACT_HOSTS:
        return True
    # A DTD or schema reference is markup, whatever host serves it.
    return lowered.endswith((".dtd", ".xsd")) or "/tr/xhtml" in lowered


def _infrastructure(host: str) -> str | None:
    for pattern, label in _INFRASTRUCTURE_PATTERNS:
        if re.search(pattern, host):
            return label
    return None


def _score(entry: TriagedUrl, sender_registered_domain: str) -> None:
    """
    How much a lookup on this URL is worth, and why.

    Deliberately explainable: an analyst reading the report should see which
    URLs were checked and on what grounds, not a bare number.
    """
    host = entry.domain
    registered = entry.registered_domain
    parsed = urlparse(entry.url)
    score = 0.0

    if entry.unwrapped_from:
        # Something thought this link needed rewriting, and the destination is
        # not the gateway — that is the link a user would actually land on.
        score += 2.0
        entry.reasons.append(f"unwrapped from {entry.unwrapped_from}")

    if registered in _SHORTENERS or host in _SHORTENERS:
        score += 2.5
        entry.reasons.append("URL shortener hides the destination")

    try:
        ipaddress.ip_address(host)
        score += 3.0
        entry.reasons.append("bare IP address instead of a hostname")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        score += 3.0
        entry.reasons.append("punycode hostname — possible lookalike")

    tld = registered.rsplit(".", 1)[-1] if "." in registered else ""
    if tld in _RISKY_TLDS:
        score += 1.5
        entry.reasons.append(f"TLD .{tld} is over-represented in phishing")

    if _CREDENTIAL_PATH.search(parsed.path or "") or _CREDENTIAL_PATH.search(parsed.query or ""):
        score += 1.5
        entry.reasons.append("path suggests a credential or payment page")

    if sender_registered_domain and registered == sender_registered_domain:
        # A link to the sender's own domain says little the sender check has not
        # already established.
        score -= 1.0
        entry.reasons.append("same registered domain as the sender")

    if (parsed.scheme or "").lower() == "http":
        score += 0.5
        entry.reasons.append("plaintext HTTP")

    # A destination appearing once in a long marketing email is more interesting
    # than the footer link repeated forty times.
    if entry.occurrences == 1:
        score += 0.5

    entry.score = round(score, 2)


def triage_email_urls(
    urls: list[str],
    *,
    sender_domain: str = "",
    budget: int = 6,
) -> dict[str, Any]:
    """
    Collapse an email's URLs to the few worth an external lookup.

    Returns the selected destinations, the ones answered locally, and a summary
    the report can show so the analyst knows what was skipped and why — silently
    dropping URLs from a phishing investigation would be worse than the quota.
    """
    sender_registered = extract_registered_domain(sender_domain or "") or ""

    by_key: dict[str, TriagedUrl] = {}
    artefacts = 0

    for raw in urls:
        if not isinstance(raw, str) or not raw.strip():
            continue
        destination, wrapper = unwrap_url(raw)
        try:
            parsed = urlparse(destination)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            continue

        if _is_artefact(destination, host):
            artefacts += 1
            continue

        # One entry per destination host: 106 URLs on 5 domains is 5 questions.
        key = host
        entry = by_key.get(key)
        if entry is None:
            entry = TriagedUrl(
                url=destination,
                domain=host,
                registered_domain=extract_registered_domain(host) or host,
                occurrences=0,
                unwrapped_from=wrapper,
            )
            by_key[key] = entry
        entry.occurrences += 1
        if raw not in entry.original_urls and len(entry.original_urls) < 5:
            entry.original_urls.append(raw)

    for entry in by_key.values():
        label = _infrastructure(entry.domain)
        if label:
            entry.local_verdict = "infrastructure"
            entry.local_detail = f"{label} — bulk-mail or asset infrastructure, not a destination"
            continue
        _score(entry, sender_registered)

    candidates = sorted(
        (e for e in by_key.values() if e.needs_lookup),
        key=lambda e: (-e.score, e.domain),
    )
    selected = candidates[: max(0, budget)]
    deferred = candidates[max(0, budget):]
    infrastructure = [e for e in by_key.values() if not e.needs_lookup]

    return {
        "selected": selected,
        "deferred": deferred,
        "infrastructure": infrastructure,
        "summary": {
            "urls_in_email": len([u for u in urls if isinstance(u, str) and u.strip()]),
            "distinct_destinations": len(by_key),
            "markup_artefacts_dropped": artefacts,
            "recognised_infrastructure": len(infrastructure),
            "looked_up": len(selected),
            "deferred_over_budget": len(deferred),
            "budget": budget,
        },
    }
