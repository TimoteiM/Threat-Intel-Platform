"""
HTTP Collector — probes the domain over HTTPS (fallback HTTP).

Captures: reachability, redirect chain, response headers, page title,
login form detection, security headers, server fingerprint,
favicon hash, brand impersonation, phishing kit patterns, external resources.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse

import requests

from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta, HTTPEvidence, HTTPRedirect

logger = logging.getLogger(__name__)

# Security headers we care about
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Brand impersonation phrases (case-insensitive)
BRAND_PHRASES = [
    "verify your account",
    "update your payment",
    "confirm your identity",
    "account suspended",
    "unusual activity",
    "log in to your account",
    "your account has been",
    "security alert",
    "verify your email",
    "action required",
    "confirm your payment",
    "unauthorized access",
]

# Well-known brands — if mentioned in page content but domain doesn't belong to them,
# it's a strong impersonation signal.
KNOWN_BRANDS = [
    "microsoft", "outlook", "office 365", "onedrive", "sharepoint",
    "google", "gmail", "google drive", "google docs",
    "apple", "icloud", "apple id",
    "paypal",
    "amazon", "aws",
    "facebook", "instagram", "whatsapp", "meta",
    "linkedin",
    "dropbox",
    "netflix",
    "bank of america", "chase", "wells fargo", "citibank", "barclays",
    "dhl", "fedex", "ups", "usps",
]

# Input field names that indicate credential/payment harvesting.
# Matched against name=, id=, and type= attributes of <input> tags.
# Includes email-only harvesters — a very common phishing pattern where a single
# email field is the entire credential collection mechanism.
CREDENTIAL_FIELD_RE = re.compile(
    r'<input[^>]+(?:name|id)\s*=\s*["\']?'
    r'(?:password|passwd|pass|pwd|cc|card(?:_?num(?:ber)?)?|cvv|cvc|'
    r'card(?:_?expir(?:y|ation)?|_?exp)|ssn|social(?:_?security)?|'
    r'pin|secret|credit|'
    r'email|e-mail|mail|user(?:name)?|login|account)',
    re.I,
)

# Separately detect type="email" inputs — single-field email harvesters
EMAIL_INPUT_RE = re.compile(r'<input[^>]+type\s*=\s*["\']?email', re.I)

# Suspicious path segments in the URL itself.
SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "validation",
    "secure", "security", "auth", "authenticate",
    "account", "accounts", "update", "confirm", "confirmation",
    "banking", "payment", "checkout", "billing", "invoice",
    "webmail", "roundcube", "owa", "autodiscover",
    "recover", "recovery", "reset", "unlock",
    "review", "reviews",  # common in fake review/survey phishing
}

# Phishing kit indicators (regex patterns)
PHISHING_PATTERNS = [
    (re.compile(r'\beval\s*\(', re.I), "eval() call — potential JS obfuscation"),
    (re.compile(r'\batob\s*\(', re.I), "atob() call — Base64 decoding"),
    (re.compile(r'String\.fromCharCode', re.I), "String.fromCharCode — character encoding"),
    (re.compile(r'\bunescape\s*\(', re.I), "unescape() — URL decoding obfuscation"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write — dynamic content injection"),
    (re.compile(r'api\.telegram\.org/bot', re.I), "Telegram Bot API — credential exfiltration"),
    # JS-based form submission to external endpoints (fetch / XHR / axios)
    (re.compile(r'''(?:fetch|axios\.post|axios\.put|jQuery\.ajax|\$\.ajax|\$\.post)\s*\(\s*['"]https?://''', re.I),
     "JS HTTP call to hardcoded external URL — possible credential exfiltration"),
    (re.compile(r'new\s+XMLHttpRequest', re.I), "XMLHttpRequest — JS-based form submission"),
]

# Simple technology detection patterns
TECH_PATTERNS = {
    "nginx": re.compile(r"nginx", re.I),
    "Apache": re.compile(r"apache", re.I),
    "IIS": re.compile(r"microsoft-iis", re.I),
    "Cloudflare": re.compile(r"cloudflare", re.I),
    "LiteSpeed": re.compile(r"litespeed", re.I),
}


def _detect_js_redirect(body: str) -> str | None:
    """
    Detect client-side redirects (meta-refresh and JavaScript) that the
    requests library cannot follow.  Returns the target URL or None.
    """
    # Meta refresh: <meta http-equiv="refresh" content="0;url=https://...">
    meta = re.search(
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^\s"\'>;]+)',
        body, re.I,
    )
    if meta:
        return meta.group(1).strip()

    # JS redirects: window.location, location.href, location.replace(...)
    js = re.search(
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        body, re.I,
    )
    if js:
        return js.group(1).strip()

    js_replace = re.search(
        r'(?:window\.)?location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        body, re.I,
    )
    if js_replace:
        return js_replace.group(1).strip()

    return None


class HTTPCollector(BaseCollector):
    name = "http"
    supported_types = frozenset({"domain", "url"})

    def _collect(self) -> HTTPEvidence:
        evidence = HTTPEvidence()
        session = requests.Session()
        session.max_redirects = 10
        session.headers.update({
            "User-Agent": "ThreatInvestigator/1.0 (Security Research)",
            "Accept": "text/html,application/xhtml+xml",
        })

        # ── Try HTTPS first, fall back to HTTP ──
        # For URL type, use the value directly; for domain, prepend scheme
        response = None
        if self.observable_type == "url":
            schemes_to_try = [("direct", self.domain)]
        else:
            schemes_to_try = [("https", f"https://{self.domain}"), ("http", f"http://{self.domain}")]

        for scheme, target_url in schemes_to_try:
            try:
                response = session.get(
                    target_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=(not target_url.startswith("http://")),
                )
                break
            except requests.exceptions.SSLError:
                if scheme == "https":
                    continue  # Will try HTTP
                raise
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                if scheme == "https":
                    continue
                evidence.reachable = False
                return evidence

        if response is None:
            evidence.reachable = False
            return evidence

        # ── Basic response info ──
        evidence.reachable = True
        evidence.final_url = str(response.url)
        evidence.final_status_code = response.status_code
        evidence.response_headers = dict(response.headers)
        evidence.server = response.headers.get("Server")
        evidence.content_type = response.headers.get("Content-Type")
        evidence.content_length = len(response.content)

        # ── Redirect chain ──
        for r in response.history:
            evidence.redirect_chain.append(HTTPRedirect(
                url=str(r.url),
                status_code=r.status_code,
                headers={k: v for k, v in r.headers.items()
                         if k.lower() in ("location", "server", "set-cookie")},
            ))

        # ── Parse body (capped at 100KB) ──
        body = response.text[:100_000]
        body_lower = body.lower()

        # Title
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title_match:
            evidence.title = title_match.group(1).strip()[:200]

        # Detect JavaScript / meta-refresh redirects (invisible to requests library)
        js_redirect_url = _detect_js_redirect(body)
        if js_redirect_url:
            evidence.redirect_chain.append(HTTPRedirect(
                url=js_redirect_url,
                status_code=0,  # 0 = client-side redirect (JS/meta)
                headers={"X-Redirect-Type": "client-side (JavaScript/meta-refresh)"},
            ))

        # Login / credential form detection — password fields OR email-only harvesters
        has_password_field = bool(re.search(r'type\s*=\s*["\']?password', body, re.I))
        has_email_field = bool(EMAIL_INPUT_RE.search(body))
        evidence.has_login_form = has_password_field or has_email_field
        if has_email_field and not has_password_field:
            evidence.phishing_indicators.append(
                "Email-only input form — typical single-step credential harvester"
            )
        evidence.has_input_fields = "<input" in body_lower

        # Security headers
        for header_name in SECURITY_HEADERS:
            val = response.headers.get(header_name)
            if val:
                evidence.security_headers[header_name] = val

        # Technology detection from Server header
        server_str = (evidence.server or "") + " " + response.headers.get("X-Powered-By", "")
        for tech_name, pattern in TECH_PATTERNS.items():
            if pattern.search(server_str):
                evidence.technologies_detected.append(tech_name)

        # ── Content analysis: brand impersonation ──
        for phrase in BRAND_PHRASES:
            if phrase in body_lower:
                evidence.brand_indicators.append(phrase)

        # ── Content analysis: phishing kit patterns ──
        for pattern, desc in PHISHING_PATTERNS:
            if pattern.search(body):
                evidence.phishing_indicators.append(desc)

        # Check for form actions posting to external domains
        own_host = self.target_domain
        form_actions = re.findall(
            r'<form[^>]+action\s*=\s*["\']?(https?://[^"\'\s>]+)',
            body, re.I,
        )
        for action_url in form_actions:
            try:
                action_domain = urlparse(action_url).hostname
                if action_domain and action_domain != own_host:
                    evidence.phishing_indicators.append(
                        f"Form posts to external domain: {action_domain}"
                    )
            except Exception:
                pass

        # Credential/payment/account field detection (name/id attributes)
        if CREDENTIAL_FIELD_RE.search(body):
            evidence.phishing_indicators.append(
                "Credential or account input fields detected (email/username/password/card)"
            )

        # Suspicious keywords in the URL path
        try:
            url_path = urlparse(evidence.final_url or "").path.lower()
            hit_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in url_path]
            if hit_keywords:
                evidence.phishing_indicators.append(
                    f"Suspicious path keywords in URL: {', '.join(hit_keywords)}"
                )
        except Exception:
            pass

        # Brand impersonation: known brand name in page but domain doesn't belong to it
        own_host_lower = own_host.lower() if own_host else ""
        for brand in KNOWN_BRANDS:
            if brand in body_lower:
                # Only flag if the domain clearly doesn't belong to that brand
                brand_slug = brand.split()[0]  # e.g. "microsoft", "google", "paypal"
                if brand_slug not in own_host_lower:
                    evidence.phishing_indicators.append(
                        f"Brand impersonation: '{brand}' referenced on non-{brand_slug} domain"
                    )
                    break  # one brand match is enough to flag

        # ── Content analysis: external resources ──
        resource_domains: set[str] = set()
        resource_patterns = [
            re.compile(r'<script[^>]+src\s*=\s*["\']?(https?://[^"\'\s>]+)', re.I),
            re.compile(r'<link[^>]+href\s*=\s*["\']?(https?://[^"\'\s>]+)', re.I),
            re.compile(r'<img[^>]+src\s*=\s*["\']?(https?://[^"\'\s>]+)', re.I),
        ]
        for rp in resource_patterns:
            for match in rp.findall(body):
                try:
                    rd = urlparse(match).hostname
                    if rd and rd != own_host:
                        resource_domains.add(rd)
                except Exception:
                    pass
        evidence.external_resources = sorted(resource_domains)[:20]

        # ── Favicon hash (Shodan-compatible) ──
        try:
            fav_url = f"{response.url.rstrip('/')}/favicon.ico"
            fav_resp = session.get(fav_url, timeout=5, verify=False)
            if fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                from app.utils.hashing import favicon_hash
                evidence.favicon_hash = favicon_hash(fav_resp.content)
        except Exception:
            pass  # Favicon not available — not critical

        # ── Store artifacts ──
        self._store_artifact(
            "response_headers",
            json.dumps(dict(response.headers)),
        )
        self._store_artifact("body_sample", body[:10_000])

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> HTTPEvidence:
        return HTTPEvidence(meta=meta)
