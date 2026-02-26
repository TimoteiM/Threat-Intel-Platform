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

# Phishing kit indicators (regex patterns)
PHISHING_PATTERNS = [
    (re.compile(r'\beval\s*\(', re.I), "eval() call — potential JS obfuscation"),
    (re.compile(r'\batob\s*\(', re.I), "atob() call — Base64 decoding"),
    (re.compile(r'String\.fromCharCode', re.I), "String.fromCharCode — character encoding"),
    (re.compile(r'\bunescape\s*\(', re.I), "unescape() — URL decoding obfuscation"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write — dynamic content injection"),
    (re.compile(r'api\.telegram\.org/bot', re.I), "Telegram Bot API — credential exfiltration"),
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

        # Login form detection
        evidence.has_login_form = bool(re.search(
            r'type\s*=\s*["\']?password', body, re.I
        ))
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
        form_actions = re.findall(
            r'<form[^>]+action\s*=\s*["\']?(https?://[^"\'\s>]+)',
            body, re.I,
        )
        # For URL type, compare against the hostname, not the full URL string
        own_host = self.target_domain
        for action_url in form_actions:
            try:
                action_domain = urlparse(action_url).hostname
                if action_domain and action_domain != own_host:
                    evidence.phishing_indicators.append(
                        f"Form posts to external domain: {action_domain}"
                    )
            except Exception:
                pass

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
