"""
HTTP Collector — probes the domain over HTTPS (fallback HTTP).

Captures: reachability, redirect chain, response headers, page title,
login form detection, security headers, server fingerprint.
"""

from __future__ import annotations

import json
import logging
import re

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

    def _collect(self) -> HTTPEvidence:
        evidence = HTTPEvidence()
        session = requests.Session()
        session.max_redirects = 10
        session.headers.update({
            "User-Agent": "ThreatInvestigator/1.0 (Security Research)",
            "Accept": "text/html,application/xhtml+xml",
        })

        # ── Try HTTPS first, fall back to HTTP ──
        response = None
        for scheme in ("https", "http"):
            try:
                response = session.get(
                    f"{scheme}://{self.domain}",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=(scheme == "https"),
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

        # ── Store artifacts ──
        self._store_artifact(
            "response_headers",
            json.dumps(dict(response.headers)),
        )
        self._store_artifact("body_sample", body[:10_000])

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> HTTPEvidence:
        return HTTPEvidence(meta=meta)
