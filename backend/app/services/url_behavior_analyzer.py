"""
URL behavior analysis (non-executing HTTP flow + page form heuristics).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests

DEFAULT_UA_SET: tuple[tuple[str, str], ...] = (
    ("browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"),
    ("bot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("mobile", "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/123.0.0.0 Mobile Safari/537.36"),
)


def analyze_url_behavior(url: str, *, timeout: int = 15, max_hops: int = 5) -> dict[str, Any]:
    """
    Analyze redirect and credential-harvesting behavior without script execution.
    """
    chains: list[dict[str, Any]] = []
    final_urls: dict[str, str] = {}
    body_sample = ""
    post_endpoints: list[str] = []
    first_chain_domains: list[str] = []

    for ua_name, ua_value in DEFAULT_UA_SET:
        chain, final_url, html = _fetch_chain(url, ua_value, timeout=timeout, max_hops=max_hops)
        domains = [c.get("host") for c in chain if c.get("host")]
        if ua_name == "browser":
            first_chain_domains = [str(d) for d in domains]
            body_sample = html
            post_endpoints = _extract_post_endpoints(html)
        chains.append({"user_agent": ua_name, "redirect_chain": chain, "final_url": final_url})
        if final_url:
            final_urls[ua_name] = final_url

    unique_finals = {u for u in final_urls.values() if u}
    ua_cloaking = len(unique_finals) > 1
    credential_form = _has_credential_form(body_sample)
    suspicious_post = any(_is_suspicious_post_target(p) for p in post_endpoints)
    unique_domains_in_chain = sorted({d for d in first_chain_domains if d})

    return {
        "checked": True,
        "redirect_count": max(0, len(first_chain_domains) - 1),
        "ua_cloaking_detected": ua_cloaking,
        "credential_form_present": credential_form,
        "suspicious_post_endpoints": post_endpoints[:20],
        "multiple_domain_hops": len(unique_domains_in_chain) > 1,
        "unique_domains_in_chain": unique_domains_in_chain[:20],
        "final_url": final_urls.get("browser"),
        "chains": chains,
        "behavior_score": _behavior_score(
            redirect_count=max(0, len(first_chain_domains) - 1),
            ua_cloaking=ua_cloaking,
            credential_form=credential_form,
            suspicious_post=suspicious_post,
            multi_domain=len(unique_domains_in_chain) > 1,
        ),
    }


def _fetch_chain(url: str, user_agent: str, *, timeout: int, max_hops: int) -> tuple[list[dict[str, Any]], str, str]:
    session = requests.Session()
    session.max_redirects = max_hops
    session.headers.update({"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml"})
    chain: list[dict[str, Any]] = []
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=(not str(url).lower().startswith("http://")))
    except Exception:
        return [], "", ""
    for h in resp.history:
        chain.append(
            {
                "url": str(h.url),
                "status_code": int(h.status_code),
                "host": (urlparse(str(h.url)).hostname or "").lower(),
            }
        )
    chain.append(
        {
            "url": str(resp.url),
            "status_code": int(resp.status_code),
            "host": (urlparse(str(resp.url)).hostname or "").lower(),
        }
    )
    html = ""
    ctype = str(resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype or "<html" in (resp.text[:500] or "").lower():
        html = resp.text[:200_000]
    return chain, str(resp.url or ""), html


def _has_credential_form(html: str) -> bool:
    if not html:
        return False
    lowered = html.lower()
    return 'type="password"' in lowered or "name=\"password\"" in lowered or "autocomplete=\"current-password\"" in lowered


def _extract_post_endpoints(html: str) -> list[str]:
    import re

    if not html:
        return []
    pattern = re.compile(r"<form[^>]+method\s*=\s*[\"']?post[\"']?[^>]*>", re.IGNORECASE)
    action_pattern = re.compile(r"action\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
    out: list[str] = []
    for form in pattern.findall(html):
        m = action_pattern.search(form)
        if m:
            out.append(m.group(1).strip())
    return out


def _is_suspicious_post_target(target: str) -> bool:
    lowered = str(target or "").lower()
    if not lowered:
        return False
    return any(token in lowered for token in ("login", "signin", "verify", "auth", "account", "password"))


def _behavior_score(
    *,
    redirect_count: int,
    ua_cloaking: bool,
    credential_form: bool,
    suspicious_post: bool,
    multi_domain: bool,
) -> float:
    score = 0.0
    score += min(0.2, redirect_count * 0.04)
    if ua_cloaking:
        score += 0.25
    if credential_form:
        score += 0.25
    if suspicious_post:
        score += 0.15
    if multi_domain:
        score += 0.15
    return round(max(0.0, min(1.0, score)), 4)

