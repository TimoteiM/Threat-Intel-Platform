"""
Redirect chain analysis — multi-UA cloaking detection, intermediate domain
reputation, and evasion technique identification.

Called from analysis_task.py as a post-processing step (not a registered collector).
Uses requests (lightweight, no Playwright needed).
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# User-Agent strings for cloaking detection
USER_AGENTS = {
    "browser": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "googlebot": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    "mobile": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ),
}

# Known URL shorteners / redirectors
KNOWN_REDIRECTORS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "tiny.cc",
}

# Known ad/tracking redirect domains
KNOWN_TRACKERS = {
    "clickserve.dartsearch.net", "doubleclick.net", "googleadservices.com",
    "googlesyndication.com", "facebook.com", "ad.doubleclick.net",
    "analytics.google.com", "t.co", "l.facebook.com", "lnkd.in",
}


def analyze_redirects(domain: str, timeout: int = 15) -> dict:
    """
    Probe a domain with multiple user agents and analyze redirect behavior.

    Detects UA-based cloaking, bot blocking, excessive redirects,
    tracker chains, and protocol downgrades.

    Args:
        domain: Target domain
        timeout: HTTP request timeout in seconds

    Returns:
        Dict matching RedirectAnalysisEvidence schema
    """
    probes = []
    for ua_type, ua_string in USER_AGENTS.items():
        probe = _probe_with_ua(domain, ua_type, ua_string, timeout)
        probes.append(probe)

    # Cloaking detection
    cloaking_detected, cloaking_details = _detect_cloaking(probes)

    # Intermediate domain analysis
    intermediate_domains = _analyze_intermediate_domains(probes)

    # Evasion techniques
    evasion_techniques = _detect_evasion_techniques(probes, intermediate_domains)

    # Max chain length across all probes
    max_chain = max((p.get("redirect_count", 0) for p in probes), default=0)

    # Check for potential geo-blocking (all probes fail with same error)
    has_geo_block = None
    failed_count = sum(1 for p in probes if p.get("status_code", 0) == 0)
    if failed_count == len(probes):
        has_geo_block = True  # All probes failed, could be geo-block

    return {
        "probes": probes,
        "cloaking_detected": cloaking_detected,
        "cloaking_details": cloaking_details,
        "intermediate_domains": intermediate_domains,
        "evasion_techniques": evasion_techniques,
        "max_chain_length": max_chain,
        "has_geo_block": has_geo_block,
    }


def _probe_with_ua(
    domain: str,
    ua_type: str,
    ua_string: str,
    timeout: int,
) -> dict:
    """Send a request with a specific User-Agent and capture redirect chain."""
    # Accept both bare domains ("phishing.com") and full URLs ("https://phishing.com/path")
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    session = requests.Session()
    session.headers["User-Agent"] = ua_string

    try:
        resp = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )

        # Build redirect chain info
        redirect_count = len(resp.history)

        # Title extraction
        title = None
        ct = resp.headers.get("Content-Type", "")
        if "text/html" in ct:
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>",
                resp.text[:5000],
                re.IGNORECASE | re.DOTALL,
            )
            if title_match:
                title = title_match.group(1).strip()[:200]

        # Content hash
        content_hash = hashlib.sha256(resp.content).hexdigest()

        # Build chain list
        chain = []
        for r in resp.history:
            chain.append({
                "url": r.url,
                "status_code": r.status_code,
            })
        chain.append({
            "url": resp.url,
            "status_code": resp.status_code,
        })

        return {
            "user_agent_type": ua_type,
            "user_agent": ua_string,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_count": redirect_count,
            "title": title,
            "content_hash": content_hash,
            "chain": chain,
        }

    except requests.exceptions.SSLError:
        # Try HTTP fallback
        try:
            resp = session.get(
                f"http://{domain}",
                timeout=timeout,
                allow_redirects=True,
            )
            content_hash = hashlib.sha256(resp.content).hexdigest()
            return {
                "user_agent_type": ua_type,
                "user_agent": ua_string,
                "status_code": resp.status_code,
                "final_url": resp.url,
                "redirect_count": len(resp.history),
                "title": None,
                "content_hash": content_hash,
                "chain": [],
            }
        except Exception:
            pass

        return {
            "user_agent_type": ua_type,
            "user_agent": ua_string,
            "status_code": 0,
            "final_url": "",
            "redirect_count": 0,
            "title": None,
            "content_hash": "",
            "chain": [],
        }

    except Exception as e:
        logger.debug(f"Probe {ua_type} failed for {domain}: {e}")
        return {
            "user_agent_type": ua_type,
            "user_agent": ua_string,
            "status_code": 0,
            "final_url": "",
            "redirect_count": 0,
            "title": None,
            "content_hash": "",
            "chain": [],
        }


def _detect_cloaking(probes: list[dict]) -> tuple[bool, list[str]]:
    """
    Compare probe results to detect UA-based cloaking.

    IMPORTANT: Different content hashes alone do NOT indicate cloaking.
    Legitimate sites routinely serve different HTML to different UAs
    (responsive design, Googlebot-optimized rendering, dynamic ads, A/B tests).

    True cloaking = different final URLs, different status codes, or
    bot blocking (403/429 for bots while browser gets 200). Content hash
    differences are noted as informational only.
    """
    details: list[str] = []
    cloaking = False

    # Need at least 2 successful probes to compare
    successful = [p for p in probes if p.get("status_code", 0) > 0]
    if len(successful) < 2:
        return False, []

    # Compare final URLs — different destinations is real cloaking
    final_urls = {p["user_agent_type"]: p["final_url"] for p in successful if p.get("final_url")}
    unique_urls = set(final_urls.values())

    if len(unique_urls) > 1:
        cloaking = True
        details.append(
            f"Different final URLs per User-Agent: "
            f"{', '.join(f'{k}={v}' for k, v in final_urls.items())}"
        )

    # Compare status codes — different status codes is real cloaking
    statuses = {p["user_agent_type"]: p["status_code"] for p in successful}
    unique_statuses = set(statuses.values())

    if len(unique_statuses) > 1:
        cloaking = True
        details.append(
            f"Different status codes per User-Agent: "
            f"{', '.join(f'{k}={v}' for k, v in statuses.items())}"
        )

    # Content hash differences are informational — NOT cloaking by themselves
    hashes = {p["user_agent_type"]: p["content_hash"] for p in successful if p.get("content_hash")}
    unique_hashes = set(hashes.values())

    if len(unique_hashes) > 1:
        details.append(
            f"Content varies across User-Agents (common for responsive/dynamic sites): "
            f"{', '.join(f'{k}={v[:12]}...' for k, v in hashes.items())}"
        )

    return cloaking, details


def _analyze_intermediate_domains(probes: list[dict]) -> list[dict]:
    """Extract and classify unique intermediate domains from redirect chains."""
    seen: dict[str, dict] = {}

    for probe in probes:
        chain = probe.get("chain", [])
        for hop_num, hop in enumerate(chain):
            url = hop.get("url", "")
            domain = _extract_domain(url)
            if domain and domain not in seen:
                seen[domain] = {
                    "domain": domain,
                    "hop_number": hop_num,
                    "is_known_tracker": _is_known_tracker(domain),
                    "is_known_redirector": _is_known_redirector(domain),
                }

    return list(seen.values())


def _detect_evasion_techniques(
    probes: list[dict],
    intermediate_domains: list[dict],
) -> list[str]:
    """Identify evasion techniques from probe results."""
    techniques: list[str] = []

    successful = [p for p in probes if p.get("status_code", 0) > 0]

    # UA cloaking — only flag when final URLs or status codes differ
    final_urls = set(p.get("final_url", "") for p in successful if p.get("final_url"))
    statuses = set(p.get("status_code", 0) for p in successful)
    if len(final_urls) > 1 or len(statuses) > 1:
        techniques.append("UA-based cloaking detected (different URLs or status codes)")

    # Bot blocking: bot gets 403/429 while browser succeeds
    browser_probe = next((p for p in probes if p["user_agent_type"] == "browser"), None)
    bot_probe = next((p for p in probes if p["user_agent_type"] == "googlebot"), None)

    if browser_probe and bot_probe:
        browser_ok = 200 <= (browser_probe.get("status_code", 0)) < 400
        bot_blocked = (bot_probe.get("status_code", 0)) in (403, 429, 0)
        if browser_ok and bot_blocked:
            techniques.append(
                f"Bot blocking detected: browser={browser_probe.get('status_code')}, "
                f"Googlebot={bot_probe.get('status_code')}"
            )

    # Excessive redirects
    for p in probes:
        if p.get("redirect_count", 0) > 5:
            techniques.append(
                f"Excessive redirects ({p['redirect_count']} hops) "
                f"for {p['user_agent_type']} User-Agent"
            )
            break

    # Tracker chains
    tracker_domains = [d for d in intermediate_domains if d.get("is_known_tracker")]
    if tracker_domains:
        names = [d["domain"] for d in tracker_domains[:3]]
        techniques.append(f"Redirect chain passes through known trackers: {', '.join(names)}")

    # Protocol downgrade (HTTPS -> HTTP)
    for p in successful:
        chain = p.get("chain", [])
        for i in range(len(chain) - 1):
            current_url = chain[i].get("url", "")
            next_url = chain[i + 1].get("url", "")
            if current_url.startswith("https://") and next_url.startswith("http://"):
                techniques.append(
                    f"Protocol downgrade: HTTPS->HTTP redirect in {p['user_agent_type']} chain"
                )
                break

    return techniques


def _extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def _is_known_tracker(domain: str) -> bool:
    """Check if a domain is a known ad/tracking service."""
    domain_lower = domain.lower()
    for tracker in KNOWN_TRACKERS:
        if domain_lower == tracker or domain_lower.endswith(f".{tracker}"):
            return True
    return False


def _is_known_redirector(domain: str) -> bool:
    """Check if a domain is a known URL shortener/redirector."""
    return domain.lower() in KNOWN_REDIRECTORS
