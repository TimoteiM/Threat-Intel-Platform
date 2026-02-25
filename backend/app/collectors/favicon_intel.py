"""
Favicon Hash Intelligence — post-processing step.

Queries Shodan for other hosts sharing the same favicon hash.
This reveals infrastructure relationships and phishing kit reuse
(e.g., same phishing panel deployed across multiple IPs).

Called from analysis_task.py after JS analysis, NOT a registered collector.
Requires SHODAN_API_KEY in settings.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from app.config import get_settings

logger = logging.getLogger(__name__)

# Favicon hashes that are so common they're not meaningful for pivoting
COMMON_FAVICON_HASHES = {
    "81586312",    # Apache default
    "-1644390083", # WordPress default
    "708578159",   # Bootstrap
    "116323821",   # Nginx default
    "-1534671546", # IIS default
    "1321126983",  # Cloudflare
    "2062375",     # nginx welcome
}


def collect_favicon_intel(
    evidence_data: dict,
    domain: str,
    investigation_id: str,
) -> dict | None:
    """
    Query Shodan for hosts sharing the same favicon hash.

    Args:
        evidence_data: Merged collector results dict
        domain: Domain being investigated
        investigation_id: For logging

    Returns:
        Serialized FaviconIntelEvidence dict, or None if skipped
    """
    settings = get_settings()
    if not settings.shodan_api_key:
        logger.debug(f"[favicon_intel] Skipped — no Shodan API key configured")
        return None

    http = evidence_data.get("http", {})
    favicon_hash = http.get("favicon_hash")
    if not favicon_hash:
        logger.debug(f"[favicon_intel][{investigation_id}] No favicon hash in HTTP evidence, skipping")
        return None

    is_default = favicon_hash in COMMON_FAVICON_HASHES

    try:
        result = _query_shodan_favicon(favicon_hash, settings.shodan_api_key)
    except Exception as e:
        logger.warning(f"[favicon_intel][{investigation_id}] Shodan query failed: {e}")
        return None

    hosts = result.get("matches", [])
    total = result.get("total", 0)

    parsed_hosts = []
    for host in hosts[:50]:  # cap at 50 results
        parsed_hosts.append({
            "ip": host.get("ip_str", ""),
            "hostnames": host.get("hostnames", []),
            "org": host.get("org"),
            "port": host.get("port", 80),
            "asn": host.get("asn"),
            "country": host.get("location", {}).get("country_code"),
        })

    notes: list[str] = []
    if is_default:
        notes.append("This favicon hash corresponds to a common default page — pivot results may not be meaningful")
    if total > 50:
        notes.append(f"Shodan returned {total} total matches; showing first 50")

    return {
        "favicon_hash": favicon_hash,
        "total_hosts_sharing": total,
        "hosts": parsed_hosts,
        "is_unique_favicon": total <= 3,
        "is_default_favicon": is_default,
        "notes": notes,
    }


def _query_shodan_favicon(favicon_hash: str, api_key: str) -> dict[str, Any]:
    """Query Shodan search API for a given favicon hash."""
    resp = requests.get(
        "https://api.shodan.io/shodan/host/search",
        params={
            "key": api_key,
            "query": f"http.favicon.hash:{favicon_hash}",
            "minify": "true",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
