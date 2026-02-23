"""
Geolocation Service — extracts IPs from evidence and resolves to lat/lon.

Uses ip-api.com batch endpoint (free, no API key required, up to 45 req/min).
"""

from __future__ import annotations

import logging

import requests as http_requests

logger = logging.getLogger(__name__)

IP_API_BATCH_URL = "http://ip-api.com/batch"


def extract_geo_points(evidence: dict) -> list[dict]:
    """Extract all IPs from evidence and resolve to geo coordinates."""
    ip_entries: list[dict] = []

    # 1. Hosting IP (ASN evidence)
    hosting = evidence.get("hosting", {})
    if hosting.get("ip"):
        ip_entries.append({
            "ip": hosting["ip"],
            "label": f"Hosting: {hosting['ip']}",
            "type": "hosting",
        })

    # 2. DNS A record IPs
    dns = evidence.get("dns", {})
    hosting_ip = hosting.get("ip")
    for ip in dns.get("a", []):
        if ip != hosting_ip:  # Avoid duplicate of hosting IP
            ip_entries.append({
                "ip": ip,
                "label": f"A Record: {ip}",
                "type": "hosting",
            })

    # 3. MX record IPs (email_security evidence)
    email_sec = evidence.get("email_security", {})
    for mx in email_sec.get("mx_records", []):
        for ip in mx.get("ips", []):
            ip_entries.append({
                "ip": ip,
                "label": f"MX: {mx.get('hostname', '')} ({ip})",
                "type": "mx",
            })

    # 4. Redirect chain IPs
    redirects = evidence.get("redirect_analysis", {})
    for step in redirects.get("redirect_chain", []):
        ip = step.get("ip")
        if ip and ip != hosting_ip:
            ip_entries.append({
                "ip": ip,
                "label": f"Redirect: {step.get('url', '')} ({ip})",
                "type": "redirect",
            })

    # 5. Subdomain IPs
    subdomains = evidence.get("subdomains", {})
    for entry in subdomains.get("interesting_subdomains", [])[:5]:
        for ip in entry.get("ips", []):
            ip_entries.append({
                "ip": ip,
                "label": f"Subdomain: {entry.get('subdomain', '')} ({ip})",
                "type": "subdomain",
            })

    # Deduplicate by IP
    seen: set[str] = set()
    unique: list[dict] = []
    for e in ip_entries:
        if e["ip"] not in seen:
            seen.add(e["ip"])
            unique.append(e)

    if not unique:
        return []

    return _resolve_batch(unique)


def _resolve_batch(entries: list[dict]) -> list[dict]:
    """Resolve IPs to lat/lon using ip-api.com batch endpoint."""
    try:
        payload = [
            {"query": e["ip"], "fields": "lat,lon,country,city,query,status"}
            for e in entries
        ]
        resp = http_requests.post(IP_API_BATCH_URL, json=payload, timeout=10)
        resp.raise_for_status()
        results = resp.json()

        geo_points = []
        for entry, result in zip(entries, results):
            if result.get("status") == "success":
                geo_points.append({
                    "lat": result["lat"],
                    "lon": result["lon"],
                    "label": entry["label"],
                    "type": entry["type"],
                    "country": result.get("country", ""),
                    "city": result.get("city", ""),
                    "ip": entry["ip"],
                })

        return geo_points
    except Exception as e:
        logger.warning(f"IP geolocation batch failed: {e}")
        return []
