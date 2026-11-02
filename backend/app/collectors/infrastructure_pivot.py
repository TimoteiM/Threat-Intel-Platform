"""
Infrastructure Pivot — post-processing step.

Discovers related domains through:
1. Reverse IP lookup (HackerTarget free API) — what else is hosted on this IP?
2. Nameserver clustering — find domains in our DB sharing the same nameservers
3. Registrant pivot — find domains in our DB sharing the same registrar/registrant_org

Called from analysis_task.py. No API key needed (uses HackerTarget free tier + internal DB).
"""

from __future__ import annotations

import logging

import requests
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import sync_engine

logger = logging.getLogger(__name__)

MAX_DOMAINS_PER_PIVOT = 500


def collect_infrastructure_pivot(
    evidence_data: dict,
    domain: str,
    investigation_id: str,
) -> dict | None:
    """
    Run infrastructure pivot queries and return serialized evidence dict.

    Args:
        evidence_data: Merged collector results
        domain: Domain being investigated
        investigation_id: For logging + excluding self from DB queries

    Returns:
        Serialized InfrastructurePivotEvidence dict, or None if nothing found
    """
    results: dict = {
        "reverse_ip": [],
        "ns_clusters": [],
        "registrant_pivots": [],
        "total_related_domains": 0,
        "shared_hosting_detected": False,
        "notes": [],
    }

    # ── 1. Reverse IP via HackerTarget ──
    hosting = evidence_data.get("hosting", {})
    ip = hosting.get("ip")
    if ip:
        try:
            reverse_ip_domains = _query_hackertarget_reverse_ip(ip)
            if reverse_ip_domains:
                # Exclude the domain itself
                other_domains = [d for d in reverse_ip_domains if d != domain][:MAX_DOMAINS_PER_PIVOT]
                results["reverse_ip"].append({
                    "ip": ip,
                    "domains": other_domains,
                    "total_domains": len(reverse_ip_domains),
                })
                if len(reverse_ip_domains) > 5:
                    results["shared_hosting_detected"] = True
        except Exception as e:
            logger.debug(f"[infra_pivot][{investigation_id}] Reverse IP failed: {e}")
            results["notes"].append(f"Reverse IP lookup failed: {type(e).__name__}")

    # ── 2. Nameserver clustering (internal DB) ──
    dns = evidence_data.get("dns", {})
    nameservers = dns.get("ns", [])
    if nameservers:
        try:
            ns_cluster_domains = _query_ns_cluster(nameservers, investigation_id)
            if ns_cluster_domains:
                results["ns_clusters"].append({
                    "nameservers": nameservers[:5],
                    "domains": ns_cluster_domains[:MAX_DOMAINS_PER_PIVOT],
                })
        except Exception as e:
            logger.debug(f"[infra_pivot][{investigation_id}] NS cluster query failed: {e}")

    # ── 3. Registrant pivot (internal DB) ──
    whois = evidence_data.get("whois", {})
    registrar = whois.get("registrar")
    registrant_org = whois.get("registrant_org")

    if registrar or registrant_org:
        try:
            registrant_domains = _query_registrant_pivot(
                registrar, registrant_org, investigation_id
            )
            if registrant_domains:
                results["registrant_pivots"].append({
                    "registrar": registrar,
                    "registrant_org": registrant_org,
                    "domains": registrant_domains[:MAX_DOMAINS_PER_PIVOT],
                })
        except Exception as e:
            logger.debug(f"[infra_pivot][{investigation_id}] Registrant pivot failed: {e}")

    # Count unique related domains across all pivots
    all_related: set[str] = set()
    for entry in results["reverse_ip"]:
        all_related.update(entry.get("domains", []))
    for entry in results["ns_clusters"]:
        all_related.update(entry.get("domains", []))
    for entry in results["registrant_pivots"]:
        all_related.update(entry.get("domains", []))
    all_related.discard(domain)

    results["total_related_domains"] = len(all_related)

    # Only return if we found something meaningful
    if results["total_related_domains"] == 0 and not results["reverse_ip"]:
        return None

    return results


def _query_hackertarget_reverse_ip(ip: str) -> list[str]:
    """Query HackerTarget free API for reverse IP lookup."""
    resp = requests.get(
        "https://api.hackertarget.com/reverseiplookup/",
        params={"q": ip},
        timeout=15,
    )
    resp.raise_for_status()
    text_body = resp.text.strip()

    # HackerTarget returns error strings on failure
    if not text_body or "error" in text_body.lower() or "API count" in text_body:
        return []

    domains = [line.strip() for line in text_body.splitlines() if line.strip()]
    return domains


def _query_ns_cluster(nameservers: list[str], exclude_investigation_id: str) -> list[str]:
    """
    Find domains in our DB that share any of the given nameservers.
    Queries evidence_json->>'dns'->>'ns' array via PostgreSQL JSONB.
    """
    if not nameservers:
        return []

    found_domains: set[str] = set()

    with Session(sync_engine) as session:
        # For each nameserver, find investigations whose DNS evidence includes it
        for ns in nameservers[:3]:  # Check up to 3 nameservers
            try:
                rows = session.execute(
                    text("""
                        SELECT i.domain
                        FROM investigations i
                        JOIN evidence e ON e.investigation_id = i.id
                        WHERE i.id != :exc_id
                          AND i.state = 'concluded'
                          AND e.evidence_json->'dns'->'ns' @> :ns_val::jsonb
                        LIMIT 20
                    """),
                    {
                        "exc_id": exclude_investigation_id,
                        "ns_val": f'["{ns}"]',
                    },
                ).fetchall()
                for row in rows:
                    found_domains.add(row[0])
            except Exception:
                continue

    return list(found_domains)


def _query_registrant_pivot(
    registrar: str | None,
    registrant_org: str | None,
    exclude_investigation_id: str,
) -> list[str]:
    """
    Find domains in our DB sharing the same registrar or registrant_org.
    """
    if not registrar and not registrant_org:
        return []

    found_domains: set[str] = set()

    with Session(sync_engine) as session:
        conditions = []
        params: dict = {"exc_id": exclude_investigation_id}

        if registrar:
            conditions.append("e.evidence_json->'whois'->>'registrar' = :registrar")
            params["registrar"] = registrar

        if registrant_org:
            conditions.append("e.evidence_json->'whois'->>'registrant_org' = :registrant_org")
            params["registrant_org"] = registrant_org

        where_clause = " OR ".join(conditions)

        try:
            rows = session.execute(
                text(f"""
                    SELECT DISTINCT i.domain
                    FROM investigations i
                    JOIN evidence e ON e.investigation_id = i.id
                    WHERE i.id != :exc_id
                      AND i.state = 'concluded'
                      AND ({where_clause})
                    LIMIT 20
                """),
                params,
            ).fetchall()
            for row in rows:
                found_domains.add(row[0])
        except Exception as e:
            logger.debug(f"Registrant pivot query failed: {e}")

    return list(found_domains)
