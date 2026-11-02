"""
Subdomain Enumeration — active DNS resolution of discovered subdomains.

NOT a registered collector (doesn't run in the Celery chord).
Runs as post-processing in analysis_task.py after all collectors finish,
since it depends on intel collector's crt.sh results.

Takes a list of subdomains from crt.sh, resolves each via DNS,
groups by IP, and flags interesting subdomains.
"""

from __future__ import annotations

import logging
import socket
from collections import defaultdict

logger = logging.getLogger(__name__)

# Keywords that flag a subdomain as "interesting" for investigation
INTERESTING_KEYWORDS = [
    "admin", "login", "signin", "auth",
    "api", "graphql", "rest",
    "staging", "stage", "stg", "dev", "test", "uat", "qa",
    "vpn", "remote", "rdp", "citrix", "ssh",
    "mail", "smtp", "webmail", "imap", "pop",
    "portal", "dashboard", "panel", "console",
    "cpanel", "phpmyadmin", "plesk", "whm",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
    "jenkins", "gitlab", "jira", "confluence", "sonar", "grafana",
    "internal", "intranet", "corp",
    "ftp", "sftp", "backup", "vault",
]


def enumerate_subdomains(
    parent_domain: str,
    subdomains: list[str],
    max_resolve: int = 100,
    timeout: float = 2.0,
) -> dict:
    """
    Resolve discovered subdomains and produce enumeration evidence.

    Args:
        parent_domain: The investigated parent domain
        subdomains: List of subdomain FQDNs from crt.sh
        max_resolve: Maximum number of subdomains to resolve (performance limit)
        timeout: DNS resolution timeout per subdomain in seconds

    Returns:
        Dict matching SubdomainEvidence schema.
    """
    socket.setdefaulttimeout(timeout)

    discovered_count = len(subdomains)
    resolved = []
    unresolved = []
    ip_groups: dict[str, list[str]] = defaultdict(list)

    # Deduplicate and sort, prioritise interesting ones first
    unique = list(dict.fromkeys(subdomains))
    interesting_first = sorted(
        unique,
        key=lambda s: (0 if _is_interesting(s) else 1, s),
    )

    for subdomain in interesting_first[:max_resolve]:
        ips = _resolve(subdomain)
        interesting = _is_interesting(subdomain)

        if ips:
            resolved.append({
                "subdomain": subdomain,
                "ips": ips,
                "is_interesting": interesting,
            })
            for ip in ips:
                ip_groups[ip].append(subdomain)
        else:
            unresolved.append(subdomain)

    # Extract interesting subset
    interesting_subdomains = [r for r in resolved if r["is_interesting"]]

    # Sort IP groups by count descending (most shared IPs first)
    sorted_ip_groups = dict(
        sorted(ip_groups.items(), key=lambda kv: len(kv[1]), reverse=True)
    )

    logger.info(
        f"Subdomain enumeration for {parent_domain}: "
        f"{discovered_count} discovered, {len(resolved)} resolved, "
        f"{len(interesting_subdomains)} interesting, "
        f"{len(sorted_ip_groups)} unique IPs"
    )

    return {
        "discovered_count": discovered_count,
        "resolved": resolved,
        "unresolved": unresolved,
        "interesting_subdomains": interesting_subdomains,
        "ip_groups": sorted_ip_groups,
    }


def _resolve(subdomain: str) -> list[str]:
    """Resolve a subdomain to IPv4 addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(
            subdomain, None, socket.AF_INET, socket.SOCK_STREAM,
        )
        return list(set(r[4][0] for r in results))
    except (socket.gaierror, socket.timeout, OSError):
        return []


def _is_interesting(subdomain: str) -> bool:
    """Check if subdomain contains any interesting keywords."""
    lower = subdomain.lower()
    # Check each label (part between dots) against keywords
    labels = lower.split(".")
    for label in labels:
        for kw in INTERESTING_KEYWORDS:
            if kw in label:
                return True
    return False
