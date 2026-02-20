"""
Email security analysis — post-processing step that parses DNS evidence
and performs additional queries for DMARC, SPF, DKIM, and MX reputation.

Called from analysis_task.py after collectors complete (not a registered collector).
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Optional

import dns.resolver

logger = logging.getLogger(__name__)

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "s1", "s2", "mail", "dkim", "smtp",
]

# DNS blocklists for MX reputation
MX_BLOCKLISTS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
]


def analyze_email_security(
    domain: str,
    dns_evidence: dict,
    timeout: float = 5.0,
) -> dict:
    """
    Analyze email security posture for a domain.

    Parses existing DMARC/SPF from DNS evidence and performs
    additional DKIM selector discovery and MX blocklist checks.

    Args:
        domain: Target domain
        dns_evidence: DNS collector output dict
        timeout: DNS query timeout in seconds

    Returns:
        Dict matching EmailSecurityEvidence schema
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # Parse existing records from DNS evidence
    dmarc_raw = dns_evidence.get("dmarc")
    spf_raw = dns_evidence.get("spf")
    mx_raw = dns_evidence.get("mx", [])

    # DMARC
    dmarc_parsed = _parse_dmarc(dmarc_raw) if dmarc_raw else {}

    # SPF
    spf_parsed = _parse_spf(spf_raw) if spf_raw else {}

    # DKIM
    dkim_selectors_found, dkim_records = _discover_dkim_selectors(domain, resolver)

    # MX
    mx_records = _resolve_mx_records(mx_raw, resolver)

    # Spoofability
    spoofability, spoofability_reasons = _compute_spoofability(
        dmarc_policy=dmarc_parsed.get("policy"),
        spf_all=spf_parsed.get("all_qualifier"),
        dkim_found=len(dkim_selectors_found) > 0,
    )

    # Score
    email_score = _compute_email_security_score(
        dmarc_raw=dmarc_raw,
        dmarc_policy=dmarc_parsed.get("policy"),
        spf_raw=spf_raw,
        spf_all=spf_parsed.get("all_qualifier"),
        dkim_found=len(dkim_selectors_found) > 0,
        mx_blocklist_count=sum(len(mx.get("blocklist_hits", [])) for mx in mx_records),
    )

    return {
        "dmarc_record": dmarc_raw,
        "dmarc_policy": dmarc_parsed.get("policy"),
        "dmarc_subdomain_policy": dmarc_parsed.get("subdomain_policy"),
        "dmarc_pct": dmarc_parsed.get("pct"),
        "dmarc_rua": dmarc_parsed.get("rua", []),
        "dmarc_ruf": dmarc_parsed.get("ruf", []),
        "dmarc_alignment_dkim": dmarc_parsed.get("adkim"),
        "dmarc_alignment_spf": dmarc_parsed.get("aspf"),
        "spf_record": spf_raw,
        "spf_mechanisms": spf_parsed.get("mechanisms", []),
        "spf_all_qualifier": spf_parsed.get("all_qualifier"),
        "spf_includes": spf_parsed.get("includes", []),
        "spf_ip_count": spf_parsed.get("ip_count"),
        "dkim_selectors_found": dkim_selectors_found,
        "dkim_records": dkim_records,
        "mx_records": mx_records,
        "spoofability_score": spoofability,
        "spoofability_reasons": spoofability_reasons,
        "email_security_score": email_score,
    }


def _parse_dmarc(record: str) -> dict:
    """Parse DMARC record tags into structured dict."""
    result: dict = {}

    # Extract p= (policy)
    m = re.search(r"\bp=(\w+)", record)
    if m:
        result["policy"] = m.group(1).lower()

    # sp= (subdomain policy)
    m = re.search(r"\bsp=(\w+)", record)
    if m:
        result["subdomain_policy"] = m.group(1).lower()

    # pct= (percentage)
    m = re.search(r"\bpct=(\d+)", record)
    if m:
        result["pct"] = int(m.group(1))

    # rua= (aggregate report URI)
    rua_matches = re.findall(r"\brua=([^;\s]+)", record)
    if rua_matches:
        result["rua"] = [uri.strip() for uri in rua_matches[0].split(",")]

    # ruf= (forensic report URI)
    ruf_matches = re.findall(r"\bruf=([^;\s]+)", record)
    if ruf_matches:
        result["ruf"] = [uri.strip() for uri in ruf_matches[0].split(",")]

    # adkim= (DKIM alignment)
    m = re.search(r"\badkim=([rs])", record, re.IGNORECASE)
    if m:
        result["adkim"] = m.group(1).lower()

    # aspf= (SPF alignment)
    m = re.search(r"\baspf=([rs])", record, re.IGNORECASE)
    if m:
        result["aspf"] = m.group(1).lower()

    return result


def _parse_spf(record: str) -> dict:
    """Parse SPF record into mechanisms, includes, and all-qualifier."""
    result: dict = {
        "mechanisms": [],
        "includes": [],
        "all_qualifier": None,
        "ip_count": 0,
    }

    parts = record.split()
    ip_count = 0

    for part in parts:
        part_lower = part.lower().strip()

        # Skip version tag
        if part_lower.startswith("v="):
            continue

        # All mechanism
        if part_lower.endswith("all"):
            qualifier = part_lower.replace("all", "").strip()
            if qualifier == "+" or qualifier == "":
                result["all_qualifier"] = "+all"
            elif qualifier == "-":
                result["all_qualifier"] = "-all"
            elif qualifier == "~":
                result["all_qualifier"] = "~all"
            elif qualifier == "?":
                result["all_qualifier"] = "?all"
            result["mechanisms"].append(part)
            continue

        # Include
        if part_lower.startswith("include:"):
            domain = part_lower.split(":", 1)[1]
            result["includes"].append(domain)
            result["mechanisms"].append(part)
            continue

        # IP mechanisms
        if part_lower.startswith(("ip4:", "ip6:")):
            ip_count += 1
            result["mechanisms"].append(part)
            continue

        # Other mechanisms (a, mx, ptr, exists, redirect)
        result["mechanisms"].append(part)

    result["ip_count"] = ip_count
    return result


def _discover_dkim_selectors(
    domain: str,
    resolver: dns.resolver.Resolver,
) -> tuple[list[str], list[dict]]:
    """Probe common DKIM selectors and return found ones."""
    found_selectors: list[str] = []
    dkim_records: list[dict] = []

    for selector in DKIM_SELECTORS:
        qname = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(qname, "TXT")
            txt_value = " ".join(
                b"".join(rdata.strings).decode("utf-8", errors="replace")
                for rdata in answers
            )

            has_key = "p=" in txt_value
            key_type = None
            kt_match = re.search(r"\bk=(\w+)", txt_value)
            if kt_match:
                key_type = kt_match.group(1)

            found_selectors.append(selector)
            dkim_records.append({
                "selector": selector,
                "public_key_present": has_key,
                "key_type": key_type,
                "notes": None,
            })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.resolver.LifetimeTimeout:
            dkim_records.append({
                "selector": selector,
                "public_key_present": False,
                "key_type": None,
                "notes": "timeout",
            })
        except Exception:
            continue

    return found_selectors, dkim_records


def _resolve_mx_records(
    mx_strings: list[str],
    resolver: dns.resolver.Resolver,
) -> list[dict]:
    """Parse raw MX strings, resolve IPs, and check blocklists."""
    records: list[dict] = []

    for mx_str in mx_strings:
        # Parse "10 mail.example.com." format
        parts = mx_str.strip().split(None, 1)
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 0
            hostname = parts[1].rstrip(".")
        else:
            priority = 0
            hostname = mx_str.strip().rstrip(".")

        # Resolve A records for the MX hostname
        ips: list[str] = []
        try:
            answers = resolver.resolve(hostname, "A")
            ips = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # Check blocklists for each IP
        blocklist_hits: list[str] = []
        for ip in ips:
            for bl in MX_BLOCKLISTS:
                if _check_mx_blocklist(ip, bl):
                    blocklist_hits.append(f"{ip} on {bl}")

        records.append({
            "priority": priority,
            "hostname": hostname,
            "ips": ips,
            "blocklist_hits": blocklist_hits,
        })

    return records


def _check_mx_blocklist(ip: str, blocklist: str) -> bool:
    """Check if an IP is listed in a DNS blocklist."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{blocklist}"
        socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_NUMERICSERV)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def _compute_spoofability(
    dmarc_policy: Optional[str],
    spf_all: Optional[str],
    dkim_found: bool,
) -> tuple[str, list[str]]:
    """Assess how easily the domain can be spoofed in email."""
    reasons: list[str] = []

    has_dmarc = dmarc_policy is not None
    has_spf = spf_all is not None

    # HIGH spoofability
    if not has_spf and not has_dmarc:
        reasons.append("No SPF and no DMARC records — domain is completely unprotected")
        return "high", reasons

    if has_dmarc and dmarc_policy == "none" and spf_all in ("+all", "~all"):
        reasons.append("DMARC policy is 'none' (monitor only) with permissive SPF")
        return "high", reasons

    if not has_dmarc and spf_all in ("+all", "~all"):
        reasons.append("No DMARC and SPF is permissive — spoofed mail will be delivered")
        return "high", reasons

    # MEDIUM spoofability
    if has_dmarc and dmarc_policy == "quarantine" and spf_all == "~all":
        reasons.append("DMARC quarantine with SPF softfail — partial protection")
        return "medium", reasons

    if has_spf and not has_dmarc:
        reasons.append("SPF present but no DMARC — receiving servers may not enforce")
        return "medium", reasons

    if has_dmarc and dmarc_policy == "none":
        reasons.append("DMARC policy is 'none' — monitoring only, no enforcement")
        return "medium", reasons

    # LOW spoofability
    if has_dmarc and dmarc_policy == "reject" and spf_all == "-all" and not dkim_found:
        reasons.append("Strong DMARC + SPF but no DKIM — good but not complete")
        return "low", reasons

    # NONE — fully protected
    if has_dmarc and dmarc_policy == "reject" and spf_all == "-all" and dkim_found:
        reasons.append("DMARC reject + SPF hardfail + DKIM — fully protected")
        return "none", reasons

    # Default to medium if we can't determine clearly
    if has_dmarc and dmarc_policy in ("quarantine", "reject"):
        reasons.append(f"DMARC {dmarc_policy} provides reasonable protection")
        return "low", reasons

    reasons.append("Partial email security configuration")
    return "medium", reasons


def _compute_email_security_score(
    dmarc_raw: Optional[str],
    dmarc_policy: Optional[str],
    spf_raw: Optional[str],
    spf_all: Optional[str],
    dkim_found: bool,
    mx_blocklist_count: int,
) -> int:
    """
    Compute an email security score from 0–100.

    Starts at 100 and subtracts for missing or weak configurations.
    """
    score = 100

    # No DMARC at all
    if not dmarc_raw:
        score -= 30
    elif dmarc_policy == "none":
        score -= 20
    elif dmarc_policy == "quarantine":
        score -= 5

    # No SPF at all
    if not spf_raw:
        score -= 25
    elif spf_all == "+all":
        score -= 25
    elif spf_all == "~all":
        score -= 15
    elif spf_all == "?all":
        score -= 10

    # No DKIM
    if not dkim_found:
        score -= 15

    # MX blocklist hits (cap at -40)
    blocklist_penalty = min(mx_blocklist_count * 20, 40)
    score -= blocklist_penalty

    return max(0, score)
