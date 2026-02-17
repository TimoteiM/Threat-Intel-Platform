"""
Domain validation and normalization utilities.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# Valid domain regex (simplified but practical)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def normalize_domain(raw: str) -> str:
    """
    Clean up user input into a bare domain.

    Handles:
    - https://example.com/path → example.com
    - www.example.com → example.com
    - EXAMPLE.COM → example.com
    - example.com/ → example.com
    """
    domain = raw.strip().lower()

    # Strip protocol
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain

    # Strip www prefix
    if domain.startswith("www."):
        domain = domain[4:]

    # Strip trailing slash/path
    domain = domain.split("/")[0]

    # Strip port
    domain = domain.split(":")[0]

    return domain


def validate_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    return DOMAIN_PATTERN.match(domain) is not None


def extract_tld(domain: str) -> str:
    """Extract the TLD from a domain (simple version)."""
    parts = domain.split(".")
    return parts[-1] if parts else ""


def extract_registered_domain(domain: str) -> str:
    """
    Extract the registered domain (eTLD+1).

    Handles multi-part TLDs correctly:
      sub.example.co.uk → example.co.uk
      revantage.drojifri.solutions → drojifri.solutions
    """
    try:
        import tldextract
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    # Fallback: take last two parts
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain
