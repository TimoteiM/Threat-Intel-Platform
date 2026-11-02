"""
Domain validation and normalization utilities.
"""

from __future__ import annotations

import re
from functools import lru_cache
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


_TLD_EXTRACT = None


def _tld_extractor():
    """
    Shared tldextract instance built from the snapshot bundled with the library.

    `suffix_list_urls=()` disables the public-suffix-list download: this runs on
    the request path (alert-body IOC preview) and inside Celery workers, neither
    of which can afford a network fetch — or a stall — on first call.
    """
    global _TLD_EXTRACT
    if _TLD_EXTRACT is None:
        import tldextract

        _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
    return _TLD_EXTRACT


@lru_cache(maxsize=4096)
def has_public_suffix(domain: str) -> bool:
    """
    True when the value ends in a real public suffix (`.net`, `.co.uk`, `.int`).

    This is what separates a hostname from a filename or a dotted field name:
    `bootx64.efi`, `alert.category` and `snapshot.sh` all have an alphabetic
    trailing label, and none of them is a domain.
    """
    candidate = str(domain or "").strip().strip(".").lower()
    if not candidate or "." not in candidate:
        return False
    try:
        return bool(_tld_extractor()(candidate).suffix)
    except Exception:
        return False


@lru_cache(maxsize=4096)
def extract_registered_domain(domain: str) -> str:
    """
    Extract the registered domain (eTLD+1).

    Handles multi-part TLDs and deep subdomains correctly:
      sub.example.co.uk              → example.co.uk
      revantage.drojifri.solutions   → drojifri.solutions
      exprdsh002.int.expertware.net  → expertware.net
    """
    candidate = str(domain or "").strip().strip(".").lower()
    if not candidate:
        return ""
    try:
        ext = _tld_extractor()(candidate)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    # Fallback (unknown/internal suffix such as .local): take the last two labels.
    parts = candidate.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return candidate
