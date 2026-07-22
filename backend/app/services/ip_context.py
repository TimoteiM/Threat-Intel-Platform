"""Context-aware IPv4 extraction for SOC logs.

Four dotted integers are syntactically ambiguous: browser/software versions
often have the same shape as IPv4 addresses. These helpers preserve explicit
network fields while rejecting well-scoped version contexts.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_EXPLICIT_IP_FIELD_RE = re.compile(
    r"(?:^|[\s,{])(?:\\*[\"'])?@?(?:src_?ip|source_?ip|dst_?ip|dest(?:ination)?_?ip|client_?ip|"
    r"remote_?ip|local_?ip|host_?ip|agent\.ip|ip)(?:\\*[\"'])?\s*[=:]\s*(?:\\*[\"'])?$",
    re.IGNORECASE,
)
_PRODUCT_VERSION_RE = re.compile(
    r"(?:chrome|crios|firefox|fxios|edg|edge|opr|opera|version|safari|applewebkit|"
    r"mozilla|curl|wget|java|python-requests|okhttp|postmanruntime|filebeat)\s*[/=:]\s*$",
    re.IGNORECASE,
)
_VERSION_FIELD_RE = re.compile(
    r"(?:^|[\s,{])(?:\\*[\"'])?(?:version|build|revision|release|kernel(?:_version)?|os_?version|"
    r"agent\.version|(?:product|browser|software|client|app)_?version)(?:\\*[\"'])?\s*[=:]\s*(?:\\*[\"'])?$",
    re.IGNORECASE,
)


def valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def is_ipv4_indicator_match(text: str, match: re.Match[str]) -> bool:
    """Return whether a regex match is an address in its surrounding context."""
    value = match.group(0)
    if not valid_ipv4(value):
        return False

    prefix = text[max(0, match.start() - 96):match.start()]
    # An explicit network field is authoritative, even when its value happens
    # to resemble a known software version.
    if _EXPLICIT_IP_FIELD_RE.search(prefix):
        return True
    if _PRODUCT_VERSION_RE.search(prefix) or _VERSION_FIELD_RE.search(prefix):
        return False
    return True


def iter_ipv4_indicators(text: str) -> Iterator[re.Match[str]]:
    for match in IPV4_RE.finditer(text or ""):
        if is_ipv4_indicator_match(text or "", match):
            yield match


def first_keyed_ipv4(text: str, field_names: tuple[str, ...]) -> str:
    """Extract the first valid IPv4 value assigned to one of the given keys."""
    if not text or not field_names:
        return ""
    keys = "|".join(re.escape(name) for name in field_names)
    pattern = re.compile(
        rf"(?:^|[\s,{{])@?(?:{keys})\s*[=:]\s*[\"']?(?P<ip>(?:\d{{1,3}}\.){{3}}\d{{1,3}})\b",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        value = match.group("ip")
        if valid_ipv4(value):
            return value
    return ""


__all__ = [
    "IPV4_RE",
    "first_keyed_ipv4",
    "is_ipv4_indicator_match",
    "iter_ipv4_indicators",
    "valid_ipv4",
]
