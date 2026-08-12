"""
The enrichment subagent's SSRF guard.

Tool arguments come from a model reading attacker-controlled evidence — page bodies, DNS
records, certificate subjects — so a target can be proposed by the attacker. Without
`_reject_private` these tools are an SSRF primitive pointed at whatever the host can
reach, including the cloud metadata endpoint.

Offline: `_reject_private` is pure address arithmetic and makes no lookup.
"""

from __future__ import annotations

import pytest

from app.analyst.enrichment_tools import _reject_private

REFUSED = [
    ("127.0.0.1", "loopback"),
    ("10.0.0.1", "RFC1918"),
    ("192.168.1.1", "RFC1918"),
    ("172.16.0.1", "RFC1918"),
    ("169.254.169.254", "link-local cloud metadata"),
    ("224.0.0.1", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("::1", "IPv6 loopback"),
    ("fd00::1", "IPv6 unique-local"),
    ("fe80::1", "IPv6 link-local"),
    ("not-an-ip", "not an address"),
    ("", "empty"),
    ("8.8.8.8; rm -rf /", "injection attempt"),
    ("localhost", "hostname, not an address"),
]

ALLOWED = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]


@pytest.mark.parametrize("address,why", REFUSED, ids=[a or "empty" for a, _ in REFUSED])
def test_non_public_addresses_are_refused(address, why):
    refusal = _reject_private(address)

    assert refusal is not None, f"{address} ({why}) was not refused"
    # The refusal is returned to the model as a tool result, so it has to read as an
    # answer rather than as a crash.
    assert address in refusal or "not a valid IP" in refusal


@pytest.mark.parametrize("address", ALLOWED)
def test_public_addresses_are_allowed(address):
    assert _reject_private(address) is None


def test_whitespace_around_a_public_address_is_tolerated():
    assert _reject_private("  8.8.8.8  ") is None


def test_the_guarded_tools_refuse_before_making_any_request(monkeypatch):
    """A refusal must short-circuit, not merely annotate a request that already went out."""
    import app.analyst.enrichment_tools as tools

    def _no_network(*args, **kwargs):
        raise AssertionError("a request was made for a non-public address")

    monkeypatch.setattr(tools.requests, "get", _no_network)
    monkeypatch.setattr(tools.socket, "gethostbyaddr", _no_network)

    assert "Refusing" in tools.lookup_ip_reputation.invoke({"ip": "169.254.169.254"})
    assert "Refusing" in tools.reverse_dns.invoke({"ip": "127.0.0.1"})


def test_resolve_hostname_rejects_unsupported_record_types():
    from app.analyst.enrichment_tools import resolve_hostname

    result = resolve_hostname.invoke({"hostname": "example.com", "record_type": "ANY"})

    assert "Unsupported record type" in result
