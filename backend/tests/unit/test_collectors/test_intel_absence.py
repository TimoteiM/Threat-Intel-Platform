"""The intel collector's absences, written before the fix that creates them.

Measured on 2026-10-13, which is what these tests are built from:

  * `meta.status = "failed"` on 2,198 consecutive runs, 2026-07-07 to today.
    Not one `completed` since 2026-05-04. Single cause on every row:
    `RuntimeError: Spamhaus SIA login failed: HTTP 401`, raised from
    `_get_spamhaus_sia_token`, which is called outside any `try`. Steps 1-3
    (crt.sh, the DNSBLs, URLhaus) had already run and their results were
    discarded with the exception.
  * `dbltest.com.dbl.spamhaus.org` -> `127.255.255.254` and
    `test.surbl.org.multi.surbl.org` -> `127.0.0.254`. Both zones answer
    nothing but refusals from this resolver. The Spamhaus family is
    recognised; SURBL's is not, and `127.0.0.254` would be read as a
    reputational response.
  * URLhaus: HTTP 401 with no `Auth-Key`, HTTP 200 with one. Zero URLhaus
    hits have ever been stored, in 400 days.

The order matters. Fixing only the crash would let the refusal codes reach
the hit builder for the first time, and SURBL would then report every domain
in the estate as listed — the fix's own logic being the highest-risk site for
the defect it is fixing, for the third time in two days. So each test below
is written against the direction that does damage, not the direction that
reads correctly.
"""

from __future__ import annotations

import socket

import pytest

from app.collectors.intel_collector import IntelCollector
from app.services.absence import is_absent


class _Probe(IntelCollector):
    """A real IntelCollector with its I/O stubbed and nothing else changed.

    Constructed through `__init__`, not `__new__`: a harness that bypasses
    the subject's own setup is the fifth shape of this platform's recurring
    measurement defect, and it produced an all-clear from the ThreatFox audit
    on 2026-10-13 by turning every hit into an error.
    """

    def _store_artifact(self, *a, **k):
        pass

    def _load_cached_intel(self, *a, **k):
        return None

    def _save_cached_intel(self, *a, **k):
        pass


def _probe(target: str = "example.com") -> _Probe:
    return _Probe(
        domain=target,
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=5,
    )


def _resolver(mapping):
    """A fake getaddrinfo. Keys are query names, values are an IP list, or an
    exception instance to raise."""
    def fake(query, *a, **k):
        if query not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        v = mapping[query]
        if isinstance(v, BaseException):
            raise v
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in v]
    return fake


# ─── the refusal codes must not become hits ───────────────────────────────

@pytest.mark.parametrize(
    "zone,ip",
    [
        ("multi.surbl.org", "127.0.0.254"),        # SURBL: query refused
        ("dbl.spamhaus.org", "127.255.255.254"),   # Spamhaus: public resolver
        ("dbl.spamhaus.org", "127.255.255.252"),   # Spamhaus: typo in zone
        ("dbl.spamhaus.org", "127.255.255.255"),   # Spamhaus: over quota
    ],
)
def test_a_refusal_code_is_not_a_blocklist_hit(monkeypatch, zone, ip):
    """The measured live responses. Both zones return these for every name,
    including names that are definitely not listed, so reading one as a
    listing marks the whole estate malicious."""
    p = _probe("example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({f"example.com.{zone}": [ip]}))
    hits = p._check_dns_blocklists("example.com")
    assert hits == [], f"{ip} from {zone} was read as a reputational listing"


def test_a_refusal_leaves_the_source_unchecked(monkeypatch):
    """And it must not read as "asked, not listed" either. A refused query is
    an absence; the source has to say so, or an empty hit list is the only
    thing downstream sees and it means the opposite."""
    p = _probe("example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "example.com.multi.surbl.org": ["127.0.0.254"],
        "example.com.dbl.spamhaus.org": ["127.255.255.254"],
    }))
    p._check_dns_blocklists("example.com")
    assert "SURBL" not in p.sources_checked
    assert "Spamhaus DBL" not in p.sources_checked
    assert is_absent(p.sources_skipped.get("SURBL"))
    assert is_absent(p.sources_skipped.get("Spamhaus DBL"))


def test_a_real_listing_still_produces_a_hit(monkeypatch):
    """The control. A guard that rejects everything would pass every test
    above and detect nothing."""
    p = _probe("bad.example")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "bad.example.dbl.spamhaus.org": ["127.0.1.2"],
        "bad.example.multi.surbl.org": ["127.0.0.8"],
    }))
    hits = p._check_dns_blocklists("bad.example")
    assert {h.source for h in hits} == {"Spamhaus DBL", "SURBL"}
    assert "SURBL" in p.sources_checked
    assert "Spamhaus DBL" in p.sources_checked


# ─── a resolution failure is not "not listed" ─────────────────────────────

def test_nxdomain_is_a_real_negative(monkeypatch):
    """EAI_NONAME from a DNSBL zone genuinely means not listed. This is the
    one gaierror that is an answer."""
    p = _probe("clean.example")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({}))
    assert p._check_dns_blocklists("clean.example") == []
    assert "Spamhaus DBL" in p.sources_checked


@pytest.mark.parametrize("errno", [socket.EAI_AGAIN, socket.EAI_FAIL])
def test_a_resolution_failure_is_not_a_negative(monkeypatch, errno):
    """SERVFAIL, a timeout, or no resolver at all raise `gaierror` exactly as
    NXDOMAIN does, and the collector's comment called all of them
    "NXDOMAIN = not listed (good)". That is the whole seven-month ThreatFox
    shape, in DNS."""
    p = _probe("example.com")
    boom = socket.gaierror(errno, "Temporary failure in name resolution")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "example.com.multi.surbl.org": boom,
        "example.com.dbl.spamhaus.org": boom,
    }))
    assert p._check_dns_blocklists("example.com") == []
    assert p.sources_checked == []
    assert is_absent(p.sources_skipped.get("SURBL"))


# ─── one source's credential must not discard the others ──────────────────

def test_a_failing_sia_login_keeps_the_dnsbl_result(monkeypatch):
    """The live fault. 2,198 runs lost crt.sh, both DNSBLs and URLhaus to a
    401 on a fourth, unrelated source."""
    p = _probe("bad.example")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "bad.example.dbl.spamhaus.org": ["127.0.1.2"],
    }))
    monkeypatch.setattr(p, "_query_crtsh", lambda *a, **k: ([], [], []))
    monkeypatch.setattr(p, "_check_urlhaus", lambda *a, **k: [])

    def explode(*a, **k):
        raise RuntimeError("Spamhaus SIA login failed: HTTP 401")

    monkeypatch.setattr(p, "_get_spamhaus_sia_token", explode)
    ev = p._collect()
    assert [h.source for h in ev.blocklist_hits] == ["Spamhaus DBL"]
    assert is_absent(ev.sources_skipped.get("Spamhaus SIA"))


def test_the_collector_reports_which_sources_answered(monkeypatch):
    """`blocklist_hits: []` is produced by four sources agreeing, by four
    sources failing, and by the collector never running. Those are different
    claims and the payload has to separate them."""
    p = _probe("example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "example.com.multi.surbl.org": ["127.0.0.254"],   # refused
    }))                                                    # Spamhaus: NXDOMAIN
    monkeypatch.setattr(p, "_query_crtsh", lambda *a, **k: ([], [], []))
    monkeypatch.setattr(p, "_check_urlhaus", lambda *a, **k: [])
    monkeypatch.setattr(p, "_get_spamhaus_sia_token", lambda *a, **k: "")
    ev = p._collect()
    assert ev.blocklist_hits == []
    assert "Spamhaus DBL" in ev.sources_checked
    assert "SURBL" not in ev.sources_checked
    assert is_absent(ev.sources_skipped["SURBL"])


# ─── a cached URLhaus hit must survive the DNSBL pass ─────────────────────

def test_cached_urlhaus_hits_are_not_overwritten(monkeypatch):
    """`evidence.blocklist_hits = blocklist_hits` replaced the list the
    cached URLhaus hits had just been appended to, so on the cache path —
    the common path — a known malware host came back clean."""
    p = _probe("bad.example")
    monkeypatch.setattr(p, "_load_cached_intel", lambda *a, **k: {
        "related_certs": [], "related_subdomains": [], "cert_entries_raw": [],
        "urlhaus_hits": [{
            "source": "URLhaus (abuse.ch)", "indicator": "bad.example",
            "category": "malware_distribution", "severity": "high",
            "details": "cached hit",
        }],
    })
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "bad.example.dbl.spamhaus.org": ["127.0.1.2"],
    }))
    monkeypatch.setattr(p, "_get_spamhaus_sia_token", lambda *a, **k: "")
    ev = p._collect()
    assert {h.source for h in ev.blocklist_hits} == {
        "URLhaus (abuse.ch)", "Spamhaus DBL",
    }
