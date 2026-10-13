"""Host equality in both directions, with every relation shape named.

The scoping work on 2026-10-13 tested one relation and shipped. The test case
was `discord.com` against `https://discord.com/api/webhooks/...` -- the IOC's
host **equals** the observable and the malice is in the path. The shape that
reached production was the reverse: `office.com` against
`nlahtc.theluxehomeoffice.com`, where the observable is a **substring of the
IOC's host**. Both are non-hits, and only the first was ever asserted.

ThreatFox's `search_ioc` is a substring search, so the API returns every
indicator containing the search term. That is the root cause: no amount of
downstream scoping makes a substring query into an exact lookup, which is why
the feed is switched off (`Settings.threatfox_enabled`) rather than merely
filtered.

What actually happened, measured:

    live.com   25 matches, 0 about the observable -> malicious/high/90/block
               (saganlive.com, www82live.com, ...)
    office.com  2 matches, 0 about the observable -> malicious/high/90/block
               (sdoffice.com.br, nlahtc.theluxehomeoffice.com)

Every shape below is a separate test, because a guard that handles one
direction reads as if it handles both.
"""

from __future__ import annotations

import pytest

from app.services.threatfox_match_scope import (
    ELSEWHERE,
    PATH_ON_HOST,
    SAME_HOST,
    UNKNOWN,
    about_observable,
    scope_of,
)


def _match(ioc_value: str, ioc_type: str = "domain") -> dict:
    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "malware_printable": "Test",
        "confidence_level": 100,
    }


# ─── shape 1: exact match. The only hit. ──────────────────────────────────

@pytest.mark.parametrize("observable,ioc", [
    ("nlahtc.theluxehomeoffice.com", "nlahtc.theluxehomeoffice.com"),
    ("grupobiopar.com.br", "grupobiopar.com.br"),
    # Case and trailing dot are not a different host.
    ("Example.COM", "example.com"),
    ("example.com", "example.com."),
])
def test_exact_match_is_a_hit(observable, ioc):
    assert scope_of(observable, ioc) == SAME_HOST
    assert about_observable(observable, [_match(ioc)]) == [_match(ioc)]


# ─── shape 2: the IOC is a path on the observable's host. Not a hit. ──────

@pytest.mark.parametrize("observable,ioc", [
    ("discord.com", "https://discord.com/api/webhooks/938447682266087475/x"),
    ("github.com", "https://github.com/MajorRaikage45/MimiLokinil/releases/v2.6/L.zip"),
    ("www.google.com", "https://www.google.com/share.google?q=HO6vl9qIVbNSnkMuG"),
])
def test_a_path_on_the_observable_is_not_a_hit(observable, ioc):
    """The shape that was tested. A malicious webhook on Discord says a
    webhook is malicious, not that Discord is."""
    assert scope_of(observable, ioc) == PATH_ON_HOST
    assert about_observable(observable, [_match(ioc, "url")]) == []


# ─── shape 3: the observable is a substring of the IOC's host. Not a hit. ─

@pytest.mark.parametrize("observable,ioc,ioc_type", [
    # The two that reached production as malicious/high/block.
    ("office.com", "nlahtc.theluxehomeoffice.com", "domain"),
    ("office.com", "http://sdoffice.com.br/wp-content/plugins/verify/proxy.php", "url"),
    ("live.com", "www82live.com", "domain"),
    ("live.com", "http://saganlive.com:5747", "url"),
    ("live.com", "https://www82live.com/", "url"),
    # A different TLD entirely, which a naive `endswith` would also miss.
    ("example.com", "example.com.br", "domain"),
    ("example.com", "notexample.com", "domain"),
])
def test_the_observable_inside_the_ioc_host_is_not_a_hit(observable, ioc, ioc_type):
    """The shape that was NOT tested, and the one that produced a
    malicious/high/block verdict on two Microsoft apexes."""
    assert scope_of(observable, ioc) == ELSEWHERE, (
        f"{ioc!r} was read as evidence about {observable!r}"
    )
    assert about_observable(observable, [_match(ioc, ioc_type)]) == []


def test_a_real_subdomain_of_the_observable_is_not_a_hit_either():
    """The direction between shapes 2 and 3: the IOC is genuinely *under*
    the observable. `mail.example.com` being malicious does not make
    `example.com` malicious, and this platform investigates apexes."""
    assert scope_of("example.com", "mail.example.com") == ELSEWHERE
    assert about_observable("example.com", [_match("mail.example.com")]) == []


# ─── the composite case, as stored ────────────────────────────────────────

def test_the_live_com_match_set_scopes_to_nothing():
    """The 25 matches that produced malicious/high/90/block, as stored."""
    stored = [
        _match("http://saganlive.com:5747", "url"),
        _match("https://www82live.com/", "url"),
        _match("www82live.com", "domain"),
        _match("saganlive.com", "domain"),
    ]
    assert about_observable("live.com", stored) == []


def test_the_office_com_match_set_scopes_to_nothing():
    stored = [
        _match("http://sdoffice.com.br/wp-content/plugins/verify/proxy.php", "url"),
        _match("nlahtc.theluxehomeoffice.com", "domain"),
    ]
    assert about_observable("office.com", stored) == []


# ─── and the control: scoping must not swallow a real hit ────────────────

def test_a_genuine_listing_survives_every_guard():
    """A guard that drops everything passes every test above. This is the
    one that fails if the scoping is too aggressive -- and it is the shape
    of the single true positive in the whole corpus."""
    stored = [
        _match("nlahtc.theluxehomeoffice.com", "domain"),
        _match("http://sdoffice.com.br/wp-content/x.php", "url"),
    ]
    kept = about_observable("nlahtc.theluxehomeoffice.com", stored)
    assert len(kept) == 1
    assert kept[0]["ioc_value"] == "nlahtc.theluxehomeoffice.com"


def test_an_unknown_observable_keeps_everything():
    """Unscopable is not irrelevant, and these feed `and not tf_matches` --
    a precondition for benign. Dropping what cannot be scoped unlocks that
    branch; keeping it only blocks it."""
    stored = [_match("anything.example", "domain")]
    assert scope_of("", "anything.example") == UNKNOWN
    assert about_observable("", stored) == stored


# ─── the scoping is at the SOURCE, so unscoped consumers cannot be wrong ──

def _collector(domain: str):
    from app.collectors.threat_feeds_collector import ThreatFeedsCollector

    return ThreatFeedsCollector(
        domain=domain,
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=10,
    )


def test_the_collector_stores_only_matches_about_the_observable():
    """30 places read `threatfox_matches` and 2 scoped it. So the scoped
    list takes the name, and every one of the other 28 becomes correct
    without being edited."""
    from app.models.schemas import ThreatFeedEvidence

    ev = ThreatFeedEvidence()
    _collector("live.com")._record_threatfox(ev, [
        _match("http://saganlive.com:5747", "url"),
        _match("www82live.com", "domain"),
        _match("live.com", "domain"),
    ])
    assert [m["ioc_value"] for m in ev.threatfox_matches] == ["live.com"]
    # And the unfiltered answer is kept, because "malware is hosted here" is
    # real context -- just not under the name a decision reads.
    assert len(ev.threatfox_matches_all_hosts) == 3


def test_the_unfiltered_list_is_not_the_name_a_decision_reads():
    """The whole point of the rename. A consumer that never heard of
    scoping reads `threatfox_matches` and gets the safe list."""
    from app.models.schemas import ThreatFeedEvidence

    ev = ThreatFeedEvidence()
    _collector("office.com")._record_threatfox(ev, [
        _match("nlahtc.theluxehomeoffice.com", "domain"),
        _match("http://sdoffice.com.br/wp-content/x.php", "url"),
    ])
    assert ev.threatfox_matches == []
    assert len(ev.threatfox_matches_all_hosts) == 2


def test_both_assignment_sites_go_through_one_helper():
    """Two ThreatFox API callers were fixed separately and one was missed;
    two consumers were scoped and 28 were missed. This asserts the third
    pair cannot diverge, by construction rather than by review."""
    import inspect

    from app.collectors import threat_feeds_collector as m

    src = inspect.getsource(m)
    assert src.count("self._record_threatfox(evidence, result)") == 2
    assert "evidence.threatfox_matches = result" not in src, (
        "an assignment site bypasses the scoping helper"
    )
