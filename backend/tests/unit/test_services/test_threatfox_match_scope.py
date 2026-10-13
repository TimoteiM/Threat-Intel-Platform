"""Which ThreatFox hits are evidence about the observable itself.

The 2026-10-13 audit re-queried all 1,829 domains the feed had silently
failed on. 45 were in ThreatFox, and 44 of those were apex domains of shared
providers: the feed lists them because other people's payloads are hosted
there. `decision_engine` reads the result as `and not tf_matches`, a
precondition for a benign verdict, so restoring the credential with
substring matching intact would have stopped that branch firing for every
case touching Microsoft, Cloudflare or Discord — most cases.
"""

from __future__ import annotations

import pytest

from app.services.threatfox_match_scope import about_observable, is_about


def hit(ioc_value: str, ioc_type: str = "domain") -> dict:
    return {"ioc_value": ioc_value, "ioc_type": ioc_type}


def test_a_url_hosted_on_the_domain_is_not_about_the_domain():
    """discord.com returns ten of these. A malicious webhook on Discord does
    not make Discord malicious."""
    assert not is_about("discord.com", hit(
        "https://discord.com/api/webhooks/1556790836333912135/ASzKY", "url"))


def test_a_different_domain_that_merely_contains_the_string_is_not_a_match():
    """cloudflare.com returns twenty trycloudflare.com subdomains, which are
    not even under cloudflare.com. ThreatFox search is substring-based."""
    assert not is_about("cloudflare.com", hit(
        "ranked-accordingly-ab-hired.trycloudflare.com"))


def test_the_observable_itself_is_a_match():
    assert is_about("grupobiopar.com.br", hit("grupobiopar.com.br"))


def test_a_subdomain_is_not_the_domain():
    assert not is_about("example.com", hit("evil.example.com"))


def test_case_and_trailing_dots_do_not_decide_it():
    assert is_about("Example.COM", hit("example.com."))


def test_an_ip_port_ioc_matches_the_address():
    assert is_about("185.220.101.47", hit("185.220.101.47:8080", "ip:port"))


def test_the_filter_keeps_only_what_is_about_the_observable():
    matches = [
        hit("https://discord.com/api/webhooks/1/x", "url"),
        hit("discord.com"),
        hit("cdn.discordapp.com"),
    ]
    kept = about_observable("discord.com", matches)
    assert [m["ioc_value"] for m in kept] == ["discord.com"]


def test_an_unknown_observable_keeps_every_match():
    """Not knowing what the hits are about is not knowing they are
    irrelevant, and the two must not give the same answer.

    The direction is forced by where this is consumed: `tf_matches` feeds
    `and not tf_matches`, a precondition for benign. Dropping unscopable
    matches unlocks that branch; keeping them only blocks it. My first
    version returned [] here, and the decision-engine suite caught it — a
    fixture with no `domain` key lost its match and a malicious verdict
    became suspicious.
    """
    assert about_observable("", [hit("x.com")]) == [hit("x.com")]
    assert about_observable(None, [hit("x.com")]) == [hit("x.com")]


def test_empty_and_missing_match_lists_do_not_throw():
    assert about_observable("x.com", []) == []
    assert about_observable("x.com", None) == []


def test_the_real_audit_shapes():
    """The three shapes the live API actually returned on 2026-10-13."""
    assert about_observable("discord.com", [
        hit("https://discord.com/api/webhooks/1/a", "url")]) == []
    assert about_observable("cloudflare.com", [
        hit("nowhere-locked-manor-hs.trycloudflare.com")]) == []
    assert len(about_observable("grupobiopar.com.br", [
        hit("grupobiopar.com.br")])) == 1


def test_the_raw_matches_are_not_discarded():
    """Recording what the feed said and deciding what it means are two
    statements. The filter returns a subset; it does not mutate the input."""
    matches = [hit("https://discord.com/api/webhooks/1/x", "url")]
    about_observable("discord.com", matches)
    assert matches == [hit("https://discord.com/api/webhooks/1/x", "url")]


@pytest.mark.parametrize("domain,ioc,expected", [
    ("live.com", "login.live.com", False),
    ("sharepoint.com", "contoso.sharepoint.com", False),
    ("github.io", "someuser.github.io", False),
    ("zoom.us", "zoom.us", True),
])
def test_the_shared_providers_from_the_audit(domain, ioc, expected):
    assert is_about(domain, hit(ioc)) is expected
