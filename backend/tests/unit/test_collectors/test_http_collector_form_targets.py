"""A form posting to the site's own www host is not posting anywhere.

The collector compared hostnames literally, so `otar.nl` posting to
`www.otar.nl` was reported as "Form posts to external domain" — a signal the
decision engine reads as high-confidence evidence of credential theft.
Measured across the stored investigations, five of the fourteen distinct form
targets were the site's own host under another spelling: tarom.ro, otar.nl,
decoder.name, linkedin.com and meubels-van-steigerhout.nl.
"""

from __future__ import annotations

from app.collectors.http_collector import _is_external_form_target as external


def test_www_and_the_apex_are_the_same_site():
    assert not external("www.otar.nl", "otar.nl")
    assert not external("otar.nl", "www.otar.nl")
    assert not external("www.tarom.ro", "tarom.ro")


def test_a_subdomain_is_the_same_site():
    assert not external("cdn.example.com", "example.com")
    assert not external("login.corp.example.com", "example.com")


def test_a_different_registrable_name_is_external():
    assert external("evil.test", "example.com")
    assert external("crm.adflex.com.tr", "adtarget.biz")
    assert external("be-mobile.com", "be-mobile.biz")


def test_a_lookalike_suffix_does_not_count_as_the_same_site():
    """`otar.nl.evil.test` is the attack this signal exists to catch."""
    assert external("otar.nl.evil.test", "otar.nl")
    assert external("example.com.phish.test", "example.com")


def test_two_tenants_of_one_hosting_platform_are_different_sites():
    """The public suffix list does the work, so a page on one github.io site
    posting to another is still posting somewhere else."""
    assert external("attacker.github.io", "victim.github.io")


def test_an_identical_host_is_never_external():
    assert not external("example.com", "example.com")
    assert not external("Example.COM.", "example.com")


def test_missing_values_do_not_raise():
    assert not external("", "example.com")
    assert not external("example.com", "")
