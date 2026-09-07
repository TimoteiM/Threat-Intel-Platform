"""OpenPhish must match a host, never a substring of a URL.

The two feed entries that made https://www.google.com/ malicious were a
phishing page hosted at sites.google.com, and a phishing URL on an unrelated
domain that carried accounts.google.com inside a redirect query parameter.
Neither says anything about www.google.com.
"""

from __future__ import annotations

from urllib.parse import urlparse


def match(feed_lines: list[str], wanted: str) -> tuple[bool, list[str]]:
    """The matching rule as implemented in ThreatFeedsCollector._query_openphish."""
    wanted = wanted.strip().lower().rstrip(".")
    exact = False
    related: list[str] = []
    for line in feed_lines:
        entry = line.strip()
        if not entry:
            continue
        try:
            host = (urlparse(entry).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host:
            continue
        if host == wanted:
            exact = True
        elif host.endswith("." + wanted) and host not in related:
            related.append(host)
    return exact, related


THE_REAL_FEED_LINES = [
    "https://sites.google.com/view/orange-secu/accueil?clckid=7d0814bc",
    "https://www.wegoupupup.com/v3/signin/identifier?continue=https://accounts.google.com/o/oauth2/programmatic_auth",
]


def test_a_redirect_parameter_does_not_list_the_host_it_names():
    listed, _related = match(THE_REAL_FEED_LINES, "www.google.com")
    assert listed is False


def test_a_page_on_a_shared_subdomain_does_not_list_the_parent():
    listed, related = match(THE_REAL_FEED_LINES, "google.com")
    assert listed is False
    assert "sites.google.com" in related, "recorded, but as a related host, not a listing"


def test_the_host_that_is_actually_listed_is_listed():
    listed, _related = match(THE_REAL_FEED_LINES, "sites.google.com")
    assert listed is True


def test_a_subdomain_is_not_its_parent():
    listed, _r = match(["http://login.evil.com/x"], "evil.com")
    assert listed is False, "the phishing is on login.evil.com, not on evil.com"


def test_an_unparseable_line_is_skipped():
    listed, related = match(["", "   ", "not a url at all"], "evil.com")
    assert listed is False and related == []


def test_a_trailing_dot_is_not_a_different_host():
    listed, _r = match(["http://evil.com./x"], "evil.com")
    assert listed is True
