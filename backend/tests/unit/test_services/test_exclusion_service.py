import os

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import exclusion_service as svc


def _row(indicator_type, normalized_value, **overrides):
    row = {
        "id": f"id-{normalized_value}",
        "indicator_type": indicator_type,
        "value": normalized_value,
        "normalized_value": normalized_value,
        "reason": "corporate estate",
        "added_by": "soc",
        "match_subdomains": True,
    }
    row.update(overrides)
    return row


# ── Normalisation ─────────────────────────────────────────────────────────────


def test_normalize_accepts_what_an_analyst_actually_pastes():
    assert svc.normalize_exclusion("domain", "  HTTPS://WWW.Expertware.NET/login ") == (
        "domain",
        "expertware.net",
    )
    assert svc.normalize_exclusion("hash", "A" * 64) == ("hash", "a" * 64)
    assert svc.normalize_exclusion("ip", "10.0.0.0/8") == ("ip", "10.0.0.0/8")
    assert svc.normalize_exclusion("url", "https://Intranet.Corp.net/app/") == (
        "url",
        "https://intranet.corp.net/app",
    )


def test_normalize_refuses_entries_that_would_whitelist_too_much():
    with pytest.raises(svc.ExclusionError) as excinfo:
        svc.normalize_exclusion("ip", "0.0.0.0/1")
    assert "too broad" in str(excinfo.value)

    for kind, value in [("hash", "not-a-digest"), ("domain", "not a domain"), ("ip", "999.1.1.1")]:
        with pytest.raises(svc.ExclusionError):
            svc.normalize_exclusion(kind, value)

    with pytest.raises(svc.ExclusionError):
        svc.normalize_exclusion("mimetype", "text/plain")


# ── Matching ──────────────────────────────────────────────────────────────────


def test_a_domain_entry_covers_its_subdomains_but_not_lookalikes():
    matcher = svc.ExclusionMatcher([_row("domain", "expertware.net")])

    assert matcher.match("domain", "expertware.net")["value"] == "expertware.net"
    assert matcher.match("domain", "exprdsh002.int.expertware.net") is not None
    # The suffix match is anchored on the dot — this is a different company.
    assert matcher.match("domain", "notexpertware.net") is None
    assert matcher.match("domain", "expertware.net.evil.com") is None


def test_subdomain_matching_can_be_turned_off():
    matcher = svc.ExclusionMatcher([_row("domain", "expertware.net", match_subdomains=False)])

    assert matcher.match("domain", "expertware.net") is not None
    assert matcher.match("domain", "mail.expertware.net") is None


def test_an_excluded_domain_also_covers_urls_pointing_at_it():
    matcher = svc.ExclusionMatcher([_row("domain", "expertware.net")])

    assert matcher.match("url", "https://mail.expertware.net/owa/login") is not None
    assert matcher.match("url", "https://evil-corp.net/login") is None


def test_an_ip_entry_matches_addresses_and_cidr_ranges():
    matcher = svc.ExclusionMatcher(
        [_row("ip", "10.0.0.0/8"), _row("ip", "8.8.8.8")]
    )

    assert matcher.match("ip", "10.4.5.6") is not None
    assert matcher.match("ip", "8.8.8.8") is not None
    assert matcher.match("ip", "8.8.4.4") is None
    assert matcher.match("ip", "not-an-ip") is None


def test_hashes_match_case_insensitively_and_never_across_types():
    matcher = svc.ExclusionMatcher([_row("hash", "a" * 64)])

    assert matcher.match("hash", "A" * 64) is not None
    # The same string as a domain is a different indicator entirely.
    assert matcher.match("domain", "A" * 64) is None


def test_an_empty_list_matches_nothing():
    matcher = svc.ExclusionMatcher([])
    assert not matcher
    assert matcher.match("domain", "expertware.net") is None


# ── Applying ──────────────────────────────────────────────────────────────────


def test_excluded_indicators_stop_being_investigable_but_stay_in_the_report():
    indicators = [
        {"type": "domain", "value": "expertware.net", "investigable": True},
        {"type": "domain", "value": "evil-corp.net", "investigable": True},
        {"type": "ip", "value": "10.1.2.3", "investigable": True},
        # Already skipped for another reason — must not be re-labelled.
        {"type": "ip", "value": "127.0.0.1", "investigable": False, "skip_reason": "private_or_reserved_address"},
    ]
    matcher = svc.ExclusionMatcher([_row("domain", "expertware.net"), _row("ip", "10.0.0.0/8")])

    assert svc.apply_to_indicators(indicators, matcher) == 2

    assert indicators[0]["investigable"] is False
    assert indicators[0]["skip_reason"] == "excluded"
    assert indicators[0]["exclusion"]["reason"] == "corporate estate"
    assert indicators[1]["investigable"] is True          # still investigated
    assert "exclusion" not in indicators[1]
    assert indicators[2]["investigable"] is False
    assert indicators[3]["skip_reason"] == "private_or_reserved_address"


def test_applying_an_empty_list_changes_nothing():
    indicators = [{"type": "domain", "value": "evil-corp.net", "investigable": True}]
    assert svc.apply_to_indicators(indicators, svc.ExclusionMatcher([])) == 0
    assert indicators[0]["investigable"] is True
