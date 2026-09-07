"""An unverified community listing must not outvote sources that disagree.

https://www.google.com/ came back malicious at 74/100 with high confidence
while VirusTotal reported 0 of 91 and Google Safe Browsing reported not-listed.
Two things caused it, and both are tested here: OpenPhish matched by substring,
so a phishing URL carrying accounts.google.com in a redirect parameter listed
Google; and a single community listing was enough on its own to return
malicious at the top of the ladder.
"""

from __future__ import annotations

from app.services.decision_engine import community_listing_weight

CLEAN_VT = {"vt_found": True, "vt_total": 91, "vt_malicious": 0, "vt_suspicious": 0}
GSB_CLEAN = {"google_safe_browsing": {"checked": True, "listed": False}}


def test_openphish_alone_does_not_decide_against_a_cleared_host():
    openphish, _phishtank, clean = community_listing_weight(
        {"openphish_listed": True, **GSB_CLEAN}, corroborated=False, **CLEAN_VT
    )
    assert clean is True
    assert openphish is False, "one community feed must not outvote 91 engines and Safe Browsing"


def test_openphish_decides_when_something_else_agrees():
    openphish, _p, _c = community_listing_weight(
        {"openphish_listed": True, **GSB_CLEAN}, corroborated=True, **CLEAN_VT
    )
    assert openphish is True


def test_openphish_decides_when_nothing_authoritative_answered():
    """Absence of evidence is not evidence of absence — the listing stands."""
    openphish, _p, clean = community_listing_weight(
        {"openphish_listed": True},
        corroborated=False,
        vt_found=False, vt_total=0, vt_malicious=0, vt_suspicious=0,
    )
    assert clean is False
    assert openphish is True


def test_safe_browsing_listing_is_corroboration():
    openphish, _p, _c = community_listing_weight(
        {"openphish_listed": True, "google_safe_browsing": {"checked": True, "listed": True}},
        corroborated=False, **CLEAN_VT,
    )
    assert openphish is True


def test_unverified_phishtank_does_not_decide_against_a_cleared_host():
    _o, phishtank, _c = community_listing_weight(
        {"phishtank": {"in_database": True, "verified": False}, **GSB_CLEAN},
        corroborated=False, **CLEAN_VT,
    )
    assert phishtank is False


def test_verified_phishtank_still_decides():
    """Verification is the whole difference — a confirmed report is evidence."""
    _o, phishtank, _c = community_listing_weight(
        {"phishtank": {"in_database": True, "verified": True}, **GSB_CLEAN},
        corroborated=False, **CLEAN_VT,
    )
    assert phishtank is True


def test_a_small_vt_panel_is_not_authoritative():
    """Zero of three engines is silence, not a clearance."""
    _o, _p, clean = community_listing_weight(
        {}, corroborated=False,
        vt_found=True, vt_total=3, vt_malicious=0, vt_suspicious=0,
    )
    assert clean is False


def test_nothing_listed_decides_nothing():
    openphish, phishtank, _c = community_listing_weight(
        {}, corroborated=False, **CLEAN_VT
    )
    assert openphish is False and phishtank is False
