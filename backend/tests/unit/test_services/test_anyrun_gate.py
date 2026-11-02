"""When a sandbox detonation is worth its cost.

The gate is inverted from the obvious one. "Detonate when something else
already called it bad" would have skipped all 16 investigations that ANY.RUN
flagged alone — tunnelling services, dynamic DNS, abuse-heavy TLDs, the shapes
reputation misses. Every test here defends that inversion or one of the two
clauses that are still allowed to skip.
"""

from __future__ import annotations

import pytest

from app.services.anyrun_gate import (
    AUTHORITATIVE_PANEL,
    ESTABLISHED_DOMAIN_DAYS,
    NEWLY_REGISTERED_DAYS,
    SETTLED_MALICIOUS_ENGINES,
    should_detonate,
)

CLEAN_PANEL = {"found": True, "malicious_count": 0, "suspicious_count": 0, "total_vendors": 91}


def decide(evidence, kind="domain", excluded=False):
    return should_detonate(evidence, observable_type=kind, excluded=excluded)


# —— what still detonates ————————————————————————————————————————————————

def test_an_unknown_host_detonates():
    """Nobody has looked. This is where the sole detections came from."""
    d = decide({"vt": {"found": False}})
    assert d.run and d.reason == "no_reputation_available"


def test_a_thin_panel_is_not_a_clearance():
    d = decide({"vt": {"found": True, "total_vendors": AUTHORITATIVE_PANEL - 1}})
    assert d.run and d.reason == "no_reputation_available"


def test_a_newly_registered_domain_detonates():
    d = decide({"vt": CLEAN_PANEL, "whois": {"domain_age_days": NEWLY_REGISTERED_DAYS - 1}})
    assert d.run and d.reason == "newly_registered"


def test_a_credential_form_detonates():
    """What a page does after submission is invisible to every static source."""
    d = decide({"vt": CLEAN_PANEL, "whois": {"domain_age_days": 4000},
                "http": {"has_login_form": True}})
    assert d.run and d.reason == "credential_or_brand_signals"


def test_a_file_always_detonates():
    """Silence about a binary someone was sent is not a clearance."""
    assert decide({}, kind="hash").reason == "file_requires_detonation"
    assert decide({}, kind="file").run is True


def test_a_subdomain_of_an_old_parent_still_detonates():
    """photography-buzz.at.ply.gg — malicious, and found by nothing else.

    `ply.gg` is an old, clean tunnelling service. Judging the child by the
    parent's registration skipped exactly the detonation that caught it.
    """
    d = decide({
        "vt": CLEAN_PANEL,
        "whois": {"domain_age_days": 5000},
        "http": {},
        "target_domain": "photography-buzz.at.ply.gg",
    })
    assert d.run is True, "a subdomain does not inherit its parent's history"


def test_an_unresolved_middle_case_detonates():
    """Found, said nothing, not old enough for that silence to reassure."""
    d = decide({"vt": CLEAN_PANEL, "whois": {"domain_age_days": 200}, "http": {}})
    assert d.run and d.reason == "unresolved"


# —— what may skip ————————————————————————————————————————————————————————

def test_an_already_condemned_host_skips():
    """Actionable without a detonation, and a clean sandbox would not acquit it."""
    d = decide({"vt": {"found": True, "malicious_count": SETTLED_MALICIOUS_ENGINES,
                       "total_vendors": 91}})
    assert d.run is False and d.reason == "already_condemned"


@pytest.mark.parametrize("feeds", [
    {"openphish_listed": True},
    {"threatfox_matches": [{"ioc": "x"}]},
    {"google_safe_browsing": {"listed": True}},
])
def test_a_feed_listing_skips(feeds):
    assert decide({"threat_feeds": feeds}).reason == "already_condemned"


def test_an_established_clean_host_skips():
    d = decide({
        "vt": CLEAN_PANEL,
        "whois": {"domain_age_days": ESTABLISHED_DOMAIN_DAYS + 1},
        "http": {},
        "target_domain": "expertware.net",
    })
    assert d.run is False and d.reason == "established_and_clean"


def test_an_excluded_indicator_skips():
    """A human already decided. Spending a licence request to confirm it is waste."""
    assert decide({}, excluded=True).reason == "excluded_by_analyst"


def test_an_exclusion_outranks_a_file():
    assert decide({}, kind="file", excluded=True).run is False


# —— the inversion itself ————————————————————————————————————————————————

def test_a_clean_reputation_does_not_prevent_a_detonation():
    """The whole point. The naive gate skips here; 16 detections lived here."""
    d = decide({"vt": CLEAN_PANEL, "whois": {"domain_age_days": 45}, "http": {}})
    assert d.run is True


def test_the_decision_is_stable():
    evidence = {"vt": CLEAN_PANEL, "whois": {"domain_age_days": 45}}
    assert decide(evidence).as_dict() == decide(evidence).as_dict()


# —— a person asking is itself the reason ————————————————————————————————

SETTLED_CLEAN = {
    "vt": CLEAN_PANEL,
    "whois": {"domain_age_days": ESTABLISHED_DOMAIN_DAYS + 1000},
    "http": {},
    "target_domain": "iana.org",
}


def test_a_manual_investigation_always_detonates():
    """The gate stops automated volume, not an analyst.

    Someone typing a domain into the box is the question; answering it with
    "we decided not to look" is the wrong answer.
    """
    assert should_detonate(SETTLED_CLEAN, observable_type="domain").run is False
    manual = should_detonate(SETTLED_CLEAN, observable_type="domain", manual=True)
    assert manual.run is True and manual.reason == "requested_by_analyst"


def test_manual_outranks_an_already_condemned_verdict():
    d = should_detonate(
        {"vt": {"found": True, "malicious_count": 9, "total_vendors": 91}},
        observable_type="domain", manual=True,
    )
    assert d.run is True and d.reason == "requested_by_analyst"


def test_manual_outranks_the_exclusion_list():
    """Investigating your own corporate domain by hand should still detonate."""
    d = should_detonate({}, observable_type="domain", excluded=True, manual=True)
    assert d.run is True and d.reason == "requested_by_analyst"


def test_automated_runs_are_unaffected_by_the_flag_being_absent():
    assert should_detonate(SETTLED_CLEAN, observable_type="domain").reason == "established_and_clean"
