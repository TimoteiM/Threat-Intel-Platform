"""A case holds alerts that are tied together, not alerts that share a device.

Membership used to be `(source, client, host)` plus a time split: everything on
one machine, cut only where the clock showed a six-hour gap. Measured over
11,359 alerts and 664 cases:

  * 96 cases mixed different detections, and in only 12% of those did every
    member share an indicator with another member;
  * 55 cases were built by *chaining* — each consecutive gap under six hours
    while the ends drifted up to 23.8 hours apart;
  * one real case held a password change at 11:43, a system critical event at
    17:44 and a .NET crash at 18:56, and the page reported three independent
    detections agreeing on the entity.

After: 884 cases, 91 sessions split, mixed-detection cases 96 -> 27, and the
182 repeat-detection cases untouched.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.alert_case_linkage_service import (
    UBIQUITY_HOST_LIMIT,
    cluster_linked,
    linking_signals,
    ubiquitous_values,
)

T0 = datetime(2026, 9, 24, 11, 43, tzinfo=timezone.utc)


def alert(name, *, minutes=0, host="EXPSQL004", user=None, iocs=(), run_id=None):
    return SimpleNamespace(
        id=run_id or f"{name}-{minutes}",
        entity_host=host,
        entity_user=user,
        detection_name=name,
        detection_rule_id=None,
        detection_rule_name=None,
        when=T0 + timedelta(minutes=minutes),
        ioc_values=list(iocs),
    )


def iocs_of(row):
    return row.ioc_values


def names(groups):
    return [sorted({a.detection_name for a in g}) for g in groups]


# --- the report that prompted this -------------------------------------------

def test_a_password_change_a_crash_and_a_critical_event_are_three_cases():
    """The case from the review, to the minute. Nothing ties these together
    but the machine and the afternoon."""
    session = [
        alert("User Account Password Last Set Value Changed", minutes=0),
        alert("Windows System critical event", minutes=361),
        alert("A .NET application crashed due to an unhandled exception", minutes=433),
    ]

    groups = cluster_linked(session, iocs_of, ubiquitous=set())

    assert len(groups) == 3
    assert names(groups) == [
        ["User Account Password Last Set Value Changed"],
        ["Windows System critical event"],
        ["A .NET application crashed due to an unhandled exception"],
    ]


def test_the_same_detection_repeating_stays_one_case():
    """182 of the 278 multi-alert cases were this, and they are real cases.
    Splitting them would be a worse answer than the one being replaced."""
    session = [alert("Repeated injection-capable access by process", minutes=m)
               for m in (0, 4, 9, 300)]

    assert len(cluster_linked(session, iocs_of, ubiquitous=set())) == 1


# --- what ties alerts together -----------------------------------------------

def test_a_shared_indicator_ties_two_different_detections():
    session = [
        alert("PowerShell Created Executable File", minutes=0, iocs=["asiemmetry.eu"]),
        alert("Double-Extension Executable File Creation", minutes=40,
              iocs=["asiemmetry.eu", "203.0.113.7"]),
    ]
    assert len(cluster_linked(session, iocs_of, ubiquitous=set())) == 1


def test_linking_is_transitive_because_an_intrusion_is_a_chain():
    """A shares a hash with B, B shares an address with C. The stages of an
    intrusion do not each carry every indicator."""
    session = [
        alert("Office Spawned Executable", minutes=0, iocs=["abc123"]),
        alert("LOLBin Payload Staging", minutes=20, iocs=["abc123", "203.0.113.7"]),
        alert("Shellcode Process Access", minutes=45, iocs=["203.0.113.7"]),
    ]

    groups = cluster_linked(session, iocs_of, ubiquitous=set())

    assert len(groups) == 1
    assert len(groups[0]) == 3


def test_the_same_account_ties_alerts_together():
    session = [
        alert("Suspicious RC4 Kerberos Service Ticket Request", minutes=0, user="CORP\\jdoe"),
        alert("User account locked out", minutes=120, user="CORP\\jdoe"),
        alert("A .NET application crashed", minutes=130, user="CORP\\other"),
    ]

    groups = cluster_linked(session, iocs_of, ubiquitous=set())

    assert len(groups) == 2
    assert len(groups[0]) == 2


def test_either_half_of_a_domain_qualified_account_matches():
    """One alert carries CORP\\jdoe and another carries jdoe. Reading those as
    two accounts splits a case that is one person."""
    both = linking_signals(alert("x", user="CORP\\jdoe"), iocs_of, ubiquitous=set())
    assert "user:corp\\jdoe" in both
    assert "user:jdoe" in both


# --- what must not tie alerts together ---------------------------------------

def test_the_device_does_not_tie_anything_because_every_member_shares_it():
    """The same mistake, in the same codebase, made every retrieved log event
    'relevant' and matched every tenant on 'Manager: Siembiot'."""
    signals = linking_signals(alert("some detection", host="EXPSQL004"), iocs_of,
                              ubiquitous=set())
    assert not any("EXPSQL004".casefold() in s for s in signals if s.startswith("ioc:"))
    assert all(s.startswith(("detection:", "user:", "ioc:")) for s in signals)


def test_an_indicator_carried_across_the_estate_does_not_link():
    """`expertware.net` is on 130 distinct hosts, a Microsoft schema URL on 47.
    Letting those link alerts rebuilds the case this replaces."""
    estate = [alert("d", host=f"HOST-{i}", iocs=["expertware.net"]) for i in range(40)]
    ubiquitous = ubiquitous_values(estate, iocs_of)
    assert "expertware.net" in ubiquitous

    session = [
        alert("Password Last Set Changed", minutes=0, iocs=["expertware.net"]),
        alert(".NET crash", minutes=400, iocs=["expertware.net"]),
    ]
    assert len(cluster_linked(session, iocs_of, ubiquitous=ubiquitous)) == 2


def test_ubiquity_is_counted_in_devices_not_in_alerts():
    """A value in a thousand alerts on one busy host may be the single most
    useful thing about that host. A value on forty hosts is infrastructure
    however rarely each one mentions it."""
    busy = [alert("d", host="ONE-HOST", minutes=i, iocs=["203.0.113.7"]) for i in range(500)]
    assert ubiquitous_values(busy, iocs_of) == set()

    spread = [alert("d", host=f"H{i}", iocs=["10.0.0.1"]) for i in range(UBIQUITY_HOST_LIMIT + 1)]
    assert "10.0.0.1" in ubiquitous_values(spread, iocs_of)


def test_a_campaign_across_a_few_machines_still_links():
    """The threshold is deliberately generous: a real campaign touching five
    machines leaves its address on five hosts, and must still tie the alerts
    together on each one."""
    campaign = [alert("d", host=f"H{i}", iocs=["203.0.113.7"]) for i in range(5)]
    assert "203.0.113.7" not in ubiquitous_values(campaign, iocs_of)


def test_an_empty_hash_is_never_evidence():
    session = [
        alert("A", minutes=0, iocs=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]),
        alert("B", minutes=300, iocs=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]),
    ]
    assert len(cluster_linked(session, iocs_of, ubiquitous=set())) == 2


# --- shape -------------------------------------------------------------------

def test_an_alert_that_ties_to_nothing_becomes_its_own_case():
    session = [
        alert("A", minutes=0, iocs=["x"]),
        alert("B", minutes=10, iocs=["x"]),
        alert("C", minutes=20, iocs=["unrelated"]),
    ]
    groups = cluster_linked(session, iocs_of, ubiquitous=set())
    assert [len(g) for g in groups] == [2, 1]


def test_groups_come_back_in_the_order_their_first_member_appears():
    """A caller that passed events in time order gets cases in time order."""
    session = [
        alert("late-linker", minutes=0, iocs=["a"]),
        alert("other", minutes=5, iocs=["b"]),
        alert("late-linker-2", minutes=90, iocs=["a"]),
    ]
    groups = cluster_linked(session, iocs_of, ubiquitous=set())
    assert groups[0][0].detection_name == "late-linker"
    assert groups[1][0].detection_name == "other"


def test_an_empty_session_is_no_cases():
    assert cluster_linked([], iocs_of, ubiquitous=set()) == []


def test_case_keys_are_unchanged_when_a_session_yields_one_case():
    """Every case already on screen keeps the identity it had."""
    from app.services.alert_session_service import case_key_for

    started = T0
    assert case_key_for("s", "c", "h", started) == case_key_for(
        "s", "c", "h", started, discriminator=""
    )
    assert case_key_for("s", "c", "h", started) != case_key_for(
        "s", "c", "h", started, discriminator="run-2"
    )
