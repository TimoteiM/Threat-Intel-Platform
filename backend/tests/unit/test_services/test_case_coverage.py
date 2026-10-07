"""Every ingested alert has to end up in a case somebody can see.

Cases replaced the manual job, so they are the unit of coverage: an alert in
no case is invisible to the analyst and outside the SLA measurement. Two
things were quietly preventing that, both found by an analyst asking why a
morning of alerts had produced no cases.

**A cluster needed two different detections to become a case.** Sound when the
page meant "cases worth attention", wrong when it has to account for
everything: measured over the estate, 863 of 890 linked clusters (97%) were
dropped before a spine row was written, and 6,249 of 11,376 alerts (55%) were
in no case at all.

**A forwarded log had no host.** Wazuh attributes a relayed firewall log to
agent 000 — the manager — and the extractor rightly refuses to correlate on
that, because it would group every forwarded log in the estate under one
machine that saw none of them. But refusing and stopping there left the alert
hostless, and a hostless alert reaches no case: 3,195 rows, of which 2,471 are
one FortiGate detection whose body carries `devname=` in plain sight.
"""

from __future__ import annotations

from app.services.alert_correlation_service import MIN_DISTINCT_RULES
from app.services.alert_field_service import extract_alert_fields


# --- a case is the unit of coverage, not a notability threshold -------------

def test_one_detection_is_enough_to_make_a_case():
    """At 2, this endpoint hid 97% of the clusters it had already computed."""
    assert MIN_DISTINCT_RULES == 1


def test_the_api_default_matches_it():
    """The threshold lived in two places and only one of them was the one the
    Cases page used."""
    import inspect

    from app.api import detections

    source = inspect.getsource(detections.get_correlated_cases)
    assert "min_rules: int = Query(default=1" in source


def test_notability_is_still_a_threshold_somewhere_else():
    """Lowering the bar for *existing* must not lower it for *escalating* —
    otherwise every single-alert case pages someone."""
    from app.config import get_settings

    settings = get_settings()
    assert int(getattr(settings, "correlation_escalation_min_score", 0) or 0) > 0


# --- a forwarded log names its own device ------------------------------------

FORWARDED = """Alert: Siembiot - Shell Execution Of Process Located In Tmp Directory
Rule: 81640
Agent: Siembiot | 000
Manager: Siembiot

date=2026-08-16 time=01:53:49 devname="FortiGate-200F-FW01" devid="FG200FT923915464" srcip=172.20.20.5
"""

OBSERVED = """Alert: EXP-4LWK334 - Repeated injection-capable access by process
Agent: EXP-4LWK334 | 1634
Manager: Siembiot
devname="a-firewall-this-host-was-talking-to"
"""


def test_a_forwarded_alert_takes_the_device_from_its_payload():
    fields = extract_alert_fields(FORWARDED)

    assert fields["agent"] == "FortiGate-200F-FW01"
    assert fields["agent_id"] == "000"
    assert fields["forwarded_device"] == "FortiGate-200F-FW01"


def test_the_manager_is_still_never_the_host():
    """The original reason for refusing agent 000 stands: correlating on it
    would group every forwarded log in the estate under one machine."""
    fields = extract_alert_fields(FORWARDED)
    assert fields["agent"] != "Siembiot"
    assert fields["manager"] == "Siembiot"


def test_an_alert_a_real_agent_observed_is_untouched():
    """On an observed log the agent *is* the device, and a `devname` in the
    payload names something it was talking to — not itself."""
    fields = extract_alert_fields(OBSERVED)

    assert fields["agent"] == "EXP-4LWK334"
    # Dropped rather than null: the extractor omits empty fields.
    assert not fields.get("forwarded_device")


def test_a_forwarded_alert_with_no_device_in_it_stays_hostless():
    """Honest rather than invented: without a device name there is nothing to
    correlate on, and guessing would rebuild the grouping this avoids."""
    fields = extract_alert_fields(
        "Alert: Siembiot - Something\nAgent: Siembiot | 000\nManager: Siembiot\n"
    )
    assert not fields.get("forwarded_device")
    assert fields["agent"] == "Siembiot"


# --- the two holes an adversarial audit found -------------------------------
#
# Found by five independent hunters and upheld by three refuters each, after
# the two the analyst reported had been fixed.


def test_an_alert_with_no_detection_identity_still_gets_a_case():
    """`rules.discard("")` leaves an empty set for a cluster whose alerts
    carry no detection_name, rule id or rule name — and `0 < min_rules` is
    true for every allowed threshold, so the cluster was dropped before a
    spine row existed. 805 rows estate-wide are like this and 151 of them
    concluded *malicious*: every one invisible and outside MTTD/MTTR.

    "No detection identity" is a different thing from "too few detections",
    and the threshold only answers the second."""
    import inspect

    from app.services import alert_correlation_service as svc

    source = inspect.getsource(svc.correlate_alerts)
    assert "if rules and len(rules) < min_rules:" in source, (
        "the threshold must not fire on a cluster that has no rules at all"
    )


def test_an_incident_gets_a_case_of_its_own():
    """The skip said an incident 'is a case, not a member of one' — and then
    nothing created that case. 18 rows on 8 hosts produced zero cases."""
    import inspect

    from app.services import alert_correlation_service as svc

    source = inspect.getsource(svc.correlate_alerts)
    assert "incidents.append(row)" in source
    assert "incident:" in source, "keyed on the row so it is never pooled"


def test_nothing_is_closed_merely_for_being_absent_from_the_listing():
    """The listing filters on wall-clock time, on score and on a row limit;
    membership is relative to each entity's own newest event. A case created
    seconds ago can be missing from the listing while its membership was read
    in that very call. Closing on that absence destroyed 575 cases, 504 of
    them within two minutes of creation, every one with zero alerts."""
    import inspect

    from app.tasks import case_closure_task

    source = inspect.getsource(case_closure_task.close_quiet_cases)
    assert "unreadable += 1" in source
    assert 'resolution="aged_out"' not in source, (
        "absence from a filtered listing is not a resolution"
    )
