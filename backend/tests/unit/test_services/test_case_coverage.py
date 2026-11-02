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


# --- the Cases page has to be fast enough to use -----------------------------


def test_indicator_values_are_read_from_a_column_not_re_derived():
    """Projecting them with a correlated `jsonb_array_elements` subquery cost
    2,398 ms against 30 ms for the same query without it — two and a half
    seconds of every page load, spent re-deriving a value that never changes
    once the investigation has concluded."""
    import inspect

    from app.services import alert_correlation_service as svc

    source = inspect.getsource(svc)
    assert "_IOCS = AlertBodyInvestigationRun.ioc_values" in source
    # Asserted on the code, not the prose: the comment above the projection
    # names the subquery it replaced, and should keep doing so.
    assert "literal_column(" not in source, (
        "the indicator values come from a column, maintained by a trigger"
    )


def test_a_recompute_that_changes_nothing_writes_nothing():
    """A page load issued 673 UPDATEs against a table nobody had asked to
    change, and made `updated_at` mean "when somebody last looked"."""
    import inspect

    from app.services import alert_case_store as store

    source = inspect.getsource(store.upsert_spine)
    assert "if changed:" in source
    assert source.index("changed = False") < source.index("if changed:")


def test_the_entity_s_cases_are_loaded_once_per_entity():
    """Correlation read a spine row twice per cluster, and a *missing* row
    costs a round trip just the same — 1,403 of them on one page load, almost
    all misses."""
    import inspect

    from app.services import alert_case_store as store
    from app.services import alert_correlation_service as svc

    assert hasattr(store, "spines_for_entity")
    source = inspect.getsource(svc.correlate_alerts)
    assert "spines_for_entity(" in source
    # And the two readers consult it rather than the database.
    assert "known=existing" in source
    assert "existing.get(closed_key)" in source


def test_the_estate_wide_spread_does_not_depend_on_what_a_pass_fetched():
    """Whether an indicator describes the estate or an incident is a property
    of the estate, never of the rows one pass happened to read.

    It was counted from those rows, so narrowing a pass to a single host saw
    every value on exactly one host, nothing was ever ubiquitous, the linking
    changed and the same host came back as 12 cases scoped against 34
    unscoped — with only 2 of them the same case. Opening one case therefore
    could not use a scoped pass at all, and paid for the whole estate."""
    import inspect

    from app.services import alert_case_linkage_service as linkage
    from app.services import alert_correlation_service as svc

    assert hasattr(linkage, "ubiquitous_values_across_estate")
    source = inspect.getsource(svc.correlate_alerts)
    assert "ubiquitous_values_across_estate(db" in source
    assert "ubiquitous_values(rows" not in source, (
        "the spread must not be derived from the rows this pass fetched"
    )


def test_one_case_is_looked_up_without_correlating_the_estate():
    """`case_by_key` ran a 720-hour whole-estate pass and then scanned the
    result for one key — and the case page paid it twice, once for the case
    and once for its observables."""
    import inspect

    from app.services import alert_correlation_service as svc

    source = inspect.getsource(svc.case_by_key)
    assert "only_entity=only_entity" in source
    assert "AlertCaseSpine" in source, "the spine row names the entity to scope by"


def test_the_entity_profile_selects_only_the_sub_document_it_reads():
    """It selected every alert's whole `result_json` for one host — indicator
    reports, previous analyses, the AI report — to read one key out of each.
    3,953 ms, the largest single cost of opening a case."""
    import inspect

    from app.services import alert_entity_profile_service as profile

    source = inspect.getsource(profile.build_entity_profile)
    assert 'result_json["indicator_summary"]' in source
    assert "AlertBodyInvestigationRun.result_json,\n" not in source
