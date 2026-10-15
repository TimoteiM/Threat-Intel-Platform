"""Sections A and B of the Falcon host panel.

The product judgment under test: 1,432 raw alert rows on EXP-22MY264 is 12
distinct detections, 936 rows of which are one developer's `wsl.exe`, and 996
of 1,000 already closed. A panel that shows 1,432 shows a compromised machine
that does not exist.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services import absence
from app.services import falcon_host_panel_service as fp

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
PASSED = {"passed": True, "field": "device.hostname",
          "checked_at": NOW.isoformat(), "reason": "a value read back filtered."}
FAILED = {"passed": False, "field": "device.hostname",
          "checked_at": NOW.isoformat(),
          "reason": "the API is ignoring this field name."}

DEVICE = {
    "hostname": "EXP-22MY264", "platform_name": "Windows",
    "os_version": "Windows 11", "os_build": "26200",
    "agent_version": "7.40.21309.0", "status": "normal",
    "reduced_functionality_mode": "no",
    "first_seen": "2025-08-20T08:13:22Z", "last_seen": "2026-10-15T09:42:59Z",
    "product_type_desc": "Workstation", "site_name": "EXPERTWARE",
    "machine_domain": "int.expertware.net",
    "device_policies": {"prevention": {"applied": True}},
    # Fields the panel must NOT pass through.
    "serial_number": "SN-12345", "mac_address": "00:11:22:33:44:55",
    "external_ip": "203.0.113.9", "last_login_user": "aparaschivoiu",
}


def _rows(n, *, name, filename, status="closed", disposition=None, user=None,
          agg=None, start=NOW):
    return [{
        "name": name, "filename": filename, "status": status,
        "pattern_disposition_description": disposition, "user_name": user,
        "aggregate_id": agg or f"{name}-{i // 10}",
        "created_timestamp": (start - timedelta(minutes=i)).isoformat(),
        "tactic": "Defense Evasion", "technique": "Masquerading",
    } for i in range(n)]


# --- section B: the headline ----------------------------------------------


def test_the_measured_host_reports_distinct_detections_not_raw_rows():
    """The real shape from 2026-10-15, scaled down.

    If the headline were the row count this panel would say a workstation had
    936 detections of one kind. It has one, repeated.
    """
    records = (
        _rows(936, name="TestingActivity", filename="wsl.exe",
              disposition="Detection, standard detection.", user="dev")
        + _rows(6, name="CredDumpTool", filename="git.exe", status="closed",
                disposition="Prevention, process was blocked from execution.",
                user="aparaschivoiu")
        + _rows(4, name="PShellExploitKit2", filename="powershell.exe",
                status="new", disposition="Detection, standard detection.")
    )
    out = fp.group_detections(records)

    assert out["distinct_detection_count"] == 3
    assert out["open_detection_count"] == 1, (
        "closed detections are counted in the headline"
    )
    assert out["raw"]["rows"] == 946
    # The raw count exists, but only inside `raw`, labelled.
    assert "repetition, not severity" in out["raw"]["note"]


def test_the_open_group_sorts_first():
    """An analyst reads the top of this list and nothing else."""
    records = (
        _rows(50, name="Noisy", filename="wsl.exe", status="closed")
        + _rows(1, name="Real", filename="mimikatz.exe", status="new")
    )
    out = fp.group_detections(records)
    assert out["groups"][0]["name"] == "Real"
    assert out["groups"][0]["rows"] == 1
    assert out["groups"][1]["rows"] == 50


def test_prevention_is_surfaced_because_it_matters_more_than_count():
    records = _rows(3, name="CredDumpTool", filename="git.exe", status="new",
                    disposition="Prevention, process was blocked from execution.")
    group = fp.group_detections(records)["groups"][0]
    assert group["prevented"] is True
    assert any("Prevention" in d for d in group["dispositions"])


def test_falcons_own_aggregate_count_sits_beside_the_group_count():
    """Neither is wrong and the gap between them is informative: 1,432 rows,
    546 aggregates, 12 groups on the measured host."""
    records = _rows(20, name="X", filename="y.exe", agg=None)
    out = fp.group_detections(records)
    assert out["raw"]["aggregate_ids"] == 2        # i//10 over 20 rows
    assert out["distinct_detection_count"] == 1


def test_no_detections_with_a_passing_control_is_a_real_negative():
    out = fp.panel(hostname="EXP-1", device=DEVICE, detections=[],
                   control=PASSED, now=NOW)
    assert not absence.is_absent(out["detections"])
    assert out["detections"]["open_detection_count"] == 0
    # The "real negative" reasoning lives in the footer's field_control, once.
    # Saying it again here made the panel read as though it were apologising.
    assert out["field_control"]["passed"] is True
    assert "zero results" in out["field_control"]["why_it_matters"]


def test_no_detections_with_a_FAILED_control_is_withheld():
    """The whole reason the control exists.

    The Alerts API answers an unknown field with 200 and zero rows, so an
    empty result from an unconfirmed field is not evidence of anything.
    """
    out = fp.panel(hostname="EXP-1", device=DEVICE, detections=[],
                   control=FAILED, now=NOW)
    assert absence.is_absent(out["detections"])
    assert out["detections"]["kind"] == absence.CHECK_FAILED
    assert "ignoring this field name" in out["detections"]["reason"]
    assert out["field_control"]["passed"] is False


def test_detections_are_withheld_even_when_rows_were_somehow_returned():
    """A failed control is not overridden by data.

    If the control failed, the field is not trustworthy, and rows that came
    back under it describe something we cannot name.
    """
    out = fp.panel(hostname="EXP-1", device=DEVICE,
                   detections=_rows(5, name="X", filename="y.exe"),
                   control=FAILED, now=NOW)
    assert absence.is_absent(out["detections"])


def test_the_control_state_is_shown_rather_than_hidden():
    out = fp.panel(hostname="EXP-1", device=DEVICE, detections=[],
                   control=PASSED, now=NOW)
    fc = out["field_control"]
    assert fc["passed"] is True and fc["field"] == "device.hostname"
    assert "zero results" in fc["why_it_matters"]


# --- section A: coverage ---------------------------------------------------


def test_an_unmanaged_host_is_a_finding_not_an_empty_panel():
    out = fp.coverage(None, hostname="DC", now=NOW)
    assert out["managed"] is False
    assert "No CrowdStrike sensor" in out["finding"]
    # And it may be stated as a real negative, unlike section B.
    assert "HTTP 400" in out["basis"]


def test_a_managed_host_reports_the_operational_facts():
    out = fp.coverage(DEVICE, hostname="EXP-22MY264", now=NOW)
    assert out["managed"] is True
    assert out["agent_version"] == "7.40.21309.0"
    assert out["prevention_applied"] is True
    assert out["degraded"] is False
    assert out["sensor_stale"] is False


def test_the_panel_does_not_pass_through_fields_it_does_not_need():
    """A device record carries 62 fields including serial number, MAC,
    external IP and the last login user. None of them belong in an API
    response for a coverage panel."""
    out = fp.coverage(DEVICE, hostname="EXP-22MY264", now=NOW)
    for leaked in ("serial_number", "mac_address", "external_ip",
                   "last_login_user", "device_policies"):
        assert leaked not in out, f"{leaked} reached the panel payload"


def test_a_stale_sensor_says_the_detections_may_be_incomplete():
    """A sensor that has not reported is not a sensor that saw nothing.

    Measured: 9 of 182 devices last reported beyond 31 days ago.
    """
    stale = dict(DEVICE, last_seen="2026-09-02T08:20:20Z")
    out = fp.coverage(stale, hostname="DESKTOP-AIIJNU8", now=NOW)
    assert out["sensor_stale"] is True
    assert "may be incomplete" in out["reporting"]


def test_reduced_functionality_mode_is_its_own_flag():
    """A sensor installed and not fully protecting. `managed: true` hides it."""
    degraded = dict(DEVICE, reduced_functionality_mode="yes")
    assert fp.coverage(degraded, hostname="X", now=NOW)["degraded"] is True


def test_a_device_with_no_last_seen_is_unknown_not_fresh():
    out = fp.coverage(dict(DEVICE, last_seen=None), hostname="X", now=NOW)
    assert absence.is_absent(out["reporting"])
    assert out["reporting"]["kind"] == absence.CHECK_FAILED


# --- the join key ----------------------------------------------------------


def test_a_missing_join_key_is_cannot_join_and_never_unmanaged():
    """7 of 182 Falcon device records carry no hostname.

    Rendering those as "unmanaged" reports an absent join key as absent
    coverage. They are opposite findings: one is a missing sensor, the other
    is a sensor we cannot match to anything.
    """
    out = fp.unjoinable("the Falcon device record carries no hostname.",
                        hostname=None)
    assert absence.is_absent(out)
    assert out["cannot_join"] is True
    assert "NOT a report that Falcon has no sensor" in out["reason"]


def test_an_alert_naming_no_host_cannot_be_asked_at_all():
    out = fp.panel(hostname=None, device=None, detections=[],
                   control=PASSED, now=NOW)
    assert out["coverage"]["cannot_join"] is True
    assert out["detections"]["cannot_join"] is True
    assert out["coverage"]["kind"] == absence.CHECK_FAILED


def test_an_alert_naming_no_host_does_not_render_as_unmanaged():
    """The dangerous collapse: `hostname=None` must not reach `coverage()` and
    come back as `managed: False`, which would invent a coverage gap for every
    alert that happens not to name a host."""
    out = fp.panel(hostname="  ", device=None, detections=[],
                   control=PASSED, now=NOW)
    assert out["coverage"].get("managed") is None
    assert out["coverage"]["cannot_join"] is True


def test_a_truncated_row_fetch_says_so():
    out = fp.group_detections(_rows(5, name="X", filename="y.exe"),
                              truncated_at=fp.DETECTION_ROW_CAP)
    assert out["raw"]["truncated_at"] == fp.DETECTION_ROW_CAP


# --- truncation: a count from a capped fetch is a floor --------------------


def test_counts_from_a_truncated_fetch_are_marked_as_lower_bounds():
    """Caught live on 2026-10-15, in my own panel.

    EXP-22MY264 hit the 500-row cap and the response said "9 distinct" as a
    fact. Grouping makes this easy to miss: the collapse from 500 rows to 9
    groups looks like the whole picture *because* the number got small. A
    detection kind that only occurs further back in the window is simply not
    counted.
    """
    out = fp.group_detections(
        _rows(500, name="Noisy", filename="wsl.exe", status="closed"),
        truncated_at=500)
    assert out["counts_are_lower_bounds"] is True
    assert out["counts_basis"].startswith("At least")
    assert "older rows in the window were not read" in out["counts_basis"]


def test_an_untruncated_fetch_states_its_counts_as_exact():
    """The control on the test above: the flag distinguishes two states rather
    than always hedging."""
    out = fp.group_detections(_rows(3, name="X", filename="y.exe"))
    assert out["counts_are_lower_bounds"] is False
    assert out["counts_basis"].startswith("Exact")


def test_the_panel_carries_the_bound_through_to_the_response():
    out = fp.panel(hostname="EXP-22MY264", device=DEVICE,
                   detections=_rows(500, name="N", filename="wsl.exe"),
                   control=PASSED, now=NOW, truncated_at=500)
    assert out["detections"]["counts_are_lower_bounds"] is True


# --- re-enrolled sensors: two records for one hostname --------------------

RETIRED = [{"first_seen": "2025-01-17T00:00:00Z",
            "last_seen": "2026-09-29T00:00:00Z",
            "agent_version": "7.40.21309.0"}]


def test_a_re_enrolled_host_says_so_rather_than_looking_brand_new():
    """5 of 175 hostnames carry 2-3 Falcon device records.

    A sensor re-install mints a new device id, so each old record's last_seen
    hands straight off to the next one's first_seen. Without this, a
    two-year-old machine re-imaged last month reads as a brand-new asset.
    """
    out = fp.coverage(dict(DEVICE, first_seen="2026-09-29T00:00:00Z"),
                      hostname="EXP-3LJ1P54", now=NOW, superseded=RETIRED)
    assert out["re_enrolled"] is True
    assert out["superseded_enrolments"] == RETIRED
    assert "dates the current enrolment and not the asset" in out["re_enrolled_note"]


def test_a_single_enrolment_carries_no_re_enrolment_claim():
    out = fp.coverage(DEVICE, hostname="EXP-22MY264", now=NOW, superseded=[])
    assert "re_enrolled" not in out
    assert "superseded_enrolments" not in out


def test_the_live_record_is_the_one_shown_not_an_arbitrary_match():
    """The defect this closed.

    `ids[0]` from the devices query is an arbitrary choice between two
    enrolments. Picking the retired one reports a host that checked in this
    morning as a stale sensor — and the stale warning then discredits a
    detection list that was complete.
    """
    live = dict(DEVICE, last_seen="2026-10-15T09:42:59Z")
    out = fp.panel(hostname="EXP-3LJ1P54", device=live, detections=[],
                   control=PASSED, now=NOW, superseded=RETIRED)
    assert out["coverage"]["sensor_stale"] is False
    assert out["coverage"]["re_enrolled"] is True


# --- the window: what was asked vs what was covered -----------------------
#
# The gap the DNS lookup's observation floor closed this morning, in a
# different integration. "No alerts in 30 days" against an unmeasured
# retention is a bounded window reported as complete, and
# absence-because-not-retained then renders as
# absence-because-it-never-happened.

RETENTION_90 = {"floor": "2026-07-17T06:49:10+00:00",
                "reason": "The oldest alert this subscription returns is 2026-07-17, 90 days ago.",
                "days": 90.0}
RETENTION_UNKNOWN = {"floor": None,
                     "reason": "the floor probe returned HTTP 503."}


def test_a_30_day_window_inside_90_day_retention_is_complete():
    """Measured on this tenant: retention reaches 2026-07-17, 90 days back.
    So the 30-day claim is sound — but only because it was measured."""
    w = fp.effective_window(requested_days=30, retention=RETENTION_90,
                            enrolment_floor="2024-01-01T00:00:00Z", now=NOW)
    assert w["complete"] is True
    assert w["bound_by"] == "requested"
    assert w["covered_days"] == 30.0


def test_retention_shorter_than_the_request_shortens_the_claim():
    """A tier change, or a tenant whose history is young."""
    w = fp.effective_window(
        requested_days=30,
        retention={"floor": (NOW - timedelta(days=11)).isoformat(),
                   "reason": "oldest alert 11 days ago"},
        enrolment_floor="2024-01-01T00:00:00Z", now=NOW)
    assert w["complete"] is False
    assert w["bound_by"] == fp.AT_RETENTION_FLOOR
    assert w["covered_days"] == 11.0
    assert "not 30" in w["statement"]
    assert "not the same as not having" in w["statement"]


def test_a_sensor_enrolled_inside_the_window_binds_instead():
    """18 of 182 devices were enrolled less than 30 days ago.

    Falcon could not have generated a detection on a host before its sensor
    existed, so for those hosts the window is the enrolment, not retention.
    """
    w = fp.effective_window(
        requested_days=30, retention=RETENTION_90,
        enrolment_floor=(NOW - timedelta(days=4)).isoformat(), now=NOW)
    assert w["bound_by"] == fp.AT_ENROLMENT_FLOOR
    assert w["covered_days"] == 4.0
    assert "sensor was enrolled" in w["statement"]


def test_the_latest_of_the_three_bounds_wins():
    """Same rule as the estate lookup's floor: the latest start binds, because
    each is a hard limit on what could be found."""
    w = fp.effective_window(
        requested_days=30,
        retention={"floor": (NOW - timedelta(days=20)).isoformat(), "reason": "x"},
        enrolment_floor=(NOW - timedelta(days=9)).isoformat(), now=NOW)
    assert w["bound_by"] == fp.AT_ENROLMENT_FLOOR
    assert w["covered_days"] == 9.0


def test_an_unmeasured_retention_withholds_the_window_claim():
    """Not a default back to what was asked for.

    An assumed floor is how a 30-day claim outlives the 30 days — the exact
    defect, one integration over.
    """
    w = fp.effective_window(requested_days=30, retention=RETENTION_UNKNOWN,
                            enrolment_floor=None, now=NOW)
    assert w["covered_days"] is None
    assert w["complete"] is None
    assert "not established" in w["statement"]
    assert "lower bound" in w["statement"]


def test_a_tenant_with_no_alerts_does_not_get_a_window_claim():
    w = fp.effective_window(
        requested_days=30,
        retention={"floor": None, "absence": "too_little_history",
                   "reason": "this tenant has no Falcon alerts at all."},
        enrolment_floor=None, now=NOW)
    assert w["complete"] is None


def test_the_panel_carries_the_window_beside_the_detections():
    out = fp.panel(hostname="EXP-1", device=DEVICE, detections=[],
                   control=PASSED, now=NOW, retention=RETENTION_90,
                   enrolment_floor="2024-01-01T00:00:00Z", requested_days=30)
    assert out["window"]["complete"] is True
    assert out["detections"]["window"]["complete"] is True
    assert out["window_days"] == 30


def test_the_panel_does_not_claim_30_days_when_the_floor_is_unknown():
    out = fp.panel(hostname="EXP-1", device=DEVICE, detections=[],
                   control=PASSED, now=NOW, retention=RETENTION_UNKNOWN,
                   enrolment_floor=None, requested_days=30)
    assert out["window"]["covered_days"] is None
    assert out["detections"]["window"]["complete"] is None
