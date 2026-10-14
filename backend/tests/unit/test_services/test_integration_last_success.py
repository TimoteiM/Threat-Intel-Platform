"""`not_configured` and "worked until Monday" must not be the same row.

The defect this closes removed the state that would have been red. SIEM log
enrichment stopped on 2026-10-12 because `OPENSEARCH_TENANT_VALUES` went
empty, which makes the integration read as **not_configured** — and on a page
listing unconfigured tools, that is invisible. `verified_failing` catches
"configured but unusable"; it does not catch "configuration vanished", because
a vanished configuration is indistinguishable from one never made.

The distinguishing fact is already stored: `alert_log_context` rows up to
2026-10-12 and none after. So the status carries `last_succeeded_at`, and a
tool that is not working *and has a last success* is an incident rather than
an absence.

Fourth split of one state into two this week: checked from listed, failed from
not_attempted, verified from consulted, and now never-configured from
configured-and-stopped.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services import absence
from app.services import integration_status_service as st

NOW = datetime(2026, 10, 14, 14, 0, tzinfo=timezone.utc)
MONDAY = datetime(2026, 10, 12, 12, 26, 32, tzinfo=timezone.utc)


# --- the dangerous direction ---------------------------------------------


def test_a_tool_that_stopped_is_not_reported_as_never_configured():
    """The exact shape of the two-day outage."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=MONDAY, now=NOW,
    )
    assert verdict["stopped"] is True, (
        "an integration with a last success is not an absence of "
        "configuration; it is an incident"
    )
    assert verdict["state"] == st.STOPPED
    assert verdict["silent_for_hours"] >= 48


def test_a_tool_that_never_worked_stays_not_configured():
    """The control. Without it, every unconfigured tool reads as an incident."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=None, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.NOT_CONFIGURED


def test_never_worked_is_an_absence_not_a_date():
    """`last_succeeded_at` of None must not render as a zero date or 'never
    observed' masquerading as a measurement."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=None, now=NOW,
    )
    assert absence.is_absent(verdict["last_success"])
    assert verdict["last_success"]["kind"] == absence.NEVER_OBSERVED


def test_a_working_tool_is_not_flagged_even_with_an_old_success():
    verdict = st.continuity(
        state=st.VERIFIED_OK, last_succeeded_at=MONDAY, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.VERIFIED_OK


def test_verified_failing_with_a_last_success_is_still_stopped():
    """Failing-and-previously-working is the same incident, louder."""
    verdict = st.continuity(
        state=st.VERIFIED_FAILING, last_succeeded_at=MONDAY, now=NOW,
    )
    assert verdict["stopped"] is True
    assert verdict["state"] == st.STOPPED


def test_a_tool_no_connector_implements_is_never_an_incident():
    verdict = st.continuity(
        state=st.NOT_IMPLEMENTED, last_succeeded_at=None, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.NOT_IMPLEMENTED


def test_a_future_last_success_does_not_produce_negative_silence():
    """Clock skew must not make a stopped tool look fine."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED,
        last_succeeded_at=NOW + timedelta(hours=3), now=NOW,
    )
    assert verdict["silent_for_hours"] >= 0


def test_stopped_is_the_worst_state_so_it_wins_the_overall_badge():
    """The page takes the worst direction. `stopped` must outrank the rest or
    a stopped tool hides behind a healthy second direction."""
    assert st.STOPPED in st.STATES
    assert st.STATES.index(st.STOPPED) == 0, (
        "STATES is worst-first and the overall badge is min() by this index"
    )


# --- the log store, which was not on the page at all --------------------


def test_the_log_store_is_a_listed_integration():
    """It carries 154M documents and feeds every alert's context, and it was
    absent from the catalogue because it is not a collector. A page that omits
    the integration most likely to break cannot report it breaking."""
    cat = st.catalogue()
    assert "opensearch" in cat, (
        f"the log store is not listed; catalogue has {sorted(cat)}"
    )
    spec = cat["opensearch"]
    assert spec.category == "siem"
    assert "enrichment" in spec.directions


def test_the_non_collector_integrations_are_derived_not_hand_listed():
    """This is a second source for the catalogue, so it is the exact position
    the eighth silent registry occupied. Each entry must declare itself."""
    for name, spec in st.catalogue().items():
        assert spec.label, f"{name} has no label"
        assert spec.directions, f"{name} declares no directions"
        assert spec.category, f"{name} declares no category"
