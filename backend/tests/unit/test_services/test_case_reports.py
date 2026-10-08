"""The Reports page: one client, one month, and what the figures leave out.

Three things are pinned here, each of which was wrong or absent before.

A service report is the place where a metric most easily comes to flatter, so
the tests are mostly about what is *excluded* and whether the exclusion is
stated.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import app.api.detections as api
from app.services import alert_case_closure_service as closure

T0 = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


# --- the month filter --------------------------------------------------------

def test_a_month_is_a_half_open_range():
    """Half-open, so a case opened in the last microsecond of the month lands
    in that month and not in both."""
    start, end = api._month_bounds("2026-10")
    assert start == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 11, 1, tzinfo=timezone.utc)


def test_december_rolls_into_the_next_year():
    start, end = api._month_bounds("2026-12")
    assert start == datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert end == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_an_unusable_month_means_the_whole_history_not_an_error():
    """The page offers only months that exist, so a bad value is a stale
    bookmark. Showing everything is the harmless answer; a 500 is not."""
    for value in (None, "", "all", "bogus", "2026-13", "2026", "not-a-month"):
        assert api._month_bounds(value) == (None, None), value


# --- the client filter -------------------------------------------------------

def test_the_client_filter_restricts_the_query_and_not_only_the_label():
    """`/detections/sla` computed the scope and then used it *only* to stamp
    the response "scoped", while the query selected every tenant's cases — so
    a client-restricted account was shown the whole estate's MTTR under a word
    asserting it was theirs. That is worse than saying nothing."""
    class Scope:
        all_tenants = False
        tenant_ids = ["c00"]
        include_unassigned = False

    clause = api._case_tenant_clause(Scope())
    assert clause, "a restricted caller must produce a WHERE clause"
    assert "tenant_id" in str(clause[0]).lower()


def test_an_all_tenants_caller_is_not_filtered():
    class Scope:
        all_tenants = True
        tenant_ids: list[str] = []
        include_unassigned = True

    assert api._case_tenant_clause(Scope()) == ()


def test_a_restricted_caller_with_no_tenants_matches_nothing():
    """Never "everything" by default. An account granted no client sees no
    client, which is the direction a mistake has to fail in."""
    class Scope:
        all_tenants = False
        tenant_ids: list[str] = []
        include_unassigned = False

    clause = api._case_tenant_clause(Scope())
    assert clause and "false" in str(clause[0]).lower()


def test_the_report_filters_on_the_tenant_not_the_senders_label():
    """`alert_client` is the sender's own label and reads "unknown" for 1,079
    of 1,098 cases — a filter built on it offers one option for almost the
    whole estate. The tenant comes from the alerts."""
    source = inspect.getsource(api.case_report)
    # The body, not the docstring — which names `alert_client` precisely to
    # record why it is not the thing being filtered on.
    body = source.split('"""', 2)[-1]
    assert "AlertCaseSpine.tenant_id" in body
    assert "alert_client" not in body


# --- what MTTR is allowed to count ------------------------------------------

def test_a_case_closed_long_after_its_last_alert_is_not_in_mttr():
    """The exclusion that was missing, and its measured consequence.

    Only the detection side had one. A case whose alerts stopped in September
    and which a catch-up pass closed in October contributed three weeks to
    MTTR — one month reported a mean resolution of 21.8 days and 620 of 620
    cases breached, which describes when the backlog was drained rather than
    how the service responded.
    """
    out = closure.metrics(
        opened_at=T0,
        created_at=T0 + timedelta(minutes=1),
        closed_at=T0 + timedelta(days=21),
        last_activity_at=T0 + timedelta(minutes=5),
    )
    assert out["resolve_seconds"] is None
    assert out["resolve_excluded"]
    # Counted, not silently dropped: three weeks unanswered is a real failure
    # of a different kind, and hiding it inside an average is how a metric
    # comes to flatter.
    assert out["resolve_lag_seconds"] > 0


def test_a_case_answered_within_the_window_is_counted():
    out = closure.metrics(
        opened_at=T0,
        created_at=T0 + timedelta(minutes=1),
        closed_at=T0 + timedelta(minutes=25),
        last_activity_at=T0 + timedelta(minutes=12),
    )
    assert out["resolve_seconds"] == 1500.0
    assert "resolve_excluded" not in out


def test_without_a_last_activity_the_old_behaviour_is_unchanged():
    """`last_activity_at` is optional, so every existing caller — including
    `/detections/sla` — keeps the figures it had."""
    out = closure.metrics(
        opened_at=T0, created_at=T0 + timedelta(minutes=1),
        closed_at=T0 + timedelta(days=21),
    )
    assert out["resolve_seconds"] == 21 * 24 * 3600.0
    assert "resolve_excluded" not in out


def test_a_population_with_nothing_measurable_reports_no_mean():
    """Rather than a zero or a dash, both of which read as a measurement.

    A month whose cases were every one of them swept up has no response time,
    and the page says "not measurable" because that is the honest answer.
    """
    swept = [
        {"alert_count": 1, "detect_seconds": 30.0, "resolve_seconds": None},
        {"alert_count": 3, "detect_seconds": 45.0, "resolve_seconds": None},
    ]
    summary = closure.summarise(swept, target_seconds=3600)
    assert summary["all"]["mttr_seconds"] is None
    assert summary["all"]["closed"] == 0
    assert summary["all"]["sla_met"] == 0
    assert summary["all"]["sla_breached"] == 0, "nothing measured is not a breach"


def test_never_answered_cases_are_excluded_from_the_response_figures():
    """Aged out, expired, or merged into another case: nobody answered them,
    so counting them as resolutions would reward losing track of one."""
    source = inspect.getsource(api.case_report)
    assert '{"aged_out", "expired", "merged"}' in source
    assert "never_answered" in source
    # And the response says so rather than applying it quietly.
    assert '"note"' in source
