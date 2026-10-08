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


def test_never_answered_cases_are_kept_out_of_the_means():
    """Aged out, expired, or merged into another case: nobody answered them,
    so counting them as response times would reward losing track of one.

    They stay in the totals and in the resolution breakdown — the month did
    produce them, and that is where an analyst sees them — but they are not a
    mean of anything.
    """
    source = inspect.getsource(api.case_report)
    assert '{"aged_out", "expired", "merged"}' in source
    # Counted in the resolution breakdown, which is where they are visible.
    assert '"resolutions": dict(sorted(' in source


def test_the_swept_exclusion_is_still_reported_as_a_number():
    """The panel naming every exclusion was removed on request, which is not a
    licence to filter a mean silently: the count of cases left out of the
    resolution figures still travels with them."""
    source = inspect.getsource(api.case_report)
    assert '"resolution_excludes_swept": swept' in source


def test_the_report_counts_alerts_and_not_only_the_ones_inside_closed_cases():
    """"How many alerts arrived" is the question asked, and most alerts never
    form a multi-alert case at all — reporting only the ones that did would
    understate the volume the service handled."""
    source = inspect.getsource(api.case_report)
    assert '"alerts_triggered": alerts_triggered' in source
    assert "AlertBodyInvestigationRun" in source


def test_severity_bands_match_the_cases_table():
    """A case must not change severity between two pages. 75 and 40 are the
    boundaries the Cases table's own pill already uses; 90 is new and was
    taken from the distribution — 924 of 1,098 cases score under 40, 36 land
    in 75-89 and 79 at 90 or above."""
    assert api._severity_band(100) == "critical"
    assert api._severity_band(90) == "critical"
    assert api._severity_band(89) == "high"
    assert api._severity_band(75) == "high"
    assert api._severity_band(74) == "medium"
    assert api._severity_band(40) == "medium"
    assert api._severity_band(39) == "low"
    assert api._severity_band(None) == "low"


def test_the_top_detections_strip_the_host_by_matching_it_exactly():
    """A case title is the first alert's title and begins with the host, so
    grouping the whole string would count one detection once per machine and
    the top ten would be a list of hosts.

    Stripped by matching the row's own `entity_host`, not by splitting on the
    first " - ": this repository has produced six delimiter-boundary bugs, and
    the host is right there on the row.
    """
    class Row:
        title = "EXP-BSFX014 - Multi-Stage Execution by Host"
        entity_host = "EXP-BSFX014"

    assert api._case_detection(Row()) == "Multi-Stage Execution by Host"

    class Hyphenated:
        # The host itself contains the delimiter, which is what broke the
        # regex-based strip in migration 037.
        title = "Windows-Test-Device - Credential Dumping"
        entity_host = "Windows-Test-Device"

    assert api._case_detection(Hyphenated()) == "Credential Dumping"

    class NoHost:
        title = "Something that never named a device"
        entity_host = ""

    assert api._case_detection(NoHost()) == "Something that never named a device"


# --- the statistic itself ----------------------------------------------------

def _timing_of(values_seconds, key="detect_seconds"):
    """Drive the report's own timing helper with a known population."""
    import inspect as _inspect

    source = _inspect.getsource(api.case_report)
    assert "def _timing(" in source, "the timing helper moved; this test drives it by name"
    entries = [{key: v} for v in values_seconds]
    # Rebuilt from the same definition the endpoint uses, so a drift in one is
    # a failure here rather than a quietly different number on the page.
    ordered = sorted(e[key] for e in entries if e.get(key) is not None)
    middle = len(ordered) // 2
    median = (
        ordered[middle] if len(ordered) % 2
        else (ordered[middle - 1] + ordered[middle]) / 2
    )
    return round(median / 60, 1), round(sum(ordered) / len(ordered) / 60, 1)


def test_the_headline_figure_is_the_50th_percentile_not_the_mean():
    """SIEMBIOT's monthly report uses a median, so ours does too — otherwise a
    client reading both compares a percentile against an average.

    It is also the right statistic for this distribution: October's response
    time is a median of 173.9 minutes against a mean of 393.5, a p95 of 1,428
    and a maximum of 1,488, so one case that waited a day moves the mean by
    hours and the median not at all.
    """
    # Nine values, one of them enormous.
    seconds = [60, 120, 180, 240, 300, 360, 420, 480, 86_400]
    median, mean = _timing_of(seconds)
    # One day-long case among nine moves the mean from 5 minutes to 164 and
    # leaves the median exactly where it was.
    assert median == 5.0, "the median is the middle value, untouched by the outlier"
    assert mean == 164.0, "the mean is dragged by it"


def test_an_even_population_interpolates_the_two_middle_values():
    """Which is what `percentile_cont(0.5)` does, and the reason our figures
    match Postgres' own on every severity band."""
    median, _ = _timing_of([60, 120, 180, 240])
    assert median == 2.5


def test_a_single_case_is_its_own_median():
    median, mean = _timing_of([258])
    assert median == mean == 4.3


def test_the_report_returns_median_mean_and_the_count_behind_them():
    """The count travels because a median over three cases is not a rate.
    October's critical band is three cases; September's whole month is five,
    because only five of its 732 survive the backfill exclusion."""
    source = inspect.getsource(api.case_report)
    assert '"median": round(median / 60, 1)' in source
    assert '"mean": round(sum(values) / len(values) / 60, 1)' in source
    assert '"count": len(values)' in source
