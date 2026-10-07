"""The time window on the alert list.

Two things are pinned here because both have already cost working code.

The first is the parse. The browser's `datetime-local` input hands back
wall-clock text with no zone, and `toISOString` on the client turns it into an
instant with a `Z` — so this endpoint receives at least three spellings of the
same moment and has to agree with all of them.

The second is the shape of the defaults. `Query(default=None)` makes FastAPI
infer a query parameter either way, but the `Query` object *is* the default
for anything that calls the function directly, and it is truthy. "No window"
then becomes "a window built from a Query object". That exact mistake cost six
passing tests on the log-context endpoint, and was made a second time on this
endpoint before it was caught, so it is pinned rather than remembered.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

import app.api.alert_investigations as api


def test_every_spelling_the_browser_sends_parses_to_the_same_instant():
    expected = datetime(2026, 10, 7, 7, 0, tzinfo=timezone.utc)
    for spelling in (
        "2026-10-07T07:00:00.000Z",   # toISOString, which is what the UI sends
        "2026-10-07T07:00:00Z",
        "2026-10-07T07:00:00+00:00",
        "2026-10-07T07:00:00",        # zoneless, read as UTC
        "  2026-10-07T07:00:00Z  ",
    ):
        assert api._parse_moment(spelling) == expected, spelling


def test_an_offset_is_honoured_rather_than_reinterpreted():
    """The analyst's own zone, carried on the stamp.

    A naive stamp is read as UTC, so a client that sends local wall-clock text
    is silently served another hour's alerts. The conversion belongs on the
    client, and this is the half of the contract the server keeps: an explicit
    offset means what it says.
    """
    assert api._parse_moment("2026-10-07T10:00:00+03:00") == datetime(
        2026, 10, 7, 7, 0, tzinfo=timezone.utc
    )


def test_nothing_and_nonsense_are_both_no_window():
    """Never a 500, and never a silently wrong window either: unparseable
    input means the filter is not applied, which is visibly "everything"
    rather than invisibly "some arbitrary range"."""
    for value in (None, "", "   ", "rubbish", "2026-13-45", "yesterday"):
        assert api._parse_moment(value) is None, value


def test_the_window_parameters_default_to_plain_values():
    """The `Query`-object trap, pinned so the third occurrence fails here.

    A direct caller — every service test, and the closure and correlation
    jobs — gets the declared default. If that default is a `Query` instance it
    is truthy, `hours` is not an `int`, and the guards downstream read a
    window that nobody asked for.
    """
    defaults = inspect.signature(api.list_alert_investigations).parameters
    for name in ("since", "until", "hours"):
        assert defaults[name].default is None, (
            f"{name} must default to a plain None, not a Query object"
        )


def test_an_explicit_range_wins_over_the_preset():
    """`hours` is a convenience, not a second filter.

    Intersecting the two answers a question nobody asked: an analyst who typed
    "between 10:00 and 11:00" has already said what they want, and quietly
    also clipping it to the last 48 hours makes the range they typed a lie.
    """
    source = inspect.getsource(api.list_alert_investigations)
    assert "if start is None and end is None and isinstance(hours, int) and hours > 0:" in source


def test_the_window_is_bounded_in_the_handler_not_only_by_query():
    """So the bound holds for a direct caller too, exactly as above."""
    source = inspect.getsource(api.list_alert_investigations)
    assert "min(int(hours), 17_520)" in source


def test_the_window_filters_the_count_as_well_as_the_page():
    """A page of 11 rows under a total of 14,810 reads as a broken filter, and
    an analyst cannot tell it from a broken window."""
    source = inspect.getsource(api.list_alert_investigations)
    body = source.split("# The window.", 1)[1]
    clause_block = body.split("rows = (", 1)[0]
    assert "query = query.where(clause)" in clause_block
    assert "count_query = count_query.where(clause)" in clause_block


def test_the_window_runs_on_when_the_alert_happened():
    """Not when we were told. An alert replayed out of a backlog belongs in
    the window it occurred in — which is the window the analyst means — and
    `created_at` is only the fallback for an alert that carried no time."""
    source = inspect.getsource(api.list_alert_investigations)
    assert "func.coalesce(" in source
    assert "AlertBodyInvestigationRun.event_time, AlertBodyInvestigationRun.created_at" in source
