"""
A large alert is still an alert.

Ingest used to answer 413 above 200,000 characters. A sender that gets 413 is
left holding an event nothing will ever look at: no run, no record, and no way
to say what it contained. Size is now handled where it actually costs
something — the analysis window, and the list query.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api import alert_investigations as api


def test_no_size_rejection():
    """Any length is accepted; only an empty body is refused."""
    body = "x" * (api.MAX_ANALYSED_ALERT_BODY_CHARS + 5_000)
    assert api._validated_alert_body(body) == body


def test_empty_body_is_still_refused():
    for empty in ("", "   ", None):
        with pytest.raises(HTTPException) as exc:
            api._validated_alert_body(empty)
        assert exc.value.status_code == 400


def test_the_analysis_window_is_generous_but_bounded():
    """
    Extraction runs at roughly six seconds per megabyte, so the cap exists to
    stop one pathological paste holding a worker thread, not to refuse work.
    """
    assert api.MAX_ANALYSED_ALERT_BODY_CHARS >= 10_000_000


def test_the_old_rejection_is_gone_from_the_source():
    """
    Asserted against the source: the raise lived inside a request handler, and
    reinstating it would silently start refusing large senders again with
    nothing else failing.
    """
    from pathlib import Path

    text = (Path(__file__).resolve().parents[3] / "app" / "api" / "alert_investigations.py").read_text(
        encoding="utf-8"
    )
    assert "status_code=413" not in text
    assert "Alert body is too large" not in text


def test_list_query_does_not_load_the_body():
    """
    _list_item never reads alert_body. Selecting it anyway meant a page of 25
    rows detoasted 25 bodies to render a list that shows none of them — which
    only became dangerous once any size was accepted.
    """
    from pathlib import Path

    text = (Path(__file__).resolve().parents[3] / "app" / "api" / "alert_investigations.py").read_text(
        encoding="utf-8"
    )
    assert "defer(AlertBodyInvestigationRun.alert_body)" in text
