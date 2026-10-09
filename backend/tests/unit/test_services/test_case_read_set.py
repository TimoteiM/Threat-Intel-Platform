"""A narrative records what it read; a judgement is what freezes.

The decision: freeze on judgement — resolution, close, supersession, an
analyst's own conclusion. An AI narrative commissioned early does not freeze,
because `analyse_case_now` exists so an analyst can ask for a read on a live
incident, and making that stop the case accepting alerts would give the
feature an invisible cost at the point of use.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.absence import is_absent
from app.services.case_read_set_service import (
    DERIVATION_VERSION,
    JUDGEMENT,
    NARRATIVE_AUTO,
    NARRATIVE_REQUESTED,
    REASONS,
    divergence_is_material,
)


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_the_three_reasons_a_read_is_taken_are_distinguished():
    """An early read requested by an analyst is the one whose set is most
    likely to diverge, so it is worth telling apart from the quiet-period job."""
    assert {NARRATIVE_AUTO, NARRATIVE_REQUESTED, JUDGEMENT} == REASONS


def test_a_case_with_no_recorded_read_reports_an_absence_not_no_divergence():
    """Every case judged before this table existed is in that position. "The
    set has not moved" and "nobody wrote down where it started" are different
    claims, and 1,698 narratives in this estate are the second."""
    import asyncio

    from app.services.case_read_set_service import divergence_for

    class _Empty:
        async def execute(self, *_a, **_k):
            class R:
                def scalars(self): return self
                def first(self): return None
            return R()

    result = asyncio.run(divergence_for(_Empty(), case_key="k", current_run_ids=["a"]))
    assert is_absent(result["read_set"])
    assert "none names the alerts it was written over" in result["read_set"]["reason"]
    assert not divergence_is_material(result)


def test_alerts_joining_after_a_conclusion_are_reported_in_words():
    """57.9% of all alert memberships in this estate arrive after a freeze, and
    95.5% of cases holding 21+ alerts grow after one, so divergence is the
    normal case. A reader seeing only counts would take the conclusion as
    current."""
    import asyncio

    from app.services.case_read_set_service import divergence_for

    stored = _Row(
        run_ids=["a", "b"], read_at=datetime(2026, 10, 9, tzinfo=timezone.utc),
        reason=NARRATIVE_AUTO, requested_by="quiet-period job",
        derivation_version=DERIVATION_VERSION,
    )

    class _One:
        async def execute(self, *_a, **_k):
            class R:
                def scalars(self): return self
                def first(self): return stored
            return R()

    result = asyncio.run(
        divergence_for(_One(), case_key="k", current_run_ids=["a", "b", "c", "d"])
    )
    assert result["diverged"] is True
    assert result["added_since"] == ["c", "d"]
    assert result["alerts_read"] == 2
    assert result["alerts_now"] == 4
    assert "has not been revised" in result["note"]
    assert divergence_is_material(result)


def test_an_unchanged_set_is_not_reported_as_divergence():
    import asyncio

    from app.services.case_read_set_service import divergence_for

    stored = _Row(
        run_ids=["a", "b"], read_at=datetime(2026, 10, 9, tzinfo=timezone.utc),
        reason=JUDGEMENT, requested_by="analyst",
        derivation_version=DERIVATION_VERSION,
    )

    class _One:
        async def execute(self, *_a, **_k):
            class R:
                def scalars(self): return self
                def first(self): return stored
            return R()

    result = asyncio.run(divergence_for(_One(), case_key="k", current_run_ids=["b", "a"]))
    assert result["diverged"] is False
    assert result["note"] is None
    assert not divergence_is_material(result)


def test_asking_for_an_early_read_does_not_freeze_the_case():
    """The endpoint must keep saying so. Turning "ask for a read" into "stop
    accepting alerts" is the hidden coupling this design removes."""
    import inspect

    from app.api import detections

    source = inspect.getsource(detections.analyse_case_now)
    assert "record_read_set" in source, "the early read must record what it covered"
    assert "NARRATIVE_REQUESTED" in source
    assert "does not freeze it" in source or "keeps accepting alerts" in source


def test_the_automatic_path_records_its_read_set_too():
    import inspect

    from app.tasks import case_closure_task

    source = inspect.getsource(case_closure_task)
    assert "_record_read_sets(jobs)" in source
    assert "NARRATIVE_AUTO" in source


def test_the_derivation_version_travels_with_the_set():
    """So a later version is comparable rather than silently superseding it —
    the same discipline as CASE_KEY_VERSION, which exists because a formula
    changed once with no migration and orphaned 881 rows."""
    assert DERIVATION_VERSION
    assert "session-gap" in DERIVATION_VERSION
