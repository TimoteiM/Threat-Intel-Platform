"""A continuation is answered on its own alerts, not on its parent's verdict.

Inheritance was the one close path that wrote a disposition at close time, and
it held every post-close accretion in the estate. Measured on
`alert_case_spine` with `last_activity_at > closed_at`:

    auto         0 of 1,063   0.0%
    inherited   20 of    45  44.4%

All 20 were continuations, and the arrivals were real: of the 1,654 alerts
that joined them after their close, 1,654 were ingested after it and 0 were
already stored. #2021 carried a verdict formed on 8 alerts while holding 299
more; #1908 one alert against 125.

The fix is not a longer quiet period. A continuation exists *because* activity
resumed, so it is born mid-burst and the burst continues after the borrowed
verdict is written. Inheritance is the wrong operation: it copies a judgement
onto a case nothing has judged — which this platform already refused to do for
dead keys, surfacing the earlier conclusion attributed and dated instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.services.alert_case_closure_service import (
    ANSWERS_AT_CLOSE,
    AWAITING_ANALYSIS,
    accreted_after_close,
    classify_closure,
)

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)


@dataclass
class _Row:
    case_number: int = 2021
    case_key: str = "parent-key"
    resolution: str | None = "false_positive"
    closed_at: datetime | None = None
    closed_by: str | None = None
    closure_kind: str | None = "auto"
    narrative_markdown: str | None = None
    alerts_at_close: int | None = 8


class _FakeDB:
    def __init__(self, row):
        self._row = row

    async def execute(self, *_a, **_k):
        row = self._row

        class _R:
            def first(self_inner):
                return row

        return _R()


class TestTheParentsVerdictIsContextNotAVerdict:
    @pytest.mark.asyncio
    async def test_it_says_whose_judgement_it_is(self):
        from app.services.case_supersession_service import prior_judgement

        out = await prior_judgement(
            _FakeDB(_Row(closed_at=NOW - timedelta(days=1))),
            continues_case_key="parent-key",
        )
        assert out is not None
        assert "continues case #2021" in out["attribution"]
        assert "concluded false positive on 8 alerts" in out["attribution"]
        assert "not this case's" in out["attribution"]
        assert "answered on the alerts it holds" in out["attribution"]

    @pytest.mark.asyncio
    async def test_it_dates_the_earlier_conclusion(self):
        from app.services.case_supersession_service import prior_judgement

        out = await prior_judgement(
            _FakeDB(_Row(closed_at=datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc))),
            continues_case_key="parent-key",
        )
        assert "recorded 2026-10-07" in out["attribution"]

    @pytest.mark.asyncio
    async def test_a_parent_still_awaiting_analysis_claims_no_conclusion(self):
        """Not an answer to show, so it must not read like one."""
        from app.services.case_supersession_service import prior_judgement

        out = await prior_judgement(
            _FakeDB(_Row(resolution=AWAITING_ANALYSIS, closed_at=NOW)),
            continues_case_key="parent-key",
        )
        assert "recorded no conclusion" in out["attribution"]
        assert "concluded" not in out["attribution"]

    @pytest.mark.asyncio
    async def test_no_parent_means_no_context_rather_than_an_empty_one(self):
        from app.services.case_supersession_service import prior_judgement

        assert await prior_judgement(_FakeDB(_Row()), continues_case_key=None) is None
        assert await prior_judgement(_FakeDB(None), continues_case_key="gone") is None


class TestTheCloseNoLongerWritesABorrowedVerdict:
    def test_inherited_is_no_longer_written(self):
        """It stays classified for the 45 historical rows that really did carry
        a verdict written at close; it is not produced any more."""
        import ast
        import pathlib

        task = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "tasks" / "case_closure_task.py"
        )
        tree = ast.parse(task.read_text())
        written = {
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.keyword)
            and node.arg == "closure_kind"
            and isinstance(node.value, ast.Constant)
        }
        assert "inherited" not in written, (
            "the closure task writes `inherited` again; a continuation must "
            "not be closed carrying its parent's disposition"
        )
        assert "auto" in written

    def test_the_historical_kind_is_still_understood(self):
        assert classify_closure("inherited") == "judgement"
        assert "inherited" in ANSWERS_AT_CLOSE

    def test_a_continuation_closed_without_a_verdict_cannot_be_wrong_on_arrival(self):
        """The 44.4% goes to zero by construction: there is no disposition at
        close for later alerts to contradict."""
        assert AWAITING_ANALYSIS not in {
            "false_positive", "true_positive", "needs_review", "inconclusive",
        }
        # Accretion can still happen; it is no longer accretion under a verdict.
        assert accreted_after_close(
            closed_at=NOW, last_activity_at=NOW + timedelta(hours=6)
        ) is True

    def test_every_closed_case_is_asked_for_its_own_narrative(self):
        """The other half of inheritance was that a case arriving with a
        borrowed answer was never asked for its own."""
        import pathlib

        task = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "tasks" / "case_closure_task.py"
        ).read_text()
        assert 'if not entry["inherited"]' not in task
        assert "Every closed case is asked" in task
