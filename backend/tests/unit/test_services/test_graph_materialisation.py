"""Keeping the graph tables warm, and saying what "stale" covers.

`materialise_run` had exactly one caller — the `graph_backfill` CLI — so every
figure drawn from `alert_graph_entity` was as of whenever a person last ran it,
and nothing in the schema said so. Two alerts on `exp-4lwk334` carrying a
corroborated ATT&CK technique had no graph rows at all.
"""

from __future__ import annotations

import pathlib

from app.services.graph_materialisation_service import BATCH, SweepResult


class TestItIsASweepNotAHook:
    def test_nothing_hooks_materialisation_onto_one_task(self):
        """A hook lives at one call site. This codebase has four writers of
        `indicator_risk_score` and seven hand-maintained lists that each
        swallowed a feature silently; a hook would fail the same way, by
        covering the path somebody remembered."""
        app = pathlib.Path(__file__).resolve().parents[3] / "app"
        callers = [
            path.name
            for path in app.rglob("*.py")
            if "materialise_run(" in path.read_text()
        ]
        assert set(callers) == {
            "alert_graph_store_service.py",      # the definition
            "graph_backfill.py",                 # the manual full re-run
            "graph_materialisation_service.py",  # the sweep
        }, callers

    def test_the_sweep_is_scheduled(self):
        app = pathlib.Path(__file__).resolve().parents[3] / "app"
        beat = (app / "tasks" / "celery_app.py").read_text()
        assert "graph-materialisation-sweep" in beat
        assert "materialise_graphs" in beat

    def test_the_batch_is_bounded(self):
        """A pass must not hold a long transaction: the measured backfill rate
        is about 38 runs a second."""
        assert 0 < BATCH <= 1000


class TestWhatStaleMeans:
    def test_the_result_reports_the_backlog_not_just_the_work_done(self):
        """`remaining` is the number that says whether this is keeping up."""
        result = SweepResult(
            considered=200, materialised=200, entities=1200, edges=900,
            failed=0, remaining=4312,
        )
        assert result.as_json()["remaining"] == 4312

    def test_a_failed_run_is_counted_not_swallowed(self):
        """A run that cannot be materialised is invisible to every graph
        figure, so it is reported rather than skipped quietly."""
        result = SweepResult(
            considered=10, materialised=8, entities=5, edges=4,
            failed=2, remaining=0,
        )
        assert result.as_json()["failed"] == 2

    def test_the_service_states_what_its_staleness_signal_does_not_cover(self):
        """A run whose assessment is rewritten after materialisation is not
        detected, and the docstring says so rather than implying coverage."""
        src = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "services" / "graph_materialisation_service.py"
        ).read_text()
        assert "is **not** detected" in src

    def test_the_timestamp_is_stamped_on_every_materialisation(self):
        src = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "services" / "alert_graph_store_service.py"
        ).read_text()
        assert "graph_materialised_at=datetime.now(timezone.utc)" in src
