"""The dominant-term check, as a type rather than a habit.

Six instances of a statistic whose dominant term was an artefact is the point
at which remembering to check stops being a strategy. The one intervention
that has held is a return type a caller cannot drop — `falcon_client.Page` for
bounded reads, this for aggregates.

Written in the dangerous direction: the failure is never an error, it is a
pooled rate that reads as a property of the population.
"""

from __future__ import annotations

from app.services import concentration as cc


def _alerts(host, n, tp):
    """n alerts for `host`, `tp` of them true positives."""
    return ([{"host": host, "tp": True}] * tp
            + [{"host": host, "tp": False}] * (n - tp))


def _tp_rate(rows):
    if not rows:
        return 0.0
    return sum(1 for r in rows if r["tp"]) / len(rows)


def test_the_real_case_the_pooled_rate_is_one_machine():
    """2,047 alerts, 21.9% true positive — and one laptop is 70.4% of them and
    holds 98% of the true positives. Held out: 2.3%."""
    rows = _alerts("exp-22my264", 1442, 371) + _alerts("everything-else", 605, 7)
    out = cc.measure(rows, by=lambda r: r["host"], aggregate=_tp_rate)

    assert out.population == 2047
    assert out.top == "exp-22my264"
    assert out.top_count == 1442
    assert round(out.top_share, 3) == 0.704
    assert out.concentrated is True
    assert round(out.value, 3) == 0.185          # pooled
    assert round(out.held_out, 3) == 0.012       # an order of magnitude lower
    assert out.held_out_population == 605


def test_an_unconcentrated_aggregate_does_not_pay_for_a_holdout():
    """The control: the type must distinguish two states rather than always
    hedging, or 'concentrated' means nothing."""
    rows = sum((_alerts(f"host-{i}", 100, 20) for i in range(10)), [])
    out = cc.measure(rows, by=lambda r: r["host"], aggregate=_tp_rate)
    assert out.concentrated is False
    assert out.held_out is None
    assert round(out.top_share, 2) == 0.10
    assert "no one of them dominates" in out.sentence()


def test_the_held_out_figure_uses_the_SAME_aggregate():
    """Comparability by construction. Two figures computed by two methods are
    not a holdout, they are two numbers."""
    calls = []

    def agg(rows):
        calls.append(len(rows))
        return _tp_rate(rows)

    rows = _alerts("dominant", 800, 400) + _alerts("other", 200, 10)
    cc.measure(rows, by=lambda r: r["host"], aggregate=agg)
    assert calls == [1000, 200], (
        "the aggregate must be applied to the whole and to the remainder, "
        "with nothing else in between"
    )


def test_the_sentence_states_both_figures_when_concentrated():
    """An honest producer with an inattentive consumer is the failure this
    type exists to prevent, so the renderable form carries both."""
    rows = _alerts("laptop", 1442, 371) + _alerts("rest", 605, 7)
    out = cc.measure(rows, by=lambda r: r["host"], aggregate=_tp_rate)
    said = out.sentence(unit="alerts", fmt=lambda v: f"{v:.1%}")
    assert "18.5%" in said and "1.2%" in said
    assert "'laptop'" in said
    assert "70%" in said
    assert "2,047 alerts" in said and "605 alerts" in said


def test_an_empty_population_is_not_a_zero():
    out = cc.measure([], by=lambda r: r["host"], aggregate=_tp_rate)
    assert out.population == 0
    assert "no figure rather than a zero" in out.sentence()


def test_a_single_contributor_is_fully_concentrated_and_holds_out_to_nothing():
    """The degenerate case, stated rather than crashing: one host at 100% has
    an empty remainder, and the aggregate over nothing is whatever the
    caller's aggregate says — not a silently dropped figure."""
    rows = _alerts("only", 50, 10)
    out = cc.measure(rows, by=lambda r: r["host"], aggregate=_tp_rate)
    assert out.top_share == 1.0
    assert out.concentrated is True
    assert out.held_out_population == 0
    assert out.held_out == 0.0
