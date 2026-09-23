"""The weak-signal cluster and the lexical model report, but do not decide.

Both key heavily on URL *shape* — entropy, dot count, length, subdomain depth
— and a legitimate deep link into SharePoint or Office scores MEDIUM on all of
them. With a shared-hosting observation and a registrar pivot that reached the
three points which make a domain "suspicious", on an observable where nothing
suspicious had actually been found.

The evidence is still collected and still shown. What it no longer does is set
the verdict.
"""

from __future__ import annotations

import pytest

from app.services import decision_engine as de


def test_weak_signals_do_not_score_by_default():
    assert de.weak_signals_affect_score() is False


def test_the_setting_can_restore_the_old_behaviour():
    """Injected rather than monkeypatched into app.config: this suite reloads
    `app` through importlib elsewhere, and a dotted string target stops
    resolving once it has."""
    class _On:
        weak_signals_affect_score = True

    class _Off:
        weak_signals_affect_score = False

    assert de.weak_signals_affect_score(_On()) is True
    assert de.weak_signals_affect_score(_Off()) is False


def test_the_field_defaults_to_off():
    from app.config import Settings

    assert Settings.model_fields["weak_signals_affect_score"].default is False


def test_both_scoring_paths_read_the_same_rule():
    """decision_engine and the deterministic path in analysis_task both
    escalated on weak_score. Gating one and not the other would give two
    different verdicts for the same evidence."""
    import inspect

    from app.tasks import analysis_task

    engine = inspect.getsource(de)
    task = inspect.getsource(analysis_task)
    assert "weak_score >= 4 and weak_signals_affect_score()" in engine
    assert "weak_score >= 3 and weak_signals_affect_score()" in engine
    assert "weak_signal_score >= 4 and weak_signals_affect_score()" in task
    assert "weak_signal_score >= 3 and weak_signals_affect_score()" in task


def test_the_cluster_is_still_reported_when_it_does_not_score():
    """Silently dropping the finding would lose the observation entirely; the
    point is to stop it deciding, not to stop it being seen."""
    import inspect

    source = inspect.getsource(de)
    assert '"id": "weak_signal_cluster"' in source
    assert "reported for review only" in source
    assert '"informational"' in source


def test_the_lexical_finding_is_relabelled_when_it_does_not_score():
    import inspect

    from app.tasks import analysis_task

    source = inspect.getsource(analysis_task)
    assert "URL lexical ML observation" in source
    assert "long legitimate" in source


def test_a_long_benign_url_still_produces_weak_signal_evidence():
    """The evidence is unchanged — only its authority is."""
    evidence = {
        "url_lexical_ml": {"label": "medium", "score": 0.40,
                           "top_features": ["entropy", "url_length", "subdomain_depth"]},
        "email_security": {"spoofability_score": "high"},
        "infrastructure_pivot": {"shared_hosting_detected": True},
        "signals": [{"id": "sig_high_spoofability"}],
    }
    score, reasons = de._domain_weak_signal_score(evidence)
    assert score >= 1
    assert any("Lexical model medium risk" in r for r in reasons)
