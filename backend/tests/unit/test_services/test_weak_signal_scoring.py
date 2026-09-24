"""URL *shape* does not decide a verdict; what a URL says about itself still does.

The lexical model's largest contributors measure size and structure — length,
entropy, dot count, subdomain depth, path depth. A legitimate deep link into
SharePoint scores HIGH on those alone, and three points makes a domain
"suspicious", so ordinary Office traffic was arriving as suspicious with
nothing suspicious having been found.

Shape is reported and not counted. Semantic features — a sensitive keyword,
punycode, a raw-IP host, an @, a shortener, a throwaway TLD — say something
about intent rather than size, and they still score.
"""

from __future__ import annotations

from app.services import decision_engine as de
from app.services.url_lexical_ml_service import (
    SEMANTIC_FEATURES,
    assess_url_lexical_risk,
    semantic_features_present,
)
from app.tasks.analysis_task import _inject_lexical_contribution


def _lexical(label, score, features=None, top=None):
    payload = {"label": label, "score": score}
    if features is not None:
        payload["features"] = features
    if top is not None:
        payload["top_features"] = top
    return payload


# --- the gate ---------------------------------------------------------------

def test_shape_does_not_score_by_default():
    assert de.url_shape_affects_score() is False


def test_the_setting_can_restore_the_old_behaviour():
    """Injected rather than monkeypatched into app.config: this suite reloads
    `app` through importlib elsewhere, and a dotted string target stops
    resolving once it has."""
    class _On:
        url_shape_affects_score = True

    class _Off:
        url_shape_affects_score = False

    assert de.url_shape_affects_score(_On()) is True
    assert de.url_shape_affects_score(_Off()) is False


def test_the_field_defaults_to_off():
    from app.config import Settings

    assert Settings.model_fields["url_shape_affects_score"].default is False


# --- what counts as semantic ------------------------------------------------

def test_a_real_sharepoint_link_scores_high_on_shape_alone():
    """The premise of the whole change, measured rather than asserted: this is a
    genuine SharePoint URL and the model rates it HIGH."""
    lexical = assess_url_lexical_risk(
        "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Forms/"
        "AllItems.aspx?id=%2Fsites%2FFinance%2FShared%20Documents%2FFY26%20Budget"
        "%20Review%2Epptx&parent=%2Fsites%2FFinance"
    )
    assert lexical["label"] == "high"
    assert semantic_features_present(lexical) == []

    score, reasons = de._domain_weak_signal_score({"url_lexical_ml": lexical})
    assert score == 0
    assert any("not scored" in r for r in reasons), "the observation must still be shown"


def test_brand_keyword_count_is_not_treated_as_semantic():
    """It fires on this estate's own mail: the search area includes the
    subdomain, so `outlook` in `outlook.office.com` counts, and a registrable
    label counts as a lookalike whenever it merely contains a brand, so
    `office365` counts as a lookalike of `office`."""
    assert "brand_keyword_count" not in SEMANTIC_FEATURES

    lexical = assess_url_lexical_risk("https://outlook.office365.com/mail/inbox")
    assert lexical["features"]["brand_keyword_count"] > 0
    assert semantic_features_present(lexical) == []
    assert de._domain_weak_signal_score({"url_lexical_ml": lexical})[0] == 0


def test_an_internal_service_on_an_odd_port_is_not_semantic():
    assert "has_abnormal_port" not in SEMANTIC_FEATURES

    lexical = assess_url_lexical_risk("https://tip-internal.expertware.net:8443/reports")
    assert lexical["features"]["has_abnormal_port"] == 1.0
    assert semantic_features_present(lexical) == []


def test_semantic_features_are_read_from_the_vector_not_just_the_top_five():
    """`top_features` is capped at five. A URL long enough to fill that list with
    shape features would otherwise hide its own punycode hostname."""
    lexical = _lexical(
        "high", 0.80,
        features={"has_punycode": 1.0, "url_length": 190.0, "entropy": 4.6},
        top=["url_length", "entropy", "path_length", "dot_count", "query_length"],
    )
    assert semantic_features_present(lexical) == ["has_punycode"]


# --- scoring behaviour ------------------------------------------------------

def test_a_sensitive_keyword_still_scores():
    """The feature the user named. Shape contributes nothing; this contributes."""
    lexical = _lexical("high", 0.82, features={"has_sensitive_keyword": 1.0, "url_length": 60.0})
    score, reasons = de._domain_weak_signal_score({"url_lexical_ml": lexical})
    assert score == 1
    assert any("sensitive keyword" in r for r in reasons)


def test_the_weak_but_real_cluster_still_escalates():
    """Lexical HIGH on a sensitive keyword, high spoofability, and registrant
    pivots reaching other investigated domains. A genuine detection, and the one
    the categorical version of this change would have lost."""
    evidence = {
        "url_lexical_ml": _lexical("high", 0.82, features={"has_sensitive_keyword": 1.0}),
        "email_security": {"spoofability_score": "high"},
        "infrastructure_pivot": {
            # Dicts carrying a "domains" list: a bare list of strings is not a
            # pivot the engine reads, and a pivot naming only this domain is the
            # domain corroborating itself.
            "registrant_pivots": [{"domains": ["login-secure-update.com", "account-verify-cdn.net"]}],
        },
        "observable": "login-secure-update.com",
    }
    score, _ = de._domain_weak_signal_score(evidence)
    assert score >= 3, "must still reach the threshold that makes a domain suspicious"


def test_shape_alone_cannot_reach_the_threshold():
    """The reported failure: a long legitimate link on crowded infrastructure."""
    evidence = {
        "url_lexical_ml": _lexical(
            "high", 0.71,
            features={"url_length": 210.0, "entropy": 4.7, "subdomain_depth": 2.0, "path_depth": 6.0},
        ),
        "email_security": {"spoofability_score": "high"},
        "infrastructure_pivot": {"shared_hosting_detected": True},
    }
    assert de._domain_weak_signal_score(evidence)[0] < 3


def test_the_flag_restores_shape_scoring():
    lexical = _lexical("high", 0.71, features={"url_length": 210.0, "entropy": 4.7})
    off, _ = de._domain_weak_signal_score({"url_lexical_ml": lexical})

    import app.services.decision_engine as module
    original = module.url_shape_affects_score
    module.url_shape_affects_score = lambda *a, **k: True
    try:
        on, reasons = de._domain_weak_signal_score({"url_lexical_ml": lexical})
    finally:
        module.url_shape_affects_score = original

    assert off == 0 and on == 2
    assert not any("not scored" in r for r in reasons)


def test_the_lexical_block_can_never_outweigh_its_old_ceiling():
    """Every semantic feature at once still contributes at most two points, so
    one URL cannot escalate itself."""
    lexical = _lexical("high", 0.99, features={name: 1.0 for name in SEMANTIC_FEATURES})
    assert de._domain_weak_signal_score({"url_lexical_ml": lexical})[0] == 2


# --- the 25% blend, which is where the model actually moved the number -------

def test_a_shape_only_verdict_does_not_move_the_risk_score():
    """The gap in the first attempt at this: the cluster was gated while this
    blend still ran, so the model went on lifting 20/100 to 29/100 on shape."""
    lexical = _lexical("medium", 0.56, features={"url_length": 190.0, "entropy": 4.6})
    report = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    assert report["risk_score"] == 20
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    assert finding["severity"] == "informational"
    assert finding["title"] == "URL lexical ML observation"
    assert any("Lexical ML" in line for line in report["key_evidence"]), "still shown to the analyst"


def test_a_semantic_verdict_does_move_the_risk_score():
    lexical = _lexical("high", 0.85, features={"has_punycode": 1.0, "has_sensitive_keyword": 1.0})
    report = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    assert report["risk_score"] > 20
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    assert finding["severity"] == "high"
    assert "punycode" in finding["description"]


def test_a_shape_only_verdict_does_not_invent_a_score_from_nothing():
    """With no upstream risk score the blend used to fall back to a 0.5 midpoint
    and write 50/100 — a number sourced entirely from a signal we just declined
    to count."""
    lexical = _lexical("medium", 0.56, features={"url_length": 190.0})
    report = {"classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    assert report.get("risk_score") is None


# --- one scorer, not two ----------------------------------------------------

def test_both_paths_use_the_same_scorer():
    """analysis_task carried its own fork, and it had drifted: no domain-age
    rule, no self-pivot check, and shared hosting and spoofability still scoring
    on their own. Identical evidence produced different scores depending on
    which path ran."""
    from app.tasks import analysis_task

    assert analysis_task._domain_weak_signal_score is de._domain_weak_signal_score
