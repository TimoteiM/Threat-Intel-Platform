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
    url_lexical_observations,
)
from app.tasks.analysis_task import _inject_lexical_contribution


def _lexical(label, score, features=None, top=None):
    """A lexical payload. `label` is accepted and discarded.

    The low/medium/high band was removed on 2026-10-19 with the model and its
    calibration (docs/design/lexical-scoring-retirement.md). The parameter
    stays so these tests keep reading as the scenarios they describe — "a
    medium-scoring shape-only URL" — without every call site growing a comment
    about a field that no longer exists. `score` survives because the risk
    blend still reads it.
    """
    payload = {"score": score}
    if features is not None:
        payload["features"] = features
        payload["observations"] = url_lexical_observations(features)
    if top is not None:
        payload["top_features"] = top
    return payload


# --- the gate, which no longer exists --------------------------------------

def test_the_shape_flag_is_gone_rather_than_defaulted_off():
    """`URL_SHAPE_AFFECTS_SCORE` is removed, not set to false.

    It gated two things: the lexical aggregate's points in the weak-signal
    cluster, and the 25% blend into the risk score. Both were removed on
    2026-10-19, so the flag had nothing left to switch — and an inert flag is
    worse than no flag, because somebody sets it and expects shape to score.

    What it never switched off was the semantic half, which still scores
    unconditionally, as named observations. See
    docs/design/lexical-scoring-retirement.md.
    """
    from app.config import Settings

    assert "url_shape_affects_score" not in Settings.model_fields
    assert not hasattr(de, "url_shape_affects_score")
    import app.tasks.analysis_task as at
    assert not hasattr(at, "url_shape_affects_score")


# --- what counts as semantic ------------------------------------------------

def test_a_real_sharepoint_link_scores_high_on_shape_alone():
    """The premise of the whole change, measured rather than asserted: this is a
    genuine SharePoint URL and the model rates it HIGH."""
    lexical = assess_url_lexical_risk(
        "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Forms/"
        "AllItems.aspx?id=%2Fsites%2FFinance%2FShared%20Documents%2FFY26%20Budget"
        "%20Review%2Epptx&parent=%2Fsites%2FFinance"
    )
    # There is no score and no label left to assert. The premise this test
    # was written to defend — that a genuine SharePoint deep link looks
    # alarming to a shape heuristic — is now expressed as the thing that
    # matters: it produces no checkable observation, so nothing about it
    # reaches a verdict.
    assert "score" not in lexical
    assert "label" not in lexical
    assert semantic_features_present(lexical) == []
    assert lexical["observations"] == []

    score, reasons = de._domain_weak_signal_score({"url_lexical_ml": lexical})
    assert score == 0
    # The reason list no longer carries "Lexical model high risk (0.99) —
    # driven by URL shape, not scored". A shape-only URL now contributes no
    # reason at all, because the only thing there was to say was the number.
    assert not any("risk" in r.lower() for r in reasons)


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


def test_shape_alone_cannot_score_at_all_now():
    """There is no longer a configuration in which URL shape scores.

    This test used to flip `url_shape_affects_score` and assert the points
    came back. The flag is gone and so are the points: a shape-only URL
    contributes 0 to the weak-signal cluster, unconditionally.
    """
    lexical = _lexical("high", 0.99, features={"url_length": 300.0, "entropy": 5.0,
                                               "subdomain_depth": 5.0})
    score, reasons = de._domain_weak_signal_score({"url_lexical_ml": lexical})
    assert score == 0
    assert not any("risk" in r.lower() for r in reasons)


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
    assert finding["title"] == "URL structure observations"
    # No probability anywhere in the finding, which is the decision.
    assert "0.56" not in finding["description"]
    assert "MEDIUM" not in finding["description"]
    # A shape-only URL has nothing checkable to report, and the finding says
    # that in words instead of printing a number that moved nothing.
    assert "No notable observations" in finding["description"]
    assert report["key_evidence"] == [], "nothing to show when there is no observation"


def test_a_semantic_verdict_no_longer_moves_the_risk_score():
    lexical = _lexical("high", 0.85, features={"has_punycode": 1.0, "has_sensitive_keyword": 1.0})
    report = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    # **The blend is gone.** This used to lift 20/100 to 40/100 because the
    # lexical score was 0.85 and carried 25% of the weight. Measured before
    # removing it: a median 13 points on 575 of 2,669 stored reports, with no
    # band change, because the final score is clamped into the band of the
    # classification and the classification does not read the probability.
    assert report["risk_score"] == 20
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    assert finding["severity"] == "informational"
    # The observations are still reported — they are the evidence.
    assert "punycode" in finding["description"]
    assert any("URL structure" in line for line in report["key_evidence"])
    # And no points disclosure, because there are no points.
    assert "moved the risk score" not in finding["description"]


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


# --- what the report says now -------------------------------------------------


def test_the_report_names_observations_and_never_a_probability():
    report = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    lexical = _lexical("high", 0.9, features={"has_ip_host": 1.0, "has_sensitive_keyword": 1.0})
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    text = " ".join(report["key_evidence"]) + " ".join(
        f["description"] for f in report["findings"]
    )
    assert "raw IP address" in text
    assert "sensitive keyword" in text
    for banned in ("Lexical model", "lexical ML is", "HIGH", "MEDIUM", "0.9000", "raw=", "calibrated="):
        assert banned not in text, f"{banned!r} is still printed in the report"


def test_nothing_about_the_url_reaches_the_risk_score():
    """The whole of the decision, in one assertion.

    Every lexical payload shape — shape-only, semantic, every semantic feature
    at once — leaves the risk score exactly as it found it. There is no flag
    and no weight that changes this.
    """
    from app.services.url_lexical_ml_service import SEMANTIC_FEATURES

    cases = [
        _lexical("medium", 0.56, features={"url_length": 190.0, "entropy": 4.6}),
        _lexical("high", 0.85, features={"has_punycode": 1.0, "has_sensitive_keyword": 1.0}),
        _lexical("high", 0.99, features={name: 1.0 for name in SEMANTIC_FEATURES}),
        _lexical("low", 0.01, features={}),
    ]
    for lexical in cases:
        report = {"risk_score": 37, "classification": "suspicious",
                  "findings": [], "key_evidence": []}
        _inject_lexical_contribution(report, {"url_lexical_ml": lexical})
        assert report["risk_score"] == 37, lexical.get("observations")
    # The rationale says so rather than printing a weight of 0.00.
    assert "does not contribute to the risk score" in report["risk_rationale"]


def test_an_unassessed_url_is_not_reported_as_a_clean_one():
    """`enabled: False` is the exception path. It used to arrive with
    `score: 0.0`, which is a legitimate value meaning "nothing unusual"."""
    report = {"risk_score": 40, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(
        report, {"url_lexical_ml": {"enabled": False, "error": "urlparse blew up"}}
    )

    assert report["risk_score"] == 40, "a failure must not move the score"
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    assert finding["title"] == "URL structure not assessed"
    assert "absence of evidence, not an absence of risk" in finding["description"]
    assert "urlparse blew up" in finding["description"]


def test_an_unassessed_url_with_no_reason_says_that_too():
    report = {"risk_score": 40, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": {"enabled": False}})
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    assert "No reason was recorded" in finding["description"]


def test_strong_observations_are_derived_for_evidence_written_before_the_field_existed():
    """Stored evidence has `features` but no `observations`. Returning an empty
    list for those would present an absence as a fact — every historical
    record would read as "no observations found"."""
    from app.services.url_lexical_ml_service import strong_observations

    legacy = {"features": {"has_ip_host": 1.0}, "score": 0.9}
    assert strong_observations(legacy) == ["ip_host"]
    assert strong_observations({"features": {"url_length": 200.0}}) == []
    assert strong_observations({}) == []
    assert strong_observations(None) == []
