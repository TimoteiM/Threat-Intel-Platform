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
    # There is no label to assert any more. The premise is unchanged and is
    # now stated on the score, which is what the band was derived from: a
    # genuine SharePoint link scores as high as this heuristic goes.
    assert lexical["score"] >= 0.65
    assert "label" not in lexical
    assert semantic_features_present(lexical) == []
    # And the point of the retirement: nothing about this URL is a checkable
    # observation, so the report now says so instead of printing 0.99.
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

    # **The flag no longer restores aggregate scoring here, and that is the
    # change rather than a regression.** It used to add 2 points from the
    # probability band. The band is gone, so there is nothing for the flag to
    # re-enable in the weak-signal cluster: a shape-only URL scores 0 whether
    # the flag is on or off.
    #
    # The flag is NOT dead — it still decides whether the probability blends
    # into the final risk score in `_inject_lexical_contribution`, which
    # `test_the_flag_still_governs_the_risk_blend` pins. Its meaning narrowed
    # from "shape can score anywhere" to "shape can move the risk blend".
    assert off == 0 and on == 0
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


def test_a_semantic_verdict_does_move_the_risk_score():
    lexical = _lexical("high", 0.85, features={"has_punycode": 1.0, "has_sensitive_keyword": 1.0})
    report = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(report, {"url_lexical_ml": lexical})

    assert report["risk_score"] > 20
    finding = next(f for f in report["findings"] if f["id"] == "lexical_ml_contribution")
    # Never "high". A severity on a lexical observation is the band this change
    # removed wearing a different field name.
    assert finding["severity"] == "informational"
    assert "punycode" in finding["description"]
    # And the blend is DISCLOSED: the probability no longer appears as a
    # verdict, but where it still moves the risk score the points are named.
    assert "moved the risk score by" in finding["description"]
    assert any("URL structure" in line for line in report["key_evidence"])


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


def test_the_flag_still_governs_the_risk_blend():
    """The other half of `test_the_flag_restores_shape_scoring`.

    `url_shape_affects_score` lost its effect on the weak-signal cluster when
    the aggregate went, but it still decides whether a shape-only URL's
    probability blends into the final risk score. Pinned so the narrowing is a
    recorded decision rather than something that quietly became total.
    """
    import app.tasks.analysis_task as at

    lexical = _lexical("medium", 0.56, features={"url_length": 190.0, "entropy": 4.6})

    off = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
    _inject_lexical_contribution(off, {"url_lexical_ml": lexical})
    assert off["risk_score"] == 20

    original = at.url_shape_affects_score
    at.url_shape_affects_score = lambda *a, **k: True
    try:
        on = {"risk_score": 20, "classification": "benign", "findings": [], "key_evidence": []}
        _inject_lexical_contribution(on, {"url_lexical_ml": lexical})
    finally:
        at.url_shape_affects_score = original

    assert on["risk_score"] > 20, "the flag no longer reaches the blend either"


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
