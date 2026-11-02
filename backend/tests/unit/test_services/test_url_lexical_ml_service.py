"""Lexical URL observations, after the model and the probability were retired.

What this file asserted before 2026-10-19 was mostly about reporting a skipped
model honestly. There is no model to skip now: the artefact is retired and the
settings that pointed at it are gone, so those tests describe a world that no
longer exists and have been replaced rather than adapted.

The decisions and their measurements:
`docs/design/lexical-scoring-retirement.md`,
`docs/measurements/url-lexical-three-arms.md`.
"""

import pytest

from app.services import url_lexical_ml_service as mod
from app.services.ml_url_model import SCORER, UNAVAILABLE_VERSION, score_url
from app.services.url_lexical_ml_service import (
    RULE_OBSERVATIONS,
    assess_url_lexical_risk,
    extract_url_lexical_features,
    url_lexical_observations,
)


def test_extract_features_flags_ip_and_suspicious_tld() -> None:
    features = extract_url_lexical_features("http://192.168.1.10/login?verify=account")
    assert features["has_ip_host"] == 1.0
    assert features["has_sensitive_keyword"] == 1.0
    assert features["query_param_count"] >= 1.0


# ── the retirement, asserted rather than documented ──────────────────────


def test_there_is_no_model_and_no_way_to_configure_one():
    """Decision 2: retire the artefact, do not leave a disabled flag.

    A flag defaulting to false is one edit away for whoever finds the model
    file and reads only its name. So the settings are gone, and so is every
    function that could have loaded it.
    """
    from app.config import get_settings

    settings = get_settings()
    assert not hasattr(settings, "url_lexical_model_path")
    assert not hasattr(settings, "url_lexical_use_lightgbm")

    for gone in ("_load_lightgbm_model", "_score_lightgbm", "_should_use_lightgbm",
                 "_configured_model_path"):
        assert not hasattr(mod, gone), f"{gone} survived the retirement"
    assert "lightgbm" not in dir(mod)


def test_there_is_no_calibration_left_to_misapply():
    """Decision 1: remove the foreign curve rather than gate it.

    It was loaded by model path and applied to whatever produced the score. A
    gate would have left the loading in place for the next person to re-enable.
    """
    for gone in ("_load_calibration_metadata", "_calibrate_score"):
        assert not hasattr(mod, gone), f"{gone} survived"
    result = assess_url_lexical_risk("https://example.com/login")
    assert "calibration_applied" not in result


def test_no_probability_leaves_this_module_at_all():
    """The probability is gone from the payload, not merely unbanded.

    It survived one more turn than the label did, for the 25% risk blend. That
    blend was removed on 2026-10-19 — measured at a median 13 risk points on
    575 of 2,669 stored reports, with no band change — so nothing reads the
    number and it is no longer returned. With it went `weights` and
    `rule_floor_applied`: the weight existed to blend a score and the floor to
    raise one.
    """
    result = assess_url_lexical_risk(
        "http://secure-update-account-login.verify-paypa1-example.top/auth?session=1"
    )
    for gone in ("score", "label", "thresholds", "weights", "raw_score",
                 "calibration_applied", "rule_floor_applied"):
        assert gone not in result, f"{gone} is still in the payload"
    assert not hasattr(mod, "_rule_based_floor")
    assert not hasattr(mod, "LEXICAL_WEIGHT")
    assert not hasattr(mod, "_score_to_label")
    assert not hasattr(mod, "LOW_THRESHOLD")
    assert not hasattr(mod, "HIGH_THRESHOLD")


def test_the_old_signature_still_works_so_callers_do_not_raise():
    """`model_path_override` is accepted and ignored. Removing the parameter
    would turn a retirement into a crash for any caller still passing it."""
    a = assess_url_lexical_risk("https://example.com")
    b = assess_url_lexical_risk("https://example.com", model_path_override="/no/such/model.txt")
    assert a == b


# ── the observations, which are what is reported ─────────────────────────


def test_a_raw_ip_host_is_reported_as_a_statement_not_a_score():
    result = assess_url_lexical_risk("http://192.168.1.10/login?verify=account")
    codes = [o["code"] for o in result["observations"]]
    assert "ip_host" in codes
    statement = next(o["statement"] for o in result["observations"] if o["code"] == "ip_host")
    # Checkable by a person reading the URL, which is the whole point.
    assert "IP address" in statement


def test_every_observation_code_has_a_statement():
    """A code with no sentence is a label by another name: the reader gets
    `disposable_tld_and_keyword` and has to guess what was checked."""
    for code, statement in RULE_OBSERVATIONS:
        assert statement.strip(), code
        assert statement.strip().endswith("."), f"{code} is not a sentence"
        assert code.islower() and " " not in code


def test_a_plain_url_yields_no_observations_and_that_is_not_an_error():
    result = assess_url_lexical_risk("https://www.w3.org/1999/xhtml/")
    assert result["observations"] == []
    assert result["enabled"] is True
    assert "error" not in result


def test_observations_are_ordered_so_two_reports_agree():
    """Fixed order, not set order. Two reports on the same URL that list the
    same facts in different sequences read as two different findings."""
    url = "http://xn--pple-43d.secure-login.top:8443/account?a=1&b=2&c=3&d=4&e=5"
    first = [o["code"] for o in assess_url_lexical_risk(url)["observations"]]
    second = [o["code"] for o in assess_url_lexical_risk(url)["observations"]]
    assert first == second
    declared = [c for c, _ in RULE_OBSERVATIONS]
    assert first == [c for c in declared if c in first]


def test_the_observations_cover_what_the_rule_floor_used_to_decide():
    """The floor's tiers are the reportable facts, which is why they were kept.

    Each floor-triggering condition must surface as an observation — otherwise
    the thing that produced every genuine high verdict would have been dropped
    along with the probability.
    """
    cases = [
        ("http://10.0.0.5/pay", "ip_host"),
        ("https://good.example.com/x@y", "at_symbol"),
        ("http://xn--pple-43d.com/login", "punycode"),
        # `.top`, not `.tk`: the list is `_SUSPICIOUS_TLDS` and `.tk` is not
        # in it. The first version of this test guessed, which is the error
        # the rest of this file exists to prevent.
        ("http://verify-account.top/login", "disposable_tld"),
        ("https://bit.ly/3abcdef", "shortener"),
        ("https://example.com:8443/x", "abnormal_port"),
    ]
    for url, expected in cases:
        codes = [o["code"] for o in assess_url_lexical_risk(url)["observations"]]
        assert expected in codes, f"{url} did not report {expected}: got {codes}"


def test_observations_are_computed_from_features_not_from_the_score():
    """The control for the test above: a URL whose heuristic score is high but
    which trips no named rule must report no observations. Otherwise the
    observation list is just the score in another costume."""
    features = extract_url_lexical_features(
        "https://a-very-long-but-otherwise-ordinary-corporate-link.example.com/"
        + "segment/" * 12
    )
    assert url_lexical_observations(features) == []


# ── the facade ───────────────────────────────────────────────────────────


def test_the_facade_names_no_model_and_no_risk_level():
    payload = score_url("http://192.168.1.10/login")
    assert payload["scorer"] == SCORER
    assert "model_version" not in payload
    assert "risk_level" not in payload
    assert "phishing_probability" not in payload
    assert "ip_host" in [o["code"] for o in payload["observations"]]


def test_the_schema_defaults_claim_nothing():
    """A Pydantic default is a value somebody reads as a measurement. These
    defaulted to `"lgbm-url-v1.0"` and `risk_level: "low"` — a model that never
    ran, reporting low risk."""
    from app.models.schemas import URLLexicalMLEvidence, URLMLScoreEvidence

    facade = URLMLScoreEvidence()
    assert facade.scorer == UNAVAILABLE_VERSION
    assert facade.observations == []
    assert not hasattr(facade, "risk_level")
    assert not hasattr(facade, "phishing_probability")

    lexical = URLLexicalMLEvidence()
    assert lexical.observations == []
    assert not hasattr(lexical, "label")
    assert not hasattr(lexical, "thresholds")
    assert not hasattr(lexical, "calibration_applied")


def test_the_reported_observations_cover_everything_that_scores():
    """Nothing may move the risk score without appearing in the report.

    The decision engine scores `SEMANTIC_FEATURES`. The first version of this
    change reported only the floor's *combinations*, so a URL with a sensitive
    keyword and nothing else scored a point in the weak-signal cluster and
    produced no observation to explain it — the probability's own defect,
    rebuilt.
    """
    from app.services.url_lexical_ml_service import SEMANTIC_FEATURES

    feature_to_code = {
        "has_ip_host": "ip_host",
        "has_at_symbol": "at_symbol",
        "has_punycode": "punycode",
        "has_sensitive_keyword": "sensitive_keyword",
        "has_suspicious_tld": "disposable_tld",
        "is_shortener": "shortener",
    }
    declared = {code for code, _ in RULE_OBSERVATIONS}
    assert set(feature_to_code) == set(SEMANTIC_FEATURES), (
        "a scored semantic feature has no observation mapping"
    )
    for feature, code in feature_to_code.items():
        assert code in declared, f"{feature} scores but is not reportable"
        found = url_lexical_observations({feature: 1.0})
        assert [o["code"] for o in found] == [code], (
            f"{feature} alone did not produce {code}"
        )


def test_a_single_weak_fact_does_not_escalate():
    """`sensitive_keyword` alone fires on an enormous amount of legitimate
    mail, and `shortener` alone is how half of marketing email is written.
    They are reported, and they are not enough to mark a URL risky."""
    from app.services.url_lexical_ml_service import strong_observations

    for feature in ("has_sensitive_keyword", "has_suspicious_tld", "is_shortener", "has_punycode"):
        payload = {"features": {feature: 1.0}}
        assert url_lexical_observations(payload["features"]), feature
        assert strong_observations(payload) == [], f"{feature} escalated on its own"

    # The control: the combinations the floor did escalate on still do.
    assert strong_observations({"features": {"has_ip_host": 1.0}}) == ["ip_host"]
    assert strong_observations(
        {"features": {"has_punycode": 1.0, "has_sensitive_keyword": 1.0}}
    ) == ["punycode", "sensitive_keyword"]
