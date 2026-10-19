from app.services.url_lexical_ml_service import (
    assess_url_lexical_risk,
    extract_url_lexical_features,
)


def test_extract_features_flags_ip_and_suspicious_tld() -> None:
    features = extract_url_lexical_features("http://192.168.1.10/login?verify=account")
    assert features["has_ip_host"] == 1.0
    assert features["has_sensitive_keyword"] == 1.0
    assert features["query_param_count"] >= 1.0


def test_assess_url_lexical_risk_high_for_obvious_phishing_pattern() -> None:
    result = assess_url_lexical_risk(
        "http://secure-update-account-login.verify-paypa1-example.top/auth?session=12345"
    )
    assert result["enabled"] is True
    assert result["model_source"] == "built_in"
    assert result["score"] >= 0.75
    assert result["label"] == "high"


def test_assess_url_lexical_risk_low_for_benign_reference() -> None:
    result = assess_url_lexical_risk("https://www.w3.org/1999/xhtml/")
    assert result["enabled"] is True
    assert result["score"] <= 0.45
    assert result["label"] in {"low", "medium"}


def test_assess_url_lexical_risk_fallbacks_to_built_in_when_model_missing() -> None:
    result = assess_url_lexical_risk(
        "https://example.com",
        model_path_override="C:/does-not-exist/url_model.json",
    )
    assert result["enabled"] is True
    assert result["model_source"] == "built_in"
    assert "error" in result


# ── a skip must not read as a clean result ───────────────────────────────
#
# The state these pin was live in production on 2026-10-19:
# `url_lexical_model_path` set, `url_lexical_use_lightgbm` false, so every URL
# was scored by the built-in heuristic while the payload said `error: None`
# and `ml_url_score.model_version: "lgbm-url-v1.0"`. A model that scored this
# URL and a model nobody loaded had identical observations.
#
# These assert the *reporting*, not the score. Backlog 41 part 2 is whether to
# turn the model on, which does change scores and needs its own measurement.

import pytest

from app.services import url_lexical_ml_service as mod
from app.services.ml_url_model import (
    BUILT_IN_VERSION,
    MODEL_VERSION,
    UNAVAILABLE_VERSION,
    score_url,
    version_for_source,
)


@pytest.fixture
def no_calibration(monkeypatch):
    """Isolate the skip note from the calibration note.

    `assess_url_lexical_risk` loads calibration from the model path, and on a
    machine where that metadata exists the two notes concatenate. These tests
    are about the skip, so the calibration is removed rather than asserted
    around — otherwise they would pass or fail on whether a file happens to
    sit next to the configured model.
    """
    monkeypatch.setattr(mod, "_load_calibration_metadata", lambda _p: {})


def test_a_configured_model_that_is_not_loaded_says_so(monkeypatch, no_calibration):
    monkeypatch.setattr(mod, "_should_use_lightgbm", lambda: False)
    monkeypatch.setattr(mod, "_configured_model_path", lambda: "/models/url_lexical.txt")

    result = assess_url_lexical_risk("https://example.com/login")

    assert result["model_source"] == "built_in"
    assert "error" in result, "a configured model that never ran reported nothing"
    assert "not loaded" in result["error"]
    assert "built-in lexical heuristic" in result["error"]


def test_no_configured_model_is_not_an_error(monkeypatch, no_calibration):
    """The narrow claim. `error` means *something was configured and skipped*,
    not *the built-in scored this* — otherwise every deployment that never
    configured a model reports a permanent error and the field stops meaning
    anything."""
    monkeypatch.setattr(mod, "_should_use_lightgbm", lambda: False)
    monkeypatch.setattr(mod, "_configured_model_path", lambda: None)

    result = assess_url_lexical_risk("https://example.com/login")

    assert result["model_source"] == "built_in"
    assert "error" not in result


def test_calibration_from_a_model_that_did_not_run_is_reported(monkeypatch):
    """The sharper half, and it is score-affecting.

    The calibration curve comes from the *model's* metadata file and is
    applied whatever produced the score. With the model file and its
    `.metadata.json` both present and the flag off — the measured state of
    this deployment — a curve fitted to LightGBM outputs is applied to the
    heuristic's output, and `calibration_applied: True` beside
    `model_source: built_in` reads as a calibrated model score.
    """
    monkeypatch.setattr(mod, "_should_use_lightgbm", lambda: False)
    monkeypatch.setattr(mod, "_configured_model_path", lambda: "/models/url_lexical.txt")
    monkeypatch.setattr(mod, "_calibrate_score", lambda score, meta: 0.5)
    monkeypatch.setattr(mod, "_load_calibration_metadata", lambda _p: {"method": "isotonic"})

    result = assess_url_lexical_risk("https://example.com/login")

    assert result["calibration_applied"] is True
    assert "the model itself did not run" in result["error"]


def test_the_version_names_what_ran_and_defaults_to_no_claim():
    assert version_for_source("lightgbm") == MODEL_VERSION
    assert version_for_source("built_in") == BUILT_IN_VERSION
    # The dangerous direction: an unknown source must not inherit the
    # strongest claim available.
    assert version_for_source(None) == UNAVAILABLE_VERSION
    assert version_for_source("") == UNAVAILABLE_VERSION
    assert version_for_source("something_new") == UNAVAILABLE_VERSION


def test_the_facade_does_not_claim_lightgbm_for_a_heuristic_score(monkeypatch, no_calibration):
    monkeypatch.setattr(mod, "_should_use_lightgbm", lambda: False)
    monkeypatch.setattr(mod, "_configured_model_path", lambda: "/models/url_lexical.txt")

    payload = score_url("https://example.com/login")

    assert payload["model_source"] == "built_in"
    assert payload["model_version"] == BUILT_IN_VERSION
    assert payload["model_version"] != MODEL_VERSION
    # The note is on the payload's own surface, not only inside `raw`.
    assert "not loaded" in payload["error"]


def test_the_schema_default_makes_no_claim():
    """A Pydantic default is a value somebody will read as a measurement.

    `model_version` defaulted to `"lgbm-url-v1.0"`, so a payload the field was
    never set on still asserted that a LightGBM model ran.
    """
    from app.models.schemas import URLMLScoreEvidence

    assert URLMLScoreEvidence().model_version == UNAVAILABLE_VERSION
    assert URLMLScoreEvidence().model_source == ""
