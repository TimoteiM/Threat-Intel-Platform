"""
URL ML model facade.

Provides a stable, explainable response contract for lexical URL risk scoring.
"""

from __future__ import annotations

from typing import Any

from app.services.url_lexical_ml_service import assess_url_lexical_risk

#: What produced the score, named by what actually ran.
#:
#: `MODEL_VERSION` was returned unconditionally, so a payload scored by the
#: built-in heuristic still said `lgbm-url-v1.0` — a stronger version of the
#: same defect as `error: None`, because it does not merely omit the skip, it
#: names a model that did not run. On this deployment
#: `url_lexical_use_lightgbm` is false, so **every** `ml_url_score` payload has
#: been claiming a LightGBM version.
MODEL_VERSION = "lgbm-url-v1.0"
BUILT_IN_VERSION = "built-in-lexical-v1"
UNAVAILABLE_VERSION = "unavailable"

_VERSION_BY_SOURCE = {
    "lightgbm": MODEL_VERSION,
    "built_in": BUILT_IN_VERSION,
}


def version_for_source(model_source: str | None) -> str:
    """The version string for whatever scored it.

    An unrecognised source is `unavailable` rather than the LightGBM version:
    the default must not be the strongest claim available.
    """
    return _VERSION_BY_SOURCE.get(str(model_source or "").strip(), UNAVAILABLE_VERSION)


def score_url(url: str) -> dict[str, Any]:
    """Return normalized lexical-ML output payload for a URL."""
    lexical = assess_url_lexical_risk(url)
    score = float(lexical.get("score") or 0.0)
    top_features = []
    contribs = lexical.get("feature_contributions") or {}
    for name in (lexical.get("top_features") or [])[:5]:
        impact = float(contribs.get(name) or 0.0)
        top_features.append({"name": str(name), "impact": round(impact, 6)})
    payload: dict[str, Any] = {
        "url": url,
        "phishing_probability": round(score, 4),
        "risk_level": str(lexical.get("label") or "low"),
        "model_source": str(lexical.get("model_source") or ""),
        "model_version": version_for_source(lexical.get("model_source")),
        "top_features": top_features,
        "raw": lexical,
    }
    # Carried up rather than left inside `raw`: a consumer reading this
    # payload's own fields should not have to reach into the nested result to
    # discover that the model it is named after never ran.
    if lexical.get("error"):
        payload["error"] = lexical["error"]
    return payload

