"""
URL lexical facade.

A stable payload shape for the lexical observations, for consumers that read
`ml_url_score` rather than `url_lexical_ml`.

**No model, no version, no risk level.** Until 2026-10-19 this module returned
`model_version: "lgbm-url-v1.0"` on every call — on the success path, on the
exception path, and as a Pydantic default — while the score came from the
built-in heuristic because the LightGBM flag was off. The artefact is now
retired outright (see `docs/design/lexical-scoring-retirement.md`), so there
is no version to name and no `risk_level` band to report: a low/medium/high
label beside a probability reads as a measurement, and against the only
external labels available this one ranked below a coin flip.

What remains is what a person can check: the named observations about how the
URL is written, and the numeric features behind them.
"""

from __future__ import annotations

from typing import Any

from app.services.url_lexical_ml_service import assess_url_lexical_risk

#: What produced the observations. Not a model version — there is no model.
#: Kept as a field because stored evidence carries one and a reader comparing
#: an old record with a new one needs to see which is which.
SCORER = "built-in-lexical-v1"

#: The value for a payload where the assessment did not run. The old default
#: was the LightGBM version string, so a payload nobody set the field on still
#: claimed a model had scored it.
UNAVAILABLE_VERSION = "unavailable"


def score_url(url: str) -> dict[str, Any]:
    """Return the lexical observation payload for a URL."""
    lexical = assess_url_lexical_risk(url)
    contribs = lexical.get("feature_contributions") or {}
    top_features = [
        {"name": str(name), "impact": round(float(contribs.get(name) or 0.0), 6)}
        for name in (lexical.get("top_features") or [])[:5]
    ]
    payload: dict[str, Any] = {
        "url": url,
        "scorer": SCORER,
        "observations": lexical.get("observations") or [],
        "top_features": top_features,
        "raw": lexical,
    }
    if lexical.get("error"):
        payload["error"] = lexical["error"]
    return payload
