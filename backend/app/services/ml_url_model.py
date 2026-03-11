"""
URL ML model facade.

Provides a stable, explainable response contract for lexical URL risk scoring.
"""

from __future__ import annotations

from typing import Any

from app.services.url_lexical_ml_service import assess_url_lexical_risk

MODEL_VERSION = "lgbm-url-v1.0"


def score_url(url: str) -> dict[str, Any]:
    """Return normalized lexical-ML output payload for a URL."""
    lexical = assess_url_lexical_risk(url)
    score = float(lexical.get("score") or 0.0)
    top_features = []
    contribs = lexical.get("feature_contributions") or {}
    for name in (lexical.get("top_features") or [])[:5]:
        impact = float(contribs.get(name) or 0.0)
        top_features.append({"name": str(name), "impact": round(impact, 6)})
    return {
        "url": url,
        "phishing_probability": round(score, 4),
        "risk_level": str(lexical.get("label") or "low"),
        "model_version": MODEL_VERSION,
        "top_features": top_features,
        "raw": lexical,
    }

