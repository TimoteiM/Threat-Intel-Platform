"""
URL lexical phishing scoring service.

Features:
- Deterministic lexical feature extraction from URL string
- Primary LightGBM model inference (if model file configured/available)
- Built-in heuristic fallback model (no external dependency required)
- Top feature explainability (Top 5)
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.config import get_settings

try:
    import lightgbm as lgb
except Exception:  # pragma: no cover - runtime fallback when lightgbm not installed
    lgb = None

LOW_THRESHOLD = 0.30
HIGH_THRESHOLD = 0.65
LEXICAL_WEIGHT = 0.25

FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_ratio",
    "subdomain_depth",
    "has_ip_host",
    "has_at_symbol",
    "has_punycode",
    "has_sensitive_keyword",
    "has_suspicious_tld",
    "query_param_count",
    "path_depth",
    "entropy",
    "is_shortener",
    "uses_https",
    "has_abnormal_port",
    "brand_keyword_count",
]

_SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "click",
    "work",
    "shop",
    "rest",
    "gq",
    "fit",
    "live",
    "cam",
    "buzz",
    "monster",
}

_SENSITIVE_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "signin",
    "password",
    "billing",
    "invoice",
    "wallet",
    "bank",
    "payment",
    "confirm",
    "unlock",
}

_BRAND_KEYWORDS = {
    "microsoft",
    "office",
    "outlook",
    "paypal",
    "apple",
    "google",
    "amazon",
    "adobe",
    "dropbox",
    "docusign",
    "facebook",
    "instagram",
    "netflix",
    "bank",
    "chase",
    "wellsfargo",
}

_SHORTENERS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rb.gy",
    "cutt.ly",
    "buff.ly",
}

_BUILT_IN_MODEL: dict[str, Any] = {
    "intercept": -3.65,
    "weights": {
        "url_length": 0.006,
        "hostname_length": 0.010,
        "path_length": 0.005,
        "query_length": 0.006,
        "dot_count": 0.16,
        "hyphen_count": 0.20,
        "digit_ratio": 1.25,
        "subdomain_depth": 0.28,
        "has_ip_host": 1.80,
        "has_at_symbol": 1.40,
        "has_punycode": 1.10,
        "has_sensitive_keyword": 0.85,
        "has_suspicious_tld": 0.90,
        "query_param_count": 0.08,
        "path_depth": 0.11,
        "entropy": 0.20,
        "is_shortener": 1.20,
        "uses_https": -0.18,
        "has_abnormal_port": 0.55,
        "brand_keyword_count": 0.22,
    },
}


@dataclass
class LexicalInferenceResult:
    score: float
    model_source: str
    top_features: list[str]
    feature_contributions: dict[str, float]
    raw_score: float | None = None
    calibration_applied: bool = False
    error: str | None = None


def extract_url_lexical_features(url: str) -> dict[str, float]:
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower().strip(".")
    path = parsed.path or ""
    query = parsed.query or ""
    full = url or ""
    host_parts = [p for p in host.split(".") if p]
    tld = host_parts[-1] if host_parts else ""
    subdomain_depth = max(0, len(host_parts) - 2)
    query_params = parse_qsl(query, keep_blank_values=True)
    alnum = [c for c in full if c.isalnum()]
    digits = [c for c in alnum if c.isdigit()]
    has_abnormal_port = 1.0 if parsed.port not in (None, 80, 443) else 0.0
    brand_keyword_count = _brand_keyword_count(host_parts, path, query)

    return {
        "url_length": float(len(full)),
        "hostname_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "dot_count": float(full.count(".")),
        "hyphen_count": float(full.count("-")),
        "digit_ratio": float(len(digits) / len(alnum)) if alnum else 0.0,
        "subdomain_depth": float(subdomain_depth),
        "has_ip_host": 1.0 if _is_ip_like_host(host) else 0.0,
        "has_at_symbol": 1.0 if "@" in full else 0.0,
        "has_punycode": 1.0 if "xn--" in host else 0.0,
        "has_sensitive_keyword": 1.0 if _contains_sensitive_keyword(full) else 0.0,
        "has_suspicious_tld": 1.0 if tld in _SUSPICIOUS_TLDS else 0.0,
        "query_param_count": float(len(query_params)),
        "path_depth": float(len([p for p in path.split("/") if p])),
        "entropy": _shannon_entropy(full),
        "is_shortener": 1.0 if host in _SHORTENERS else 0.0,
        "uses_https": 1.0 if (parsed.scheme or "").lower() == "https" else 0.0,
        "has_abnormal_port": has_abnormal_port,
        "brand_keyword_count": brand_keyword_count,
    }


def assess_url_lexical_risk(url: str, model_path_override: str | None = None) -> dict[str, Any]:
    features = extract_url_lexical_features(url)
    model_path = model_path_override or _configured_model_path()
    inference = _infer_score(features, model_path_override=model_path)
    raw_score = max(0.0, min(1.0, float(inference.raw_score if inference.raw_score is not None else inference.score)))
    score = max(0.0, min(1.0, float(inference.score)))
    calibration_meta = _load_calibration_metadata(model_path) if model_path else {}
    calibrated = _calibrate_score(score, calibration_meta)
    if calibrated is not None:
        score = calibrated
        inference.calibration_applied = True
    rule_floor = _rule_based_floor(features)
    rule_floor_applied = False
    if rule_floor is not None and rule_floor > score:
        score = rule_floor
        rule_floor_applied = True

    result: dict[str, Any] = {
        "enabled": True,
        "model_source": inference.model_source,
        "raw_score": round(raw_score, 4),
        "score": round(score, 4),
        "label": _score_to_label(score),
        "thresholds": {"low_max": LOW_THRESHOLD, "medium_max": HIGH_THRESHOLD},
        "features": features,
        "top_features": _ensure_top_features(inference.top_features, features, inference.model_source)[:5],
        "feature_contributions": inference.feature_contributions,
        "calibration_applied": bool(inference.calibration_applied),
        "rule_floor_applied": rule_floor_applied,
        "weights": {"lexical_weight": LEXICAL_WEIGHT},
    }
    if inference.error:
        result["error"] = inference.error
    return result


def _infer_score(features: dict[str, float], *, model_path_override: str | None = None) -> LexicalInferenceResult:
    if not _should_use_lightgbm():
        score, contribs = _score_built_in(features)
        return LexicalInferenceResult(
            score=score,
            model_source="built_in",
            top_features=_top_features_from_contribs(contribs, 5),
            feature_contributions=contribs,
            raw_score=score,
        )

    custom_path = model_path_override or _configured_model_path()
    if custom_path:
        lgbm, load_error = _load_lightgbm_model(custom_path)
        if lgbm is not None:
            score, contribs = _score_lightgbm(features, lgbm)
            return LexicalInferenceResult(
                score=score,
                model_source="lightgbm",
                top_features=_top_features_from_contribs(contribs, 5),
                feature_contributions=contribs,
                raw_score=score,
            )
        score, contribs = _score_built_in(features)
        return LexicalInferenceResult(
            score=score,
            model_source="built_in",
            top_features=_top_features_from_contribs(contribs, 5),
            feature_contributions=contribs,
            raw_score=score,
            error=load_error,
        )

    score, contribs = _score_built_in(features)
    return LexicalInferenceResult(
        score=score,
        model_source="built_in",
        top_features=_top_features_from_contribs(contribs, 5),
        feature_contributions=contribs,
        raw_score=score,
    )


def _configured_model_path() -> str | None:
    path = (get_settings().url_lexical_model_path or "").strip()
    return path or None


def _should_use_lightgbm() -> bool:
    try:
        return bool(get_settings().url_lexical_use_lightgbm)
    except Exception:
        return False


@lru_cache(maxsize=4)
def _load_lightgbm_model(path: str) -> tuple[Any | None, str | None]:
    if lgb is None:
        return None, "LightGBM not installed; falling back to built-in lexical model"
    p = Path(path)
    if not p.exists():
        return None, f"LightGBM model file not found: {path}"
    try:
        booster = lgb.Booster(model_file=str(p))
        return booster, None
    except Exception as exc:
        return None, f"Unable to load LightGBM model: {exc}"


def _score_lightgbm(features: dict[str, float], booster: Any) -> tuple[float, dict[str, float]]:
    row = _ordered_vector(features)
    feature_names = list(booster.feature_name() or [])
    if not feature_names:
        feature_names = FEATURE_ORDER[:]

    score_raw = booster.predict([row], num_iteration=booster.best_iteration)
    score = float(score_raw[0]) if score_raw else 0.0

    contribs: dict[str, float] = {}
    try:
        contrib_raw = booster.predict([row], pred_contrib=True, num_iteration=booster.best_iteration)
        if contrib_raw:
            vals = list(contrib_raw[0])
            if len(vals) >= len(feature_names):
                for idx, name in enumerate(feature_names):
                    if idx < len(vals):
                        contribs[name] = float(vals[idx])
    except Exception:
        contribs = {}

    if not contribs:
        contribs = _fallback_lightgbm_feature_contribs(features, booster, feature_names)

    return score, contribs


def _score_built_in(features: dict[str, float]) -> tuple[float, dict[str, float]]:
    intercept = float(_BUILT_IN_MODEL.get("intercept", 0.0))
    weights = _BUILT_IN_MODEL.get("weights") or {}
    linear = intercept
    contribs: dict[str, float] = {}
    for name, value in features.items():
        contrib = float(weights.get(name, 0.0)) * float(value)
        contribs[name] = contrib
        linear += contrib
    score = 1.0 / (1.0 + math.exp(-linear))
    return score, contribs


def _ordered_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]


def _top_features_from_contribs(contribs: dict[str, float], limit: int) -> list[str]:
    ranked = sorted(contribs.items(), key=lambda kv: abs(float(kv[1])), reverse=True)
    return [name for name, _ in ranked[:limit]]


def _ensure_top_features(top_features: list[str], features: dict[str, float], model_source: str) -> list[str]:
    if top_features:
        return top_features
    ranked = _fallback_feature_rank(features, model_source=model_source)
    return [name for name, _ in ranked]


def _fallback_feature_rank(features: dict[str, float], *, model_source: str) -> list[tuple[str, float]]:
    # Prioritize security-relevant lexical signals when explainability payload is missing.
    weights = {
        "has_ip_host": 8.0,
        "has_at_symbol": 7.0,
        "has_punycode": 6.0,
        "has_suspicious_tld": 5.5,
        "has_sensitive_keyword": 5.0,
        "is_shortener": 4.5,
        "brand_keyword_count": 3.5,
        "subdomain_depth": 2.5,
        "digit_ratio": 2.2,
        "entropy": 1.6,
        "hyphen_count": 1.2,
        "query_param_count": 1.0,
        "has_abnormal_port": 1.0,
        "uses_https": -0.8,
    }
    ranked = []
    for name in FEATURE_ORDER:
        value = float(features.get(name, 0.0))
        if value <= 0 and name != "uses_https":
            continue
        score = abs(value * float(weights.get(name, 0.2)))
        if score > 0:
            ranked.append((name, score))
    ranked.sort(key=lambda kv: kv[1], reverse=True)
    return ranked[:5]


def _fallback_lightgbm_feature_contribs(
    features: dict[str, float],
    booster: Any,
    feature_names: list[str],
) -> dict[str, float]:
    contribs: dict[str, float] = {}
    try:
        gains = list(booster.feature_importance(importance_type="gain") or [])
    except Exception:
        gains = []
    if gains and feature_names:
        for idx, name in enumerate(feature_names):
            if idx >= len(gains):
                break
            gain = float(gains[idx])
            value = float(features.get(name, 0.0))
            if gain == 0.0 and value == 0.0:
                continue
            contribs[name] = gain * value
    if not contribs:
        for name, score in _fallback_feature_rank(features, model_source="lightgbm"):
            contribs[name] = float(score)
    return contribs


def _score_to_label(score: float) -> str:
    if score < LOW_THRESHOLD:
        return "low"
    if score <= HIGH_THRESHOLD:
        return "medium"
    return "high"


@lru_cache(maxsize=4)
def _load_calibration_metadata(model_path: str) -> dict[str, Any]:
    path = (model_path or "").strip()
    if not path:
        return {}
    p = Path(path)
    candidates = [p.with_suffix(".metadata.json"), Path(str(p) + ".metadata.json")]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            calib = payload.get("calibration") or {}
            if isinstance(calib, dict):
                # Backward compatibility:
                # old format: {"method":"bin_interpolation","bins":{"method":"...","bins":[...],"enabled":...}}
                nested_bins = calib.get("bins")
                if isinstance(nested_bins, dict):
                    normalized = dict(nested_bins)
                    if "method" not in normalized and isinstance(calib.get("method"), str):
                        normalized["method"] = calib.get("method")
                    return normalized
                return calib
        except Exception:
            continue
    return {}


def _calibrate_score(score: float, calibration_meta: dict[str, Any]) -> float | None:
    if not isinstance(calibration_meta, dict):
        return None
    if calibration_meta.get("enabled") is False:
        return None
    bins = calibration_meta.get("bins")
    if not isinstance(bins, list) or len(bins) < 2:
        return None
    points: list[tuple[float, float]] = []
    for row in bins:
        if not isinstance(row, dict):
            continue
        x = row.get("pred_mean")
        y = row.get("actual_rate")
        try:
            px = float(x)
            py = float(y)
        except Exception:
            continue
        points.append((max(0.0, min(1.0, px)), max(0.0, min(1.0, py))))
    if len(points) < 2:
        return None
    points.sort(key=lambda t: t[0])
    x = max(0.0, min(1.0, float(score)))
    # Avoid edge extrapolation that can over-correct scores when calibration bins
    # cover only a narrow probability range from imbalanced validation data.
    if x <= points[0][0] or x >= points[-1][0]:
        return None
    for i in range(1, len(points)):
        x0, y0 = points[i - 1]
        x1, y1 = points[i]
        if x0 <= x <= x1 and x1 > x0:
            t = (x - x0) / (x1 - x0)
            return round(max(0.01, min(0.99, (1.0 - t) * y0 + t * y1)), 6)
    return None


def _is_ip_like_host(host: str) -> bool:
    if not host:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True
    if ":" in host:
        return True
    return False


def _contains_sensitive_keyword(text: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in _SENSITIVE_KEYWORDS)


def _brand_keyword_count(host_parts: list[str], path: str, query: str) -> float:
    if not host_parts:
        return 0.0
    # Legitimate brand root domains (e.g. microsoft.com) are common and should not
    # be treated as phishing just because the brand appears in the registrable label.
    registrable_label = host_parts[-2] if len(host_parts) >= 2 else host_parts[-1]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) >= 2 else ""
    search_area = f"{subdomain} {path or ''} {query or ''}".lower()

    count = 0
    for keyword in _BRAND_KEYWORDS:
        if keyword in search_area:
            count += 1
            continue
        if keyword in registrable_label and registrable_label != keyword:
            # Penalize lookalike combinations like "microsoft-secure-login".
            count += 1
    return float(count)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 6)


def _rule_based_floor(features: dict[str, float]) -> float | None:
    # Practical safeguards for high-confidence lexical phishing patterns.
    if float(features.get("has_ip_host", 0.0)) >= 1.0 or float(features.get("has_at_symbol", 0.0)) >= 1.0:
        return 0.90
    if float(features.get("has_punycode", 0.0)) >= 1.0 and float(features.get("has_sensitive_keyword", 0.0)) >= 1.0:
        return 0.85
    if float(features.get("has_suspicious_tld", 0.0)) >= 1.0 and float(features.get("has_sensitive_keyword", 0.0)) >= 1.0:
        return 0.72
    if (
        float(features.get("has_suspicious_tld", 0.0)) >= 1.0
        and float(features.get("digit_ratio", 0.0)) >= 0.2
        and float(features.get("entropy", 0.0)) >= 4.0
    ):
        return 0.65
    if float(features.get("subdomain_depth", 0.0)) >= 4.0 and float(features.get("query_param_count", 0.0)) >= 5.0:
        return 0.55
    return None


def write_builtin_model_json(path: str) -> None:
    Path(path).write_text(json.dumps(_BUILT_IN_MODEL, indent=2), encoding="utf-8")
