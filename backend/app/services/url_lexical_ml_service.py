"""
Lightweight local URL lexical risk scoring.

This module is intentionally dependency-light:
- Extract lexical URL features
- Score with built-in logistic weights
- Optionally load custom weights from a local JSON file
- Fall back to built-in model if custom model is unavailable/invalid
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.config import get_settings

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
    "intercept": -3.6,
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
    },
}


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
    }


def assess_url_lexical_risk(url: str, model_path_override: str | None = None) -> dict[str, Any]:
    features = extract_url_lexical_features(url)
    model_source = "built_in"
    error: str | None = None
    model = _BUILT_IN_MODEL

    custom_path = model_path_override or _configured_model_path()
    if custom_path:
        loaded_model, load_error = _load_custom_model(custom_path)
        if loaded_model is not None:
            model = loaded_model
            model_source = "custom"
        elif load_error:
            error = load_error

    score = _score(features, model)
    label = "high" if score >= 0.75 else ("medium" if score >= 0.45 else "low")
    result: dict[str, Any] = {
        "enabled": True,
        "model_source": model_source,
        "score": round(score, 4),
        "label": label,
        "features": features,
    }
    if error:
        result["error"] = error
    return result


def _configured_model_path() -> str | None:
    path = (get_settings().url_lexical_model_path or "").strip()
    return path or None


@lru_cache(maxsize=4)
def _load_custom_model(path: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"Custom model unavailable: {exc}"

    if not isinstance(data, dict):
        return None, "Custom model unavailable: invalid JSON root type"
    if "weights" not in data or not isinstance(data["weights"], dict):
        return None, "Custom model unavailable: missing 'weights' object"

    weights: dict[str, float] = {}
    for key, value in data["weights"].items():
        try:
            weights[str(key)] = float(value)
        except Exception:
            return None, f"Custom model unavailable: non-numeric weight for '{key}'"

    intercept_raw = data.get("intercept", 0.0)
    try:
        intercept = float(intercept_raw)
    except Exception:
        return None, "Custom model unavailable: invalid intercept"

    return {"intercept": intercept, "weights": weights}, None


def _score(features: dict[str, float], model: dict[str, Any]) -> float:
    intercept = float(model.get("intercept", 0.0))
    weights = model.get("weights") or {}
    linear = intercept
    for name, value in features.items():
        linear += float(weights.get(name, 0.0)) * float(value)
    return 1.0 / (1.0 + math.exp(-linear))


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
