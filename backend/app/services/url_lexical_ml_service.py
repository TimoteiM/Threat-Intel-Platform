"""
URL lexical observations.

Deterministic facts about how a URL is written — a raw-IP host, an `@`, a
punycode hostname, a sensitive keyword, a disposable TLD, a shortener — each
one checkable by a person looking at the URL, plus the numeric features behind
them.

**There is no model and no probability verdict here any more.** Three things
were removed on 2026-10-19; `docs/measurements/url-lexical-three-arms.md` has
the measurements and docs/design/lexical-scoring-retirement.md the decisions.

1. **The LightGBM artefact is retired.** Its own metadata reported
   `accuracy@0.5` of 0.9692 against an always-benign baseline of 0.9698 — it
   scored worse than predicting "benign" for everything, which is effectively
   what it did, since 99% of its validation predictions fell below 0.31 and
   nothing reached the 0.5 decision point. On our corpus it could not produce
   a high verdict at all (0 of 1,535 above 0.65) and 633 URLs shared a single
   output value. The settings that pointed at it are gone, so it cannot be
   switched back on by someone who has read only the filename.

2. **The calibration curve is removed, not gated.** It was loaded by model
   path and applied to whatever produced the score, so with the model off a
   curve fitted to LightGBM's output distribution was being applied to the
   heuristic's. Measured effect: 217 scores moved, all 217 upward, promoting
   171 URLs from `low` to `medium` — among them `aka.ms` and GitHub's avatar
   CDN.

3. **The aggregate probability and its low/medium/high label are no longer
   reported.** The rule observations stayed, because that is where every
   genuine high verdict came from: all 376 of them in the model arm, and the
   named features are what the decision engine scores. A probability with a
   label reads as a measurement, and this one was not one.

`score` still exists in the payload because one consumer still blends it into
the risk score — see `analysis_task._inject_lexical_contribution`, which now
discloses that contribution in points rather than leaving it implicit. That
blend is the last place the number acts and is the open question in backlog 41.
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

# The features that assert something about a URL's *intent or identity*, as
# opposed to its size and structure. Only these are allowed to move a risk
# score; everything else in FEATURE_ORDER — length, depth, entropy, counts —
# grows with any long legitimate URL, which is how ordinary SharePoint and
# Office links came to score MEDIUM and drag investigations to "suspicious".
#
# Two features that look semantic are deliberately left out, because both fire
# on this estate's own legitimate traffic:
#
#   brand_keyword_count — the search area includes the subdomain, so
#     `outlook.office.com` counts "outlook"; and a registrable label is counted
#     as a lookalike whenever it *contains* a brand without equalling it, so
#     `office365` counts as a lookalike of `office`.
#   has_abnormal_port — any internal service not on 80/443 trips it, and there
#     are plenty here.
#
# Both remain in the model and still contribute to the reported score. They
# just cannot escalate a verdict on their own.
SEMANTIC_FEATURES = frozenset({
    "has_ip_host",
    "has_at_symbol",
    "has_punycode",
    "has_sensitive_keyword",
    "has_suspicious_tld",
    "is_shortener",
})


# How each semantic feature reads in an analyst-facing finding.
SEMANTIC_FEATURE_LABELS = {
    "has_ip_host": "hostname is a raw IP address",
    "has_at_symbol": "URL contains an @, which hides the real host",
    "has_punycode": "hostname uses punycode, which can imitate another name",
    "has_sensitive_keyword": "a sensitive keyword such as secure/login/account",
    "has_suspicious_tld": "a TLD commonly used for disposable domains",
    "is_shortener": "hostname is a URL shortener",
}


def semantic_features_present(lexical: Any) -> list[str]:
    """The semantic features this lexical assessment actually found, in FEATURE_ORDER.

    Reads the raw `features` vector first and only falls back to `top_features`,
    because `top_features` is capped at five: a URL long enough to fill that list
    with shape features would otherwise hide its own punycode hostname.
    """
    if not isinstance(lexical, dict) or not lexical:
        return []

    features = lexical.get("features")
    if isinstance(features, dict) and features:
        found = []
        for name in FEATURE_ORDER:
            if name not in SEMANTIC_FEATURES:
                continue
            try:
                if float(features.get(name, 0.0)) > 0:
                    found.append(name)
            except (TypeError, ValueError):
                continue
        return found

    top = {str(x).lower() for x in (lexical.get("top_features") or [])}
    return [name for name in FEATURE_ORDER if name in SEMANTIC_FEATURES and name in top]

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


#: Every individual fact about a URL string that this platform will report.
#:
#: One entry per *fact*, not per combination, and the reported set is a
#: superset of the set the decision engine scores — otherwise something could
#: move the risk score without appearing in the report, which is the defect
#: the probability had. Each statement is checkable by a person reading the
#: URL, which a probability is not.
RULE_OBSERVATIONS: tuple[tuple[str, str], ...] = (
    ("ip_host", "The hostname is a raw IP address rather than a domain name."),
    ("at_symbol", "The URL contains an @, which makes the visible start of the link misleading."),
    ("punycode", "The hostname uses punycode, which can imitate another name."),
    ("sensitive_keyword", "The URL contains a sensitive keyword such as secure, login or account."),
    ("disposable_tld", "The top-level domain is one commonly used for disposable domains."),
    ("shortener", "The hostname is a URL shortener, so the real destination is hidden until followed."),
    ("abnormal_port", "The URL names a non-standard web port."),
    ("brand_keyword", "The URL contains brand wording outside the legitimate root domain."),
    ("deep_subdomains_and_many_params",
     "The hostname is four or more levels deep and the URL carries five or more query parameters."),
    ("digit_heavy_and_high_entropy",
     "The URL is digit-heavy and high-entropy, so it reads as machine-generated."),
)

_OBSERVATION_TEXT = dict(RULE_OBSERVATIONS)

#: Which facts, in which combinations, used to put a URL at or above the old
#: `high` band through the rule floor. Kept as combinations because that is
#: the judgement the floor encoded and it is worth preserving: a raw-IP host
#: or an `@` was enough on its own (floor 0.90), punycode needed a keyword
#: beside it (0.85), a disposable TLD needed a keyword (0.72) or a
#: machine-generated look (0.65).
#:
#: Two gates used to ask `lexical.label == "high"` — `_url_is_risky` in the
#: email pipeline and the narrative's suspicious-URL list. With the band gone
#: they need a predicate, and these are it: specific facts a person can check,
#: rather than a number above a threshold. A single weak fact is deliberately
#: NOT enough — `sensitive_keyword` alone fires on an enormous amount of
#: legitimate mail, and `shortener` alone is how half of marketing email is
#: written.
ESCALATING_COMBINATIONS: tuple[tuple[str, ...], ...] = (
    ("ip_host",),
    ("at_symbol",),
    ("punycode", "sensitive_keyword"),
    ("disposable_tld", "sensitive_keyword"),
    ("disposable_tld", "digit_heavy_and_high_entropy"),
)


def url_lexical_observations(features: dict[str, float]) -> list[dict[str, str]]:
    """The named, checkable facts true of this URL.

    In a fixed order, so two reports on the same URL agree. No weights and no
    total: a count of observations is a score with the honesty removed.
    """
    f = lambda k: float(features.get(k, 0.0))
    found: list[str] = []

    if f("has_ip_host") >= 1.0:
        found.append("ip_host")
    if f("has_at_symbol") >= 1.0:
        found.append("at_symbol")
    if f("has_punycode") >= 1.0:
        found.append("punycode")
    if f("has_sensitive_keyword") >= 1.0:
        found.append("sensitive_keyword")
    if f("has_suspicious_tld") >= 1.0:
        found.append("disposable_tld")
    if f("is_shortener") >= 1.0:
        found.append("shortener")
    if f("has_abnormal_port") >= 1.0:
        found.append("abnormal_port")
    if f("brand_keyword_count") >= 1.0:
        found.append("brand_keyword")
    if f("subdomain_depth") >= 4.0 and f("query_param_count") >= 5.0:
        found.append("deep_subdomains_and_many_params")
    if f("digit_ratio") >= 0.2 and f("entropy") >= 4.0:
        found.append("digit_heavy_and_high_entropy")

    order = [c for c, _ in RULE_OBSERVATIONS]
    found.sort(key=order.index)
    return [{"code": c, "statement": _OBSERVATION_TEXT[c]} for c in found]


def observation_codes(lexical: Any) -> list[str]:
    """The observation codes in a payload, derived if the field is absent.

    Stored evidence written before `observations` existed carries `features`
    and no observations. Returning an empty list for those would present an
    absence as a fact — every historical record would read as "nothing was
    observed about this URL".
    """
    if not isinstance(lexical, dict):
        return []
    codes = [
        str(o.get("code") or "")
        for o in (lexical.get("observations") or [])
        if isinstance(o, dict) and o.get("code")
    ]
    if codes:
        return codes
    features = lexical.get("features")
    if isinstance(features, dict):
        return [o["code"] for o in url_lexical_observations(features)]
    return []


def strong_observations(lexical: Any) -> list[str]:
    """The codes taking part in a satisfied escalating combination.

    Returns the facts themselves rather than a verdict, so a caller that gates
    on this can also say which fact it gated on.
    """
    present = set(observation_codes(lexical))
    strong: list[str] = []
    for combination in ESCALATING_COMBINATIONS:
        if all(code in present for code in combination):
            strong.extend(combination)
    order = [c for c, _ in RULE_OBSERVATIONS]
    return sorted(set(strong), key=order.index)


def assess_url_lexical_risk(url: str, model_path_override: str | None = None) -> dict[str, Any]:
    """Lexical observations about a URL, and the features behind them.

    `model_path_override` is accepted and ignored. It is kept so that callers
    and tests written against the old signature do not raise; there is no
    model to point it at. See the module docstring.
    """
    features = extract_url_lexical_features(url)
    score, contribs = _score_built_in(features)
    score = max(0.0, min(1.0, float(score)))

    rule_floor = _rule_based_floor(features)
    rule_floor_applied = False
    if rule_floor is not None and rule_floor > score:
        score = rule_floor
        rule_floor_applied = True

    result: dict[str, Any] = {
        "enabled": True,
        # The only scorer there is. Kept rather than dropped because stored
        # evidence carries it and a reader comparing an old record to a new
        # one should see that the field still means the same thing.
        "model_source": "built_in",
        "observations": url_lexical_observations(features),
        "features": features,
        "top_features": _top_features_from_contribs(contribs, 5),
        "feature_contributions": contribs,
        "rule_floor_applied": rule_floor_applied,
        # NOT reported as a verdict. No `label`, no `thresholds`: a
        # probability beside a low/medium/high band reads as a measurement,
        # and against the only external labels available this one scored below
        # a coin flip. It remains in the payload for exactly one consumer —
        # the risk-score blend in `analysis_task._inject_lexical_contribution`,
        # which discloses the points it adds — and that blend is the open
        # question in backlog 41.
        "score": round(score, 4),
        "weights": {"lexical_weight": LEXICAL_WEIGHT},
    }
    return result












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




def _top_features_from_contribs(contribs: dict[str, float], limit: int) -> list[str]:
    ranked = sorted(contribs.items(), key=lambda kv: abs(float(kv[1])), reverse=True)
    return [name for name, _ in ranked[:limit]]














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
