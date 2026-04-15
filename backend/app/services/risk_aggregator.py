"""
Composite risk aggregation engine.
"""

from __future__ import annotations

from typing import Any


DEFAULT_WEIGHTS = {
    "lexical_score": 0.20,
    "behavior_score": 0.16,
    "content_ml_score": 0.12,
    "attachment_score": 0.12,
    "sandbox_score": 0.10,
    "infrastructure_score": 0.15,
    "opencti_score": 0.15,
}


def aggregate_risk(evidence: dict[str, Any], *, weights: dict[str, float] | None = None) -> dict[str, Any]:
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)

    lexical = float((((evidence.get("url_lexical_ml") or {}).get("score")) or 0.0))
    behavior = float((((evidence.get("url_behavior") or {}).get("behavior_score")) or 0.0))
    content = _content_score(evidence.get("content_ml") or {})
    attachment = _attachment_score(evidence.get("attachment_analysis") or {})
    sandbox = _sandbox_score(evidence.get("hybrid_analysis") or {})
    infra = _infrastructure_score(evidence)
    opencti = _opencti_score(evidence)

    final = (
        lexical * w["lexical_score"]
        + behavior * w["behavior_score"]
        + content * w["content_ml_score"]
        + attachment * w["attachment_score"]
        + sandbox * w["sandbox_score"]
        + infra * w["infrastructure_score"]
        + opencti * w["opencti_score"]
    )
    risk_score = int(round(max(0.0, min(1.0, final)) * 100))
    opencti_floor = _opencti_risk_floor(evidence)
    risk_score = max(risk_score, opencti_floor)
    level = "high" if risk_score >= 70 else ("medium" if risk_score >= 35 else "low")

    rationale: list[str] = []
    if lexical >= 0.65:
        rationale.append("URL lexical model high score")
    if behavior >= 0.55:
        rationale.append("URL behavior indicates redirect/cloaking/credential risk")
    if content >= 0.55:
        rationale.append("Email header-content model indicates social engineering")
    if attachment >= 0.55:
        rationale.append("Attachment static analysis indicates elevated risk")
    if sandbox >= 0.55:
        rationale.append("Hybrid Analysis indicates suspicious/malicious behavior")
    if infra >= 0.55:
        rationale.append("Infrastructure/reputation collectors indicate elevated risk")
    if opencti >= 0.55:
        rationale.append("OpenCTI indicates known malicious or previously tracked infrastructure")
    if opencti_floor >= 70:
        rationale.append("Risk floor raised to high by trusted OpenCTI intelligence")
    elif opencti_floor >= 35:
        rationale.append("Risk floor raised to medium by trusted OpenCTI intelligence")
    if not rationale:
        rationale.append("No strong malicious signal; monitor and corroborate with external context")

    confidence = "high" if len(rationale) >= 3 else ("medium" if len(rationale) == 2 else "low")
    return {
        "risk_score": risk_score,
        "risk_level": level,
        "confidence": confidence,
        "components": {
            "lexical_score": round(lexical, 4),
            "behavior_score": round(behavior, 4),
            "content_ml_score": round(content, 4),
            "attachment_score": round(attachment, 4),
            "sandbox_score": round(sandbox, 4),
            "infrastructure_score": round(infra, 4),
            "opencti_score": round(opencti, 4),
        },
        "weights": w,
        "rationale": rationale,
    }


def _content_score(content_ml: dict[str, Any]) -> float:
    vals = [
        float(content_ml.get("social_engineering_probability") or 0.0),
        float(content_ml.get("urgency_probability") or 0.0),
        float(content_ml.get("impersonation_probability") or 0.0),
        float(content_ml.get("bec_probability") or 0.0),
    ]
    if not vals:
        return 0.0
    return max(0.0, min(1.0, sum(vals) / len(vals)))


def _attachment_score(attachment_analysis: dict[str, Any]) -> float:
    items = attachment_analysis.get("items") or []
    if not isinstance(items, list) or not items:
        return 0.0
    return max(0.0, min(1.0, max(float(i.get("static_risk_score") or 0.0) for i in items if isinstance(i, dict))))


def _sandbox_score(hybrid: dict[str, Any]) -> float:
    if not isinstance(hybrid, dict):
        return 0.0
    entries = hybrid.get("items")
    if isinstance(entries, list) and entries:
        best = 0.0
        for e in entries:
            if not isinstance(e, dict):
                continue
            verdict = str(e.get("verdict") or "unknown").lower()
            if verdict == "malicious":
                best = max(best, 0.9)
            elif verdict == "suspicious":
                best = max(best, 0.6)
            elif verdict == "clean":
                best = max(best, 0.1)
        return best
    verdict = str(hybrid.get("verdict") or "unknown").lower()
    if verdict == "malicious":
        return 0.9
    if verdict == "suspicious":
        return 0.6
    if verdict == "clean":
        return 0.1
    return 0.0


def _infrastructure_score(evidence: dict[str, Any]) -> float:
    vt = evidence.get("vt") or {}
    tf = evidence.get("threat_feeds") or {}
    whois = evidence.get("whois") or {}

    score = 0.0
    malicious = int(vt.get("malicious_count") or 0)
    suspicious = int(vt.get("suspicious_count") or 0)
    if malicious > 0:
        score += min(0.5, malicious * 0.08)
    elif suspicious > 0:
        score += min(0.25, suspicious * 0.03)

    abuse = (tf.get("abuseipdb") or {})
    abuse_score = float(abuse.get("abuse_confidence_score") or 0.0)
    score += min(0.2, abuse_score / 100.0 * 0.2)

    age_days = whois.get("domain_age_days")
    if isinstance(age_days, int) and age_days <= 30:
        score += 0.15

    return max(0.0, min(1.0, score))


def _opencti_score(evidence: dict[str, Any]) -> float:
    best = 0.0
    for item in _opencti_items(evidence):
        best = max(best, _single_opencti_score(item))
    return best


def _opencti_richness(opencti: dict[str, Any]) -> int:
    buckets = [
        opencti.get("reports") or [],
        opencti.get("threat_actors") or [],
        opencti.get("malware_families") or [],
        opencti.get("attack_patterns") or [],
        opencti.get("campaigns") or [],
        opencti.get("intrusion_sets") or [],
    ]
    return sum(1 for bucket in buckets if isinstance(bucket, list) and len(bucket) > 0)


def _opencti_risk_floor(evidence: dict[str, Any]) -> int:
    best = 0
    for item in _opencti_items(evidence):
        if not item.get("found"):
            continue
        score = int(item.get("score") or 0)
        richness = _opencti_richness(item)
        component = _single_opencti_score(item)
        if score >= 85 or component >= 0.85 or (score >= 75 and richness >= 2):
            best = max(best, 70)
        elif score >= 50 and richness >= 1:
            best = max(best, 35)
    return best


def _opencti_items(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in ("opencti", "opencti_observables"):
        raw = evidence.get(key)
        if isinstance(raw, dict):
            items.append(raw)
        elif isinstance(raw, list):
            items.extend(item for item in raw if isinstance(item, dict))
    return items


def _single_opencti_score(opencti: dict[str, Any]) -> float:
    if not isinstance(opencti, dict) or not opencti.get("found"):
        return 0.0

    score = max(0.0, min(1.0, float(opencti.get("score") or 0.0) / 100.0))
    richness = _opencti_richness(opencti)
    bonus = min(0.25, richness * 0.05)
    found_bonus = 0.1

    return max(0.0, min(1.0, score * 0.7 + found_bonus + bonus))
