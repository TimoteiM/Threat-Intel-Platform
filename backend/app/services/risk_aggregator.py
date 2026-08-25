"""
Composite risk aggregation engine.
"""

from __future__ import annotations

from typing import Any

from app.services.opencti_hygiene import is_hygiene_match


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
        rationale.append("AnyRun indicates suspicious/malicious behavior")
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
            scope = e.get("scope_validation") or (e.get("raw_summary") or {}).get("scope_validation") or {}
            if isinstance(scope, dict) and scope.get("scope_match") is False:
                continue
            verdict = str(e.get("verdict") or "unknown").lower()
            verdict_context = e.get("verdict_context") or {}
            if (
                verdict == "clean"
                and isinstance(verdict_context, dict)
                and verdict_context.get("msdw_false_positive_exclusion_applied") is True
                and verdict_context.get("excluded_from_final_risk") is True
            ):
                # The provider verdict was caused solely by a qualified benign
                # MSDW diagnostic signature. It must contribute zero, not the
                # normal small baseline assigned to a clean sandbox result.
                continue
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

    otx = tf.get("otx") or {}
    if otx.get("found"):
        pulse_count = int(otx.get("pulse_count") or 0)
        score += min(0.25, 0.08 + pulse_count * 0.02)

    age_days = whois.get("domain_age_days")
    if isinstance(age_days, int) and age_days <= 30:
        score += 0.15

    return max(0.0, min(1.0, score))


def _opencti_score(evidence: dict[str, Any]) -> float:
    best = 0.0
    for item in _opencti_items(evidence):
        # A hygiene label means OpenCTI matched this against a known-good
        # warning list. Scoring it anyway is how a public DNS resolver reached
        # a malicious verdict — see opencti_hygiene.
        if is_hygiene_match(item):
            continue
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
        if _is_opencti_contextual_account_compromise(item):
            continue
        # Warning-list infrastructure must not get a risk floor. This one bites
        # hardest: a floor of 70 forces suspicious regardless of what every
        # other collector found.
        if is_hygiene_match(item):
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

    component = max(0.0, min(1.0, score * 0.7 + found_bonus + bonus))
    if _is_opencti_contextual_account_compromise(opencti):
        return min(component, 0.35)
    return component


def _is_opencti_contextual_account_compromise(opencti: dict[str, Any]) -> bool:
    """
    Internal CTI about a compromised user/mailbox is useful triage context, but it
    does not prove the investigated domain itself is attacker-controlled.
    """
    text_parts: list[str] = []
    for key in ("labels", "notes"):
        value = opencti.get(key)
        if isinstance(value, list):
            text_parts.extend(str(item) for item in value)
        elif value:
            text_parts.append(str(value))
    for key in ("reports", "indicators"):
        value = opencti.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            text_parts.extend(
                str(item.get(field) or "")
                for field in ("name", "description", "pattern")
            )

    text = " ".join(text_parts).lower()
    entity_type = str(opencti.get("observable_entity_type") or "").strip().lower()
    observable_value = str(opencti.get("observable_value") or "").strip().lower()
    if not text:
        return entity_type == "user-account" or "@" in observable_value

    account_terms = (
        "compromised account",
        "account compromise",
        "compromised user",
        "user compromise",
        "compromised mailbox",
        "mailbox compromise",
        "bec",
        "business email compromise",
        "credential leak",
        "leaked credential",
    )
    domain_threat_terms = (
        "phishing",
        "malware",
        "c2",
        "command and control",
        "botnet",
        "ransomware",
        "smishing",
        "credential harvesting",
    )
    has_account_context = (
        entity_type == "user-account"
        or "@" in observable_value
        or any(term in text for term in account_terms)
    )
    return has_account_context and not any(term in text for term in domain_threat_terms)
