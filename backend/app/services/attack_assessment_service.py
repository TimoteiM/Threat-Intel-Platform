"""
Check a detection's ATT&CK mapping against what the investigation actually found.

A SIEM rule carries its technique mapping from the moment it is written: it is
the rule author's hypothesis about what a matching event would mean, decided
before this particular alert existed and before anything was investigated. That
mapping is useful, and it is also a claim.

Once the platform has collected evidence it can say something the rule could
not, and this module says exactly that much and no more:

    confirmed         the evidence gathered here independently supports the
                      technique the rule claimed
    not_corroborated  nothing found either way. NOT a contradiction — a domain
                      alert simply carries no evidence about a registry
                      persistence technique, and saying so is the honest answer
    refuted           evidence actively contradicts the claim. Deliberately rare
    additional        a technique the evidence supports that the rule did not
                      claim

The verdicts come from deterministic behaviour signals: the endpoint event
parser has already matched a literal command line, so "this command is
T1490 Inhibit System Recovery" is a statement about what the command *is*, not
an opinion. Every technique reported therefore carries the signal that supports
it and the matched text, and a technique with no such support is never emitted.

Nothing here consults a model. A technique nobody can evidence is a technique
nobody can invent.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable, Sequence

from app.analyst.attack_mapping import (
    AMBIGUOUS_SIGNAL_GROUPS,
    COLLECTOR_ATTACK_RULES,
    get_technique_info,
    normalize_technique_id,
    parent_technique,
    techniques_for_signal,
)

# Same threshold the decision engine uses for "newly registered".
NEWLY_REGISTERED_DAYS = 30

logger = logging.getLogger(__name__)

# A technique id anywhere in the alert text. Only accepted on a line that also
# mentions MITRE/ATT&CK — see _is_attack_context — so a ticket number or a rule
# name that happens to look like one is not mistaken for a mapping.
_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_ATTACK_CONTEXT = re.compile(r"mitre|att&ck|attack\.mitre|technique|tactic", re.IGNORECASE)

# Field names a SIEM uses for its mapping, for the flattened-document path.
DETECTION_FIELDS = (
    "rule.mitre.id",
    "rule.mitre.technique",
    "rule.mitre.tactic",
    "mitre.id",
    "mitre_technique",
    "Mitre Sub_technique ID",
    "Mitre Technique ID",
)

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def extract_detection_techniques(alert_body: str) -> list[str]:
    """
    Technique ids the *detection* claimed, read out of the alert.

    Works on the alert text rather than the source document because that is what
    survives to the worker, and because a pasted alert or a `text/plain` delivery
    has no document at all. The MITRE-context requirement is what keeps this from
    collecting every T-number in a Windows message.
    """
    found: list[str] = []
    for line in str(alert_body or "").splitlines():
        if not _is_attack_context(line):
            continue
        for match in _TECHNIQUE_PATTERN.finditer(line):
            technique = normalize_technique_id(match.group(0))
            if technique and technique not in found:
                found.append(technique)
    return found


def _is_attack_context(line: str) -> bool:
    return bool(_ATTACK_CONTEXT.search(line))


def assess_attack(
    alert_body: str,
    event_reports: Sequence[dict[str, Any]],
    *,
    indicator_reports: Sequence[dict[str, Any]] = (),
    detection_techniques: Sequence[str] | None = None,
    ai_proposals: Sequence[dict[str, Any]] = (),
) -> dict[str, Any] | None:
    """
    Compare the detection's mapping with the techniques the evidence supports.

    Returns None when there is nothing to say — no claimed mapping and no
    supporting evidence — so the report carries no ATT&CK section at all rather
    than an empty one implying an assessment was made.
    """
    claimed = list(detection_techniques if detection_techniques is not None
                   else extract_detection_techniques(alert_body))
    evidenced = _evidenced_techniques(event_reports)
    _merge(evidenced, _collector_techniques(indicator_reports))

    if not claimed and not evidenced and not ai_proposals:
        return None

    assessed_claims = [_assess_one(technique, evidenced) for technique in claimed]
    claimed_keys = {normalize_technique_id(t) for t in claimed}
    claimed_parents = {parent_technique(t) for t in claimed}

    additional = [
        _describe(technique, entry, status="additional")
        for technique, entry in sorted(evidenced.items())
        if technique not in claimed_keys and technique not in claimed_parents
    ]

    # AI proposals are already validated (whitelisted id, quote located in the
    # evidence) and never displace a deterministic result — they are appended,
    # marked, and kept out of confirmed_count.
    evidenced_ids = set(evidenced)
    additional.extend(
        proposal
        for proposal in ai_proposals
        if proposal.get("id") not in evidenced_ids
        and proposal.get("id") not in claimed_keys
    )

    return {
        "detection_claimed": claimed,
        "techniques": assessed_claims,
        "additional_techniques": additional,
        "evidence_available": bool(evidenced),
        "confirmed_count": sum(1 for item in assessed_claims if item["status"] == "confirmed"),
        "sources": _sources(evidenced, ai_proposals),
        "method": "deterministic_signals" + ("_plus_ai" if ai_proposals else ""),
        "note": _summary_note(assessed_claims, additional, bool(evidenced)),
    }


def _sources(evidenced: dict[str, Any], ai_proposals: Sequence[dict[str, Any]]) -> list[str]:
    sources: list[str] = []
    for entry in evidenced.values():
        for signal_id in entry.get("signal_ids") or []:
            source = "collector_findings" if any(
                signal_id == rule[0] for rule in COLLECTOR_ATTACK_RULES
            ) else "endpoint_behaviour"
            if source not in sources:
                sources.append(source)
    if ai_proposals:
        sources.append("ai_suggested")
    return sources


# ── Internals ─────────────────────────────────────────────────────────────────


def _evidenced_techniques(event_reports: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Techniques the endpoint behaviour signals support, keyed by technique id.

    Each carries every signal that supports it, with the text that matched — the
    citation that makes the claim checkable.
    """
    evidenced: dict[str, dict[str, Any]] = {}

    for report in event_reports or []:
        if not isinstance(report, dict):
            continue
        event = report.get("event") or {}
        for finding in report.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            data = finding.get("data") or {}
            signal_id = str(data.get("signal_id") or "")
            if not signal_id:
                continue
            for technique, confidence in techniques_for_signal(signal_id):
                entry = evidenced.setdefault(
                    technique,
                    {"confidence": confidence, "evidence": [], "signal_ids": []},
                )
                if CONFIDENCE_RANK.get(confidence, 0) > CONFIDENCE_RANK.get(entry["confidence"], 0):
                    entry["confidence"] = confidence
                if signal_id not in entry["signal_ids"]:
                    entry["signal_ids"].append(signal_id)
                entry["evidence"].append(
                    {
                        "signal_id": signal_id,
                        "signal": finding.get("summary"),
                        "severity": finding.get("severity"),
                        "matched": data.get("matched") or data.get("image") or data.get("location"),
                        "command_line": (event.get("command_line") or "")[:300] or None,
                        "process": event.get("image"),
                    }
                )
    return evidenced


def _collector_techniques(
    indicator_reports: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Techniques supported by what the collectors found about an indicator.

    Endpoint signals say what a command *is*; these say what a domain or URL
    turned out to *be*. The conditions are strict on purpose — a reachable page
    supports nothing, a malicious page serving a login form supports credential
    capture — and every rule that fires cites the finding it read.
    """
    evidenced: dict[str, dict[str, Any]] = {}

    for report in indicator_reports or []:
        if not isinstance(report, dict):
            continue
        verdict = report.get("verdict") or {}
        classification = str(verdict.get("classification") or "")
        is_malicious = classification == "malicious"
        indicator = (report.get("indicator") or {}).get("value")

        by_collector: dict[str, list[dict[str, Any]]] = {}
        for finding in report.get("findings") or []:
            if isinstance(finding, dict):
                by_collector.setdefault(str(finding.get("collector") or ""), []).append(finding)

        for rule_id, collector, technique, confidence, requires_malicious in COLLECTOR_ATTACK_RULES:
            if requires_malicious and not is_malicious:
                continue
            for finding in by_collector.get(collector, []):
                if not _collector_rule_matches(rule_id, finding):
                    continue
                entry = evidenced.setdefault(
                    technique, {"confidence": confidence, "evidence": [], "signal_ids": []}
                )
                if CONFIDENCE_RANK.get(confidence, 0) > CONFIDENCE_RANK.get(entry["confidence"], 0):
                    entry["confidence"] = confidence
                if rule_id not in entry["signal_ids"]:
                    entry["signal_ids"].append(rule_id)
                entry["evidence"].append(
                    {
                        "signal_id": rule_id,
                        "signal": finding.get("summary"),
                        "severity": finding.get("severity"),
                        "matched": _collector_citation(rule_id, finding),
                        "indicator": indicator,
                        "collector": collector,
                    }
                )
                break  # one citation per rule per indicator is enough
    return evidenced


def _collector_rule_matches(rule_id: str, finding: dict[str, Any]) -> bool:
    """Whether this finding actually satisfies the rule's condition."""
    data = finding.get("data") or {}
    if rule_id == "credential_page":
        return bool(data.get("has_login_form"))
    if rule_id == "brand_impersonation":
        return bool(data.get("brand_indicators"))
    if rule_id == "newly_registered":
        age = data.get("domain_age_days")
        return isinstance(age, int) and 0 <= age <= NEWLY_REGISTERED_DAYS
    if rule_id == "phish_feed_hit":
        blob = f"{finding.get('summary')} {data}".lower()
        return "phish" in blob
    if rule_id == "sandbox_c2":
        return bool(data.get("urls") or data.get("connections") or data.get("network"))
    return False


def _collector_citation(rule_id: str, finding: dict[str, Any]) -> str | None:
    """The specific value that made the rule fire, for the report to quote."""
    data = finding.get("data") or {}
    if rule_id == "credential_page":
        return f"login form on {data.get('final_url') or 'the live page'}"
    if rule_id == "brand_impersonation":
        brands = data.get("brand_indicators")
        return f"brand indicators: {', '.join(map(str, brands[:3]))}" if isinstance(brands, list) else str(brands)
    if rule_id == "newly_registered":
        return f"registered {data.get('domain_age_days')} day(s) ago"
    if rule_id in ("phish_feed_hit", "sandbox_c2"):
        return str(finding.get("summary") or "")[:120]
    return None


def _merge(target: dict[str, dict[str, Any]], extra: dict[str, dict[str, Any]]) -> None:
    """Fold one evidence map into another, keeping the strongest confidence."""
    for technique, entry in extra.items():
        existing = target.get(technique)
        if existing is None:
            target[technique] = entry
            continue
        if CONFIDENCE_RANK.get(entry["confidence"], 0) > CONFIDENCE_RANK.get(existing["confidence"], 0):
            existing["confidence"] = entry["confidence"]
        existing["evidence"].extend(entry["evidence"])
        for signal_id in entry["signal_ids"]:
            if signal_id not in existing["signal_ids"]:
                existing["signal_ids"].append(signal_id)


def _assess_one(technique: str, evidenced: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """One claimed technique, judged against the evidence."""
    normalized = normalize_technique_id(technique)

    direct = evidenced.get(normalized)
    if direct:
        return _describe(normalized, direct, status="confirmed")

    # A rule claiming T1059 is corroborated by evidence for T1059.001, and a rule
    # claiming the sub-technique is corroborated by evidence for its parent — the
    # behaviour is the same behaviour, observed at a different resolution.
    related = _related_evidence(normalized, evidenced)
    if related is not None:
        technique_id, entry = related
        described = _describe(normalized, entry, status="confirmed")
        described["confirmed_via"] = technique_id
        return described

    return {
        "id": normalized,
        **_technique_fields(normalized),
        "status": "not_corroborated",
        "confidence": None,
        "evidence": [],
        "explanation": (
            "The investigation found no evidence bearing on this technique. That is not "
            "a contradiction of the detection — this alert simply carried nothing that "
            "would show it either way."
        ),
    }


def _related_evidence(
    technique: str,
    evidenced: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    """Evidence for a parent, a sub-technique, or a same-behaviour sibling."""
    parent = parent_technique(technique)

    for candidate, entry in evidenced.items():
        if candidate == parent or parent_technique(candidate) == parent:
            return candidate, entry

    # A persistence signal cannot tell a Run key from a scheduled task. When the
    # rule names one of the group the signal covers, the evidence corroborates
    # that one rather than arbitrarily picking a sibling.
    for group in AMBIGUOUS_SIGNAL_GROUPS:
        if technique not in group:
            continue
        for candidate, entry in evidenced.items():
            if candidate in group:
                return candidate, entry
    return None


def _describe(technique: str, entry: dict[str, Any], *, status: str) -> dict[str, Any]:
    evidence = entry.get("evidence") or []
    return {
        "id": technique,
        **_technique_fields(technique),
        "status": status,
        "confidence": entry.get("confidence"),
        "evidence": evidence[:5],
        "explanation": _explain(status, evidence),
    }


def _technique_fields(technique: str) -> dict[str, Any]:
    info = get_technique_info(technique) or {}
    return {
        "name": info.get("name"),
        "tactic": info.get("tactic"),
        "url": info.get("url"),
        # A technique the detection claimed that we hold no definition for is
        # reported as-is rather than dropped: the rule said it, and hiding that
        # would misrepresent the detection.
        "known": bool(info),
    }


def _explain(status: str, evidence: Sequence[dict[str, Any]]) -> str:
    if not evidence:
        return "No supporting evidence."
    first = evidence[0]
    matched = str(first.get("matched") or "").strip()
    signal = first.get("signal") or "an endpoint behaviour signal"
    citation = f' — matched "{matched}"' if matched else ""
    if status == "additional":
        return (
            f"Observed in this alert but not claimed by the detection: {signal}{citation}."
        )
    return f"Corroborated by what was observed: {signal}{citation}."


def _summary_note(
    claims: Sequence[dict[str, Any]],
    additional: Sequence[dict[str, Any]],
    had_evidence: bool,
) -> str:
    """One sentence an analyst can read without opening the structure."""
    if not had_evidence:
        return (
            "No endpoint behaviour was available in this alert, so the detection's ATT&CK "
            "mapping could not be checked either way."
        )
    confirmed = [item["id"] for item in claims if item["status"] == "confirmed"]
    open_claims = [item["id"] for item in claims if item["status"] == "not_corroborated"]

    parts: list[str] = []
    if confirmed:
        parts.append(f"confirmed {', '.join(confirmed)}")
    if open_claims:
        parts.append(f"found nothing bearing on {', '.join(open_claims)}")
    if additional:
        parts.append(f"observed {', '.join(item['id'] for item in additional)} which the rule did not claim")
    if not parts:
        return "The evidence supports no ATT&CK technique on its own."
    return f"Against the detection's mapping, the analysis {'; '.join(parts)}."
