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
    get_technique_info,
    normalize_technique_id,
    parent_technique,
    techniques_for_signal,
)

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
    detection_techniques: Sequence[str] | None = None,
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

    if not claimed and not evidenced:
        return None

    assessed_claims = [_assess_one(technique, evidenced) for technique in claimed]
    claimed_keys = {normalize_technique_id(t) for t in claimed}
    claimed_parents = {parent_technique(t) for t in claimed}

    additional = [
        _describe(technique, entry, status="additional")
        for technique, entry in sorted(evidenced.items())
        if technique not in claimed_keys and technique not in claimed_parents
    ]

    return {
        "detection_claimed": claimed,
        "techniques": assessed_claims,
        "additional_techniques": additional,
        "evidence_available": bool(evidenced),
        "confirmed_count": sum(1 for item in assessed_claims if item["status"] == "confirmed"),
        "sources": ["endpoint_behaviour"] if evidenced else [],
        "method": "deterministic_behaviour_signals",
        "note": _summary_note(assessed_claims, additional, bool(evidenced)),
    }


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
