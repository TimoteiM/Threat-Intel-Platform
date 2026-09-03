"""The reading of the whole case, as distinct from the reading of each alert.

Every member of a correlated case already carries its own AI resolution. Eight
of them in a row is eight verdicts about eight fragments, and assembling the
intrusion out of them is exactly the work the correlation was meant to have
done. This writes the assembly down: what happened, in what order, what it
means, and what to do about it.

Two things govern when it runs. It is never called from a read — a case is
recomputed on every page load, and analysing on every recompute would spend the
token budget on the fact that someone opened a tab. And it is never called for
a case that has not changed: the fingerprint below is the same change signal
that decides whether a snapshot is appended, so an unchanged case keeps the
narrative it already has.

The evidence handed to the model is the correlation's own reasoning — the
order, the tactics, the tempo, the reasons the score was what it was — plus
each member's own conclusion. It is not the raw alert bodies again: the
per-alert analysis already read those, and re-deriving them here would produce
a ninth opinion rather than a synthesis of the eight.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# How much of each member's own resolution is carried into the case prompt. The
# per-alert report is complete on its own page; what the case needs is its
# conclusion, not its full working.
MEMBER_SUMMARY_CHARS = 900

# Guard against a case with a hundred members producing a prompt no model will
# read carefully. Members are ordered by event time, so this keeps the start and
# the end of the chain — where the entry and the objective are.
MAX_MEMBERS_IN_PROMPT = 24


def narrative_fingerprint(
    *, score: int, member_count: int, tactics: Iterable[str]
) -> str:
    """What the narrative was written from.

    Deliberately the same three fields that decide whether a snapshot is
    appended. If those have not moved, the case says the same thing it said
    last time and re-analysing it would produce a differently-worded copy at
    full token cost.
    """
    basis = json.dumps(
        {
            "score": int(score),
            "members": int(member_count),
            "tactics": sorted({str(t) for t in tactics if str(t or "").strip()}),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _member_line(member: dict[str, Any]) -> str:
    parts = [
        f"- {member.get('event_time') or 'unknown time'}",
        f"rule {member.get('detection_rule_id') or '?'}",
        str(member.get("detection_rule_name") or member.get("title") or "").strip(),
    ]
    verdict = str(member.get("overall_verdict") or "").strip()
    if verdict:
        parts.append(f"concluded {verdict}")
    risk = member.get("highest_risk_score")
    if risk:
        parts.append(f"risk {risk}/100")
    return " · ".join(part for part in parts if part)


def build_case_evidence(case: dict[str, Any], resolutions: dict[str, str]) -> str:
    """The text handed to the assistant, assembled from the case as computed.

    Written as readable prose and lists rather than raw JSON: the model reads
    this the way an analyst would, and the correlation's own reasoning — why
    these alerts are one thing — is the part it cannot re-derive from the
    members alone.
    """
    members = case.get("alerts") or []
    if len(members) > MAX_MEMBERS_IN_PROMPT:
        half = MAX_MEMBERS_IN_PROMPT // 2
        shown = members[:half] + members[-half:]
        elision = (
            f"\n  … {len(members) - MAX_MEMBERS_IN_PROMPT} further alerts between "
            f"these, same host, omitted for length …\n"
        )
    else:
        shown = members
        elision = ""

    progression = case.get("progression") or {}
    tempo = case.get("tempo") or {}

    lines: list[str] = [
        f"# Correlated case on {case.get('entity_host')}",
        "",
        f"Source platform: {case.get('source')}",
        f"Client: {case.get('client')}",
        f"Window: {case.get('first_seen')} to {case.get('last_seen')} (event time, not ingest time)",
        f"Members: {case.get('alert_count')} alerts, {case.get('distinct_rules')} distinct detection rules",
        f"Correlation score: {case.get('score')}/100",
        "",
        "## Why these alerts were grouped",
        "",
        "This platform grouped them because they share one entity, one sending",
        "platform and one client, and because more than one *independent*",
        "detection rule fired. The score below is not a severity — it measures",
        "how much independent agreement there is and how far the behaviour",
        "travelled across the kill chain.",
        "",
    ]
    for reason in case.get("reasons") or []:
        lines.append(f"- {reason}")

    lines += [
        "",
        "## Measured shape",
        "",
        f"- Tactics evidenced, in kill-chain order: {', '.join(case.get('tactics') or []) or 'none'}",
    ]
    if case.get("tactics_claimed_only"):
        lines.append(
            f"- Tactics the rules asserted but the evidence did not confirm: "
            f"{', '.join(case['tactics_claimed_only'])} — treat these as claims, not findings"
        )
    if progression.get("ratio") is not None:
        lines.append(
            f"- Progression: {progression.get('forward')} of {progression.get('transitions')} "
            f"stage transitions run forward along the kill chain "
            f"(ratio {progression.get('ratio')})"
        )
    if tempo.get("kind"):
        lines.append(
            f"- Tempo: {tempo.get('kind')}"
            + (
                f", median {tempo.get('median_gap_seconds')}s between alerts"
                if tempo.get("median_gap_seconds") is not None
                else ""
            )
        )
    if case.get("surprise") is not None:
        lines.append(
            f"- Familiarity multiplier: {case.get('surprise')} "
            "(1.0 means this combination of rules has not been seen together on "
            "this host before; lower means it is routine here)"
        )

    lines += ["", "## The alerts, in the order they happened", ""]
    for member in shown:
        lines.append(_member_line(member))
        resolution = (resolutions.get(str(member.get("run_id"))) or "").strip()
        if resolution:
            trimmed = resolution[:MEMBER_SUMMARY_CHARS]
            lines.append(f"    Its own analysis concluded: {trimmed}")
        if elision and member is shown[len(shown) // 2 - 1]:
            lines.append(elision)

    lines += [
        "",
        "## What to produce",
        "",
        "Explain this case as one event. The individual alerts have each been",
        "analysed already and the analyst can read those; what is missing is the",
        "single account of what happened across them. Say what the intrusion did",
        "in sequence, what it was trying to achieve, which assets and accounts",
        "are implicated, and what should be done now. If the evidence does not",
        "support calling it an intrusion, say that plainly and say what it looks",
        "like instead — a case scoring high on agreement and movement can still",
        "be routine administration, and reporting that clearly is more useful",
        "than a narrative built to justify the score.",
    ]
    return "\n".join(lines)
