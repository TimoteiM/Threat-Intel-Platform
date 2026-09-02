"""
Alerts that are one event, seen from several angles.

A single alert is judged on what it carries. That is the right unit for a
verdict and the wrong unit for an attack: Kerberoasting on a domain controller
is suspicious, an account being changed is routine, and the two together on the
same machine within an hour is an intrusion. This deployment has exactly that
pair on ExpDC001 on two consecutive days, and nothing ever showed them together.

A case is (entity, window, the alerts inside it). What makes one worth raising
is not how many alerts it holds — forty repeats of one noisy rule is still one
noisy rule — but how many *independent* detections agree and how far the
behaviour travels across the kill chain. Those are the two things a single
alert can never tell you, so they are what the score is built from.

Suppressed alerts count. An alert an analyst muted as routine is exactly the one
that turns out to be step one, and the suppression only ever removed its
collector spend, never its record.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun

logger = logging.getLogger(__name__)

# Roughly the order an intrusion moves through. Used only to ask whether a case
# *advances* — a chain that reaches Impact from Discovery is a different animal
# from three alerts sitting in one stage — so precise ATT&CK ordering matters
# less than the direction of travel.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_RANK = {name.casefold(): index for index, name in enumerate(TACTIC_ORDER)}

DEFAULT_WINDOW_HOURS = 48
# One rule firing repeatedly is one detection, however loud. A case needs two
# independent rules to agree before it is worth anyone's attention.
MIN_DISTINCT_RULES = 2


def _tactics_of(assessment: Any) -> tuple[set[str], set[str]]:
    """
    (evidenced, claimed) tactics — kept apart, because they are not equally true.

    A rule's ATT&CK mapping is its author's hypothesis. In this deployment every
    single claim is not_corroborated, and the mismatch view shows rules claiming
    Valid Accounts on alerts whose evidence is PowerShell and obfuscation. Wiring
    those claims into a case score would let a mismapped rule manufacture kill
    chain breadth out of nothing — the exact failure this platform keeps hitting
    when someone else's assertion is read as a finding.

    A technique the investigation established is a different kind of fact, so it
    is the one the score leans on.
    """
    if not isinstance(assessment, dict):
        return set(), set()

    def names(entry: Any) -> set[str]:
        if not isinstance(entry, dict):
            return set()
        raw = entry.get("tactics") or ([entry["tactic"]] if entry.get("tactic") else [])
        return {str(t).strip() for t in raw if str(t or "").strip().lower() not in ("", "unmapped")}

    evidenced: set[str] = set()
    claimed: set[str] = set()
    for entry in assessment.get("techniques") or []:
        # Only a confirmed claim counts as evidence of itself.
        (evidenced if (entry or {}).get("status") == "confirmed" else claimed).update(names(entry))
    for entry in assessment.get("additional_techniques") or []:
        evidenced.update(names(entry))
    return evidenced, claimed


def score_case(
    *,
    distinct_rules: int,
    tactics: set[str],
    max_risk: int,
    verdicts: list[str],
    claimed_only: set[str] | None = None,
) -> tuple[int, list[str]]:
    """
    How much this case deserves attention, and why in words.

    Deliberately not a function of alert count. Volume is what a noisy rule
    produces; agreement between independent detections, and movement across the
    kill chain, are what an attack produces.
    """
    reasons: list[str] = []
    score = 0

    # Rule agreement carries the most weight, because it is the one signal here
    # that does not depend on ATT&CK data being right. This deployment cannot
    # evidence a Kerberos attack at all — its collectors answer questions about
    # domains, addresses and files — so a domain controller showing Kerberoasting
    # and an account change has two independent detections and no evidenced
    # tactics whatsoever. Scoring only what can be evidenced would rank the most
    # interesting case on the estate last.
    if distinct_rules >= 2:
        score += 30 * min(distinct_rules - 1, 3)
        reasons.append(f"{distinct_rules} independent detections agree on this entity")

    ranks = sorted({_TACTIC_RANK[t.casefold()] for t in tactics if t.casefold() in _TACTIC_RANK})
    if len(ranks) >= 2:
        score += 15 * min(len(ranks) - 1, 3)
        span = TACTIC_ORDER[ranks[-1]]
        reasons.append(
            f"{len(ranks)} ATT&CK tactics touched, reaching {span}"
        )
        # Distance travelled, not just breadth: Discovery→Impact is the shape
        # that matters, and two neighbouring tactics is not that.
        if ranks[-1] - ranks[0] >= 4:
            score += 20
            reasons.append(
                f"the behaviour advances from {TACTIC_ORDER[ranks[0]]} to {TACTIC_ORDER[ranks[-1]]}"
            )

    # Said, not scored. Breadth that exists only in rule mappings is worth
    # showing an analyst and worth nothing in the number.
    # Claimed tactics count for a little. A rule's mapping is its author's
    # hypothesis and this deployment has never once corroborated one, so it is
    # not evidence — but a Kerberoasting rule asserting Credential Access is
    # still information, and treating it as zero throws away the only ATT&CK
    # signal available for attacks the collectors cannot reach. Capped low, and
    # always named as unevidenced so nobody reads it as a finding.
    extra = {t for t in (claimed_only or set()) if t not in tactics}
    if extra:
        score += min(5 * len(extra), 15)
        reasons.append(
            f"{len(extra)} further tactic(s) claimed by the rules, not evidenced here"
        )

    if max_risk >= 70:
        score += 15
        reasons.append(f"an alert in this window scored {max_risk}/100 on its own")
    if "malicious" in verdicts:
        score += 15
        reasons.append("at least one alert concluded malicious")

    return min(score, 100), reasons


async def correlate_alerts(
    db: AsyncSession,
    *,
    hours: int = DEFAULT_WINDOW_HOURS,
    min_rules: int = MIN_DISTINCT_RULES,
    limit: int = 50,
) -> dict[str, Any]:
    """Entities carrying more than one independent detection inside the window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, hours))

    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.title,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.entity_host,
                AlertBodyInvestigationRun.entity_user,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.overall_verdict,
                AlertBodyInvestigationRun.highest_risk_score,
                AlertBodyInvestigationRun.result_attack_assessment,
            )
            .where(
                AlertBodyInvestigationRun.created_at >= cutoff,
                AlertBodyInvestigationRun.entity_host.isnot(None),
            )
            .order_by(AlertBodyInvestigationRun.created_at.desc())
        )
    ).all()

    grouped: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        grouped[str(row.entity_host)].append(row)

    cases: list[dict[str, Any]] = []
    for entity, members in grouped.items():
        rules = {str(m.detection_rule_id or m.detection_rule_name or "") for m in members}
        rules.discard("")
        if len(rules) < min_rules:
            continue

        tactics: set[str] = set()
        claimed: set[str] = set()
        for member in members:
            evidenced_t, claimed_t = _tactics_of(member.result_attack_assessment)
            tactics |= evidenced_t
            claimed |= claimed_t

        verdicts = [str(m.overall_verdict or "") for m in members]
        max_risk = max((int(m.highest_risk_score or 0) for m in members), default=0)
        score, reasons = score_case(
            distinct_rules=len(rules), tactics=tactics, max_risk=max_risk,
            verdicts=verdicts, claimed_only=claimed,
        )

        ordered = sorted(members, key=lambda m: m.created_at or cutoff)
        cases.append(
            {
                "entity_host": entity,
                "entity_users": sorted({str(m.entity_user) for m in members if m.entity_user}),
                "window_hours": hours,
                "first_seen": ordered[0].created_at.isoformat() if ordered[0].created_at else None,
                "last_seen": ordered[-1].created_at.isoformat() if ordered[-1].created_at else None,
                "alert_count": len(members),
                "distinct_rules": len(rules),
                "tactics": sorted(tactics, key=lambda t: _TACTIC_RANK.get(t.casefold(), 99)),
                "tactics_claimed_only": sorted(
                    {t for t in claimed if t not in tactics},
                    key=lambda t: _TACTIC_RANK.get(t.casefold(), 99),
                ),
                "max_risk_score": max_risk,
                "score": score,
                "reasons": reasons,
                "alerts": [
                    {
                        "run_id": str(m.id),
                        "title": m.title,
                        "created_at": m.created_at.isoformat() if m.created_at else None,
                        "detection_rule_id": m.detection_rule_id,
                        "detection_rule_name": m.detection_rule_name,
                        "overall_verdict": m.overall_verdict,
                        "highest_risk_score": m.highest_risk_score,
                    }
                    for m in ordered
                ][:100],
            }
        )

    cases.sort(key=lambda case: (-case["score"], -case["distinct_rules"]))
    return {
        "window_hours": hours,
        "entities_seen": len(grouped),
        "cases": cases[:limit],
        "total_cases": len(cases),
    }


async def case_for_run(db: AsyncSession, run_id: Any, *, hours: int = DEFAULT_WINDOW_HOURS) -> dict[str, Any] | None:
    """
    The case this one alert belongs to, if any.

    What the alert page asks: an analyst reading a single alert has no way to
    know it is one of five on that machine tonight, and that is the fact that
    changes what they do next.
    """
    run = await db.get(AlertBodyInvestigationRun, run_id)
    if run is None or not run.entity_host:
        return None

    result = await correlate_alerts(db, hours=hours, limit=500)
    for case in result["cases"]:
        if case["entity_host"] == run.entity_host and any(
            alert["run_id"] == str(run.id) for alert in case["alerts"]
        ):
            return case
    return None
