"""
What each detection rule is actually worth, measured from its own alerts.

A SIEM reports how often a rule fired. It cannot report whether firing was
useful, because it never investigates what it produced. This platform does, and
it now records which rule produced each run — so the questions a detection
engineer actually has become answerable:

    which rules fire most and conclude benign every time
    whose ATT&CK mapping the evidence never corroborates
    which fire only on indicators the SOC has already excluded
    which the analysts themselves marked false positive

None of these are opinions. Each is counted from stored runs: the verdicts the
decision engine reached, the ATT&CK assessment against the rule's own claim, and
the feedback analysts left. A rule with too few alerts to judge is reported as
exactly that rather than given a misleading score.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun, AnalystFeedback

logger = logging.getLogger(__name__)

# Below this, proportions are noise. The rule is listed with its counts and no
# score, which is more honest than "100% false positive" from two alerts.
MIN_ALERTS_TO_SCORE = 5

NOISE_VERDICTS = frozenset({"benign", "inconclusive", None})


async def detection_quality(
    db: AsyncSession,
    *,
    days: int = 30,
    limit: int = 100,
) -> dict[str, Any]:
    """One row per detection rule seen in the window, worst signal-to-noise first."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    # Selecting the whole entity dragged `result_json` and `alert_body` along
    # for every run in the window. Only these columns are read.
    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.overall_verdict,
                AlertBodyInvestigationRun.highest_risk_score,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.result_attack_assessment,
                AlertBodyInvestigationRun.result_summary,
                AlertBodyInvestigationRun.result_extraction,
                AlertBodyInvestigationRun.result_overall_verdict,
            ).where(
                AlertBodyInvestigationRun.created_at >= cutoff,
                AlertBodyInvestigationRun.detection_rule_id.isnot(None),
            )
        )
    ).all()

    feedback = await _feedback_by_rule(db, cutoff)

    rules: dict[str, dict[str, Any]] = {}
    for run in rows:
        rule_id = str(run.detection_rule_id)
        entry = rules.setdefault(rule_id, _blank(rule_id, run.detection_rule_name))
        _accumulate(entry, run)

    summaries = [_finalize(entry, feedback.get(entry["rule_id"], {})) for entry in rules.values()]
    # Worst first: the rules costing the most attention for the least result.
    summaries.sort(key=lambda item: (-(item["noise_rate"] or 0), -item["alerts"]))

    return {
        "window_days": days,
        "rules_seen": len(summaries),
        "alerts_total": sum(item["alerts"] for item in summaries),
        "min_alerts_to_score": MIN_ALERTS_TO_SCORE,
        "rules": summaries[:limit],
        "unattributed_alerts": await _unattributed(db, cutoff),
    }


# ── Internals ─────────────────────────────────────────────────────────────────


def _blank(rule_id: str, rule_name: str | None) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "alerts": 0,
        "verdicts": {"malicious": 0, "suspicious": 0, "benign": 0, "inconclusive": 0},
        "highest_risk_score": 0,
        "duplicate_deliveries": 0,
        "fully_excluded_alerts": 0,
        "attack_claims": 0,
        "attack_confirmed": 0,
        "attack_uncorroborated": 0,
        "attack_additional": 0,
        "last_seen": None,
    }


def _accumulate(entry: dict[str, Any], run: Any) -> None:
    entry["alerts"] += 1

    verdict = str(run.overall_verdict or run.result_overall_verdict or "inconclusive")
    if verdict in entry["verdicts"]:
        entry["verdicts"][verdict] += 1

    entry["highest_risk_score"] = max(entry["highest_risk_score"], int(run.highest_risk_score or 0))

    created = run.created_at
    if created and (entry["last_seen"] is None or created > entry["last_seen"]):
        entry["last_seen"] = created

    extraction = run.result_extraction or {}
    summary = run.result_summary or {}
    # An alert whose every indicator was whitelisted told the SOC nothing it did
    # not already know — the clearest possible waste signal.
    if extraction.get("excluded_total") and not summary.get("indicators_investigated"):
        entry["fully_excluded_alerts"] += 1

    assessment = run.result_attack_assessment or {}
    for claim in assessment.get("techniques") or []:
        entry["attack_claims"] += 1
        if claim.get("status") == "confirmed":
            entry["attack_confirmed"] += 1
        elif claim.get("status") == "not_corroborated":
            entry["attack_uncorroborated"] += 1
    entry["attack_additional"] += len(assessment.get("additional_techniques") or [])


def _finalize(entry: dict[str, Any], feedback: dict[str, int]) -> dict[str, Any]:
    alerts = entry["alerts"]
    verdicts = entry["verdicts"]
    noisy = verdicts["benign"] + verdicts["inconclusive"]
    scored = alerts >= MIN_ALERTS_TO_SCORE

    true_positive = feedback.get("true_positive", 0)
    false_positive = feedback.get("false_positive", 0)
    judged = true_positive + false_positive

    entry = {
        **entry,
        "last_seen": entry["last_seen"].isoformat() if entry["last_seen"] else None,
        # Share of this rule's alerts that concluded benign or inconclusive.
        # None below the threshold — a proportion from two alerts is not a rate.
        "noise_rate": round(noisy / alerts, 3) if scored and alerts else None,
        "actionable_rate": (
            round((verdicts["malicious"] + verdicts["suspicious"]) / alerts, 3) if scored and alerts else None
        ),
        # Of the ATT&CK techniques this rule claims, how often the evidence
        # actually bore them out. The rule's mapping is a testable assertion.
        "attack_confirm_rate": (
            round(entry["attack_confirmed"] / entry["attack_claims"], 3)
            if entry["attack_claims"] >= MIN_ALERTS_TO_SCORE
            else None
        ),
        "analyst_feedback": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "unclear": feedback.get("unclear", 0),
            "false_positive_rate": round(false_positive / judged, 3) if judged else None,
        },
        "scored": scored,
    }
    entry["assessment"] = _verdict_on_the_rule(entry)
    return entry


def _verdict_on_the_rule(entry: dict[str, Any]) -> str:
    """One sentence a detection engineer can act on, or an honest refusal."""
    if not entry["scored"]:
        return (
            f"Only {entry['alerts']} alert(s) in this window — too few to judge. "
            f"Counts are shown; no rate is calculated."
        )

    parts: list[str] = []
    noise = entry["noise_rate"] or 0
    if noise >= 0.9:
        parts.append(f"{noise:.0%} of its alerts concluded benign or inconclusive — a tuning candidate")
    elif noise >= 0.6:
        parts.append(f"{noise:.0%} concluded benign or inconclusive")
    else:
        parts.append(f"{entry['actionable_rate']:.0%} concluded malicious or suspicious")

    if entry["fully_excluded_alerts"]:
        parts.append(
            f"{entry['fully_excluded_alerts']} alert(s) contained nothing but excluded indicators"
        )

    confirm = entry["attack_confirm_rate"]
    if confirm is not None and confirm <= 0.2 and entry["attack_claims"]:
        parts.append(
            f"the evidence corroborated its ATT&CK mapping in only {confirm:.0%} of claims"
        )

    fp_rate = entry["analyst_feedback"]["false_positive_rate"]
    if fp_rate is not None and fp_rate >= 0.5:
        parts.append(f"analysts marked {fp_rate:.0%} of judged alerts false positive")

    return "; ".join(parts) + "."


async def _feedback_by_rule(db: AsyncSession, cutoff: datetime) -> dict[str, dict[str, int]]:
    try:
        rows = (
            await db.execute(
                select(
                    AnalystFeedback.detection_rule_id,
                    AnalystFeedback.verdict,
                    func.count(AnalystFeedback.id),
                )
                .where(
                    AnalystFeedback.created_at >= cutoff,
                    AnalystFeedback.detection_rule_id.isnot(None),
                )
                .group_by(AnalystFeedback.detection_rule_id, AnalystFeedback.verdict)
            )
        ).all()
    except Exception as exc:  # feedback is an enrichment, not a dependency
        logger.warning("Detection feedback lookup failed: %s", exc)
        return {}

    grouped: dict[str, dict[str, int]] = {}
    for rule_id, verdict, count in rows:
        grouped.setdefault(str(rule_id), {})[str(verdict)] = int(count)
    return grouped


async def _unattributed(db: AsyncSession, cutoff: datetime) -> int:
    """
    Alerts with no rule id — pasted by an analyst, or from a sender that does
    not send one. Reported so the totals visibly do not add up to everything.
    """
    return int(
        (
            await db.execute(
                select(func.count(AlertBodyInvestigationRun.id)).where(
                    AlertBodyInvestigationRun.created_at >= cutoff,
                    AlertBodyInvestigationRun.detection_rule_id.is_(None),
                )
            )
        ).scalar()
        or 0
    )
