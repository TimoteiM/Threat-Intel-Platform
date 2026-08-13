"""
ATT&CK coverage: what the detections claim, and what the evidence ever shows.

Rolled up across stored alert runs, three numbers per technique answer three
different questions:

    claimed      how often detections asserted this technique
    confirmed    how often the evidence bore that assertion out
    observed     how often the evidence showed it whether or not a rule said so

The gaps between them are the interesting part. A technique with claims and no
confirmations is a mapping nobody has ever validated. One that is observed but
never claimed is behaviour the detections are not describing. And a tactic with
no rows at all is a blind spot — which is why tactics with zero coverage are
listed explicitly rather than being absent from the output.

Everything here counts what was stored. Nothing is inferred about techniques the
platform has never seen evidence for.

Tactics come from the ATT&CK catalog, not from this platform's evidence
whitelist, so a technique a rule claimed but nothing here could ever corroborate
still lands on the matrix. A technique belonging to several tactics is counted
under each, as ATT&CK's own matrix lists it — so the per-tactic technique counts
sum to more than `techniques_seen`. Only an id ATT&CK does not know at all is
reported as Unmapped.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.attack_mapping import TECHNIQUE_DB, describe_technique, technique_tactics
from app.models.database import AlertBodyInvestigationRun


async def attack_coverage(db: AsyncSession, *, days: int = 90) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    # Only the assessment is needed. Selecting `result_json` pulled the whole
    # 14 KB payload for every run — 21 MB to read 1.9 KB per row.
    assessments = (
        await db.execute(
            select(AlertBodyInvestigationRun.result_attack_assessment).where(
                AlertBodyInvestigationRun.created_at >= cutoff
            )
        )
    ).scalars().all()

    claimed: dict[str, int] = defaultdict(int)
    confirmed: dict[str, int] = defaultdict(int)
    uncorroborated: dict[str, int] = defaultdict(int)
    observed: dict[str, int] = defaultdict(int)
    ai_suggested: dict[str, int] = defaultdict(int)
    runs_assessed = 0

    for assessment in assessments:
        if not isinstance(assessment, dict):
            continue
        runs_assessed += 1
        for claim in assessment.get("techniques") or []:
            technique = str(claim.get("id") or "")
            if not technique:
                continue
            claimed[technique] += 1
            if claim.get("status") == "confirmed":
                confirmed[technique] += 1
                observed[technique] += 1
            elif claim.get("status") == "not_corroborated":
                uncorroborated[technique] += 1
        for extra in assessment.get("additional_techniques") or []:
            technique = str(extra.get("id") or "")
            if not technique:
                continue
            observed[technique] += 1
            if extra.get("source") == "ai_suggested":
                ai_suggested[technique] += 1

    techniques = [
        _row(technique, claimed, confirmed, uncorroborated, observed, ai_suggested)
        for technique in sorted(set(claimed) | set(observed))
    ]

    return {
        "window_days": days,
        "runs_assessed": runs_assessed,
        "techniques_seen": len(techniques),
        "techniques": techniques,
        "tactics": _by_tactic(techniques),
        "unvalidated_mappings": [
            row for row in techniques if row["claimed"] and not row["confirmed"]
        ],
        "undetected_behaviour": [
            row for row in techniques if row["observed"] and not row["claimed"]
        ],
        "blind_spots": _blind_spots(techniques),
    }


async def tactic_alerts(
    db: AsyncSession, *, tactic: str, days: int = 90, limit: int = 100
) -> dict[str, Any]:
    """
    The alerts behind one tactic's numbers.

    A tactic row says how many techniques were claimed and confirmed; it cannot
    say which alerts produced them, and that is the first thing an analyst asks
    of a number they doubt. Same window and same technique→tactic mapping as
    `attack_coverage`, so the counts here reconcile with the row that was
    clicked: a run appears once, carrying every technique of this tactic it
    touched and how that technique fared.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    runs = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.title,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.overall_verdict,
                AlertBodyInvestigationRun.highest_risk_score,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.result_attack_assessment,
            )
            .where(AlertBodyInvestigationRun.created_at >= cutoff)
            .order_by(AlertBodyInvestigationRun.created_at.desc())
        )
    ).all()

    alerts: list[dict[str, Any]] = []
    for run in runs:
        assessment = run.result_attack_assessment
        if not isinstance(assessment, dict):
            continue
        matched = _techniques_in_tactic(assessment, tactic)
        if not matched:
            continue
        alerts.append(
            {
                "run_id": str(run.id),
                "title": run.title,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "overall_verdict": run.overall_verdict,
                "highest_risk_score": run.highest_risk_score,
                "detection_rule_id": run.detection_rule_id,
                "detection_rule_name": run.detection_rule_name,
                "techniques": matched,
                "confirmed": sum(1 for item in matched if item["status"] == "confirmed"),
            }
        )

    return {
        "tactic": tactic,
        "window_days": days,
        "total": len(alerts),
        "returned": min(len(alerts), limit),
        "alerts": alerts[:limit],
    }


def _techniques_in_tactic(assessment: dict[str, Any], tactic: str) -> list[dict[str, Any]]:
    """
    This run's techniques belonging to `tactic`, deduplicated by id.

    The tactic is resolved from the ATT&CK catalog rather than the stored row,
    so an old run whose payload predates a mapping change still lands in the
    same bucket the coverage rollup puts it in — and a technique ATT&CK lists
    under two tactics appears under both.
    """
    matched: dict[str, dict[str, Any]] = {}

    def consider(entry: Any, *, status: str) -> None:
        if not isinstance(entry, dict):
            return
        technique = str(entry.get("id") or "")
        if not technique:
            return
        info = describe_technique(technique) or {}
        if tactic not in (info.get("tactics") or ["Unmapped"]):
            return
        # A confirmed claim outranks the same id arriving again as additional.
        if technique in matched and matched[technique]["status"] == "confirmed":
            return
        matched[technique] = {
            "id": technique,
            "name": info.get("name") or entry.get("name"),
            "url": info.get("url"),
            "status": status,
            "evidenceable": bool(info.get("evidenceable")),
            "explanation": entry.get("explanation"),
        }

    for claim in assessment.get("techniques") or []:
        status = claim.get("status") if isinstance(claim, dict) else None
        consider(claim, status=str(status or "claimed"))
    for extra in assessment.get("additional_techniques") or []:
        source = extra.get("source") if isinstance(extra, dict) else None
        consider(extra, status="ai_suggested" if source == "ai_suggested" else "observed")

    return sorted(matched.values(), key=lambda item: item["id"])


def _row(
    technique: str,
    claimed: dict[str, int],
    confirmed: dict[str, int],
    uncorroborated: dict[str, int],
    observed: dict[str, int],
    ai_suggested: dict[str, int],
) -> dict[str, Any]:
    info = describe_technique(technique) or {}
    claims = claimed.get(technique, 0)
    return {
        "id": technique,
        "name": info.get("name"),
        "tactic": info.get("tactic") or "Unmapped",
        "tactics": info.get("tactics") or ["Unmapped"],
        "url": info.get("url"),
        # True when this platform could corroborate the technique at all. A
        # claim we can never evidence is not a failing detection, and the UI
        # needs to be able to say so rather than showing it as unvalidated.
        "evidenceable": bool(info.get("evidenceable")),
        # ATT&CK retired it; the rule claiming it has not caught up.
        "deprecated": bool(info.get("deprecated")),
        "claimed": claims,
        "confirmed": confirmed.get(technique, 0),
        "uncorroborated": uncorroborated.get(technique, 0),
        "observed": observed.get(technique, 0),
        "ai_suggested": ai_suggested.get(technique, 0),
        "confirm_rate": round(confirmed.get(technique, 0) / claims, 3) if claims else None,
    }


def _by_tactic(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Roll techniques up per tactic, counting a multi-tactic technique under each.

    ATT&CK lists T1547 under both Persistence and Privilege Escalation, and an
    analyst reading either column expects to find it there — so the per-tactic
    counts deliberately do not sum to the technique total.
    """
    grouped: dict[str, dict[str, int]] = defaultdict(
        lambda: {"techniques": 0, "claimed": 0, "confirmed": 0, "observed": 0}
    )
    for row in techniques:
        for tactic in row["tactics"]:
            bucket = grouped[tactic]
            bucket["techniques"] += 1
            bucket["claimed"] += row["claimed"]
            bucket["confirmed"] += row["confirmed"]
            bucket["observed"] += row["observed"]
    return [{"tactic": tactic, **counts} for tactic, counts in sorted(grouped.items())]


def _blind_spots(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Tactics this platform can evidence but has never seen.

    Scoped to the technique whitelist on purpose: claiming a blind spot in a
    tactic we could not detect even in principle would overstate the gap.
    """
    seen_tactics = {tactic for row in techniques if row["observed"] for tactic in row["tactics"]}
    coverable: dict[str, list[str]] = defaultdict(list)
    for technique_id in TECHNIQUE_DB:
        for tactic in technique_tactics(technique_id):
            coverable[tactic].append(technique_id)
    return [
        {"tactic": tactic, "techniques_we_could_evidence": len(ids)}
        for tactic, ids in sorted(coverable.items())
        if tactic not in seen_tactics
    ]
