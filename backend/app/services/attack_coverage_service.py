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
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.attack_mapping import TECHNIQUE_DB, get_technique_info
from app.models.database import AlertBodyInvestigationRun


async def attack_coverage(db: AsyncSession, *, days: int = 90) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    runs = (
        await db.execute(
            select(AlertBodyInvestigationRun.result_json).where(
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

    for payload in runs:
        assessment = (payload or {}).get("attack_assessment")
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


def _row(
    technique: str,
    claimed: dict[str, int],
    confirmed: dict[str, int],
    uncorroborated: dict[str, int],
    observed: dict[str, int],
    ai_suggested: dict[str, int],
) -> dict[str, Any]:
    info = get_technique_info(technique) or {}
    claims = claimed.get(technique, 0)
    return {
        "id": technique,
        "name": info.get("name"),
        "tactic": info.get("tactic") or "Unmapped",
        "url": info.get("url"),
        "claimed": claims,
        "confirmed": confirmed.get(technique, 0),
        "uncorroborated": uncorroborated.get(technique, 0),
        "observed": observed.get(technique, 0),
        "ai_suggested": ai_suggested.get(technique, 0),
        "confirm_rate": round(confirmed.get(technique, 0) / claims, 3) if claims else None,
    }


def _by_tactic(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, int]] = defaultdict(
        lambda: {"techniques": 0, "claimed": 0, "confirmed": 0, "observed": 0}
    )
    for row in techniques:
        bucket = grouped[row["tactic"]]
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
    seen_tactics = {row["tactic"] for row in techniques if row["observed"]}
    coverable: dict[str, list[str]] = defaultdict(list)
    for technique_id, info in TECHNIQUE_DB.items():
        coverable[info["tactic"]].append(technique_id)
    return [
        {"tactic": tactic, "techniques_we_could_evidence": len(ids)}
        for tactic, ids in sorted(coverable.items())
        if tactic not in seen_tactics
    ]
