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
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.attack_mapping import TECHNIQUE_DB, describe_technique, technique_tactics
from app.models.database import AlertBodyInvestigationRun


async def attack_coverage(db: AsyncSession, *, days: int = 90) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    # Only the assessment is needed. Selecting `result_json` pulled the whole
    # 14 KB payload for every run — 21 MB to read 1.9 KB per row.
    # The rule columns ride along so the mismatch view can name who owns a bad
    # mapping. They are short varchars; the 14 KB result_json is still not read.
    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.result_attack_assessment,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
            ).where(AlertBodyInvestigationRun.created_at >= cutoff)
        )
    ).all()
    assessments = [row[0] for row in rows]

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
        # Confirmed: the evidence independently bore out what a rule claimed.
        "confirmed_techniques": [row for row in techniques if row["confirmed"]],
        # Found by the AI and claimed by no rule — the techniques a detection
        # author has not thought of yet, which is a different question from a
        # rule that was wrong.
        "ai_suggested_techniques": [row for row in techniques if row["ai_suggested"]],
        "unvalidated_mappings": [
            row for row in techniques if row["claimed"] and not row["confirmed"]
        ],
        "undetected_behaviour": [
            row for row in techniques if row["observed"] and not row["claimed"]
        ],
        "blind_spots": _blind_spots(techniques),
        "mapping_mismatches": _mapping_mismatches(rows),
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
        lambda: {
            "techniques": 0, "claimed": 0, "confirmed": 0, "observed": 0,
            # Carried so the page can filter tactics by the same lenses it
            # offers for techniques. Without these a tactic row cannot say
            # whether anything under it was ever confirmed, or whether the AI
            # is the only reason it appears at all.
            "uncorroborated": 0, "ai_suggested": 0,
            "confirmed_techniques": 0, "ai_suggested_techniques": 0,
        }
    )
    for row in techniques:
        for tactic in row["tactics"]:
            bucket = grouped[tactic]
            bucket["techniques"] += 1
            bucket["claimed"] += row["claimed"]
            bucket["confirmed"] += row["confirmed"]
            bucket["observed"] += row["observed"]
            bucket["uncorroborated"] += row["uncorroborated"]
            bucket["ai_suggested"] += row["ai_suggested"]
            # Distinct techniques, not occurrences: "3 confirmed techniques" is
            # what an analyst reads a tactic row for, and one technique
            # confirmed 40 times is not three.
            if row["confirmed"]:
                bucket["confirmed_techniques"] += 1
            if row["ai_suggested"]:
                bucket["ai_suggested_techniques"] += 1
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


def _mapping_mismatches(rows: Sequence[Any], *, limit: int = 25) -> list[dict[str, Any]]:
    """
    What a rule claimed against what the evidence found on the same alert.

    Every ATT&CK claim in this deployment is not_corroborated — not because the
    assessment is broken, but because the rules and the evidence are describing
    different things. A rule claims T1078 Valid Accounts and the evidence on
    that same run shows T1027 and T1059; a rule claims T1489 and the evidence
    shows T1566.002. The existing views cannot show this: "claimed but never
    corroborated" lists the claim with no idea what turned up instead, and
    "observed but never claimed" lists the finding with no idea which rule
    missed it. The pairing is the actionable part, and it only exists per run.

    Only runs carrying both a claim and evidence are counted. A run with a claim
    and nothing found is not a mismatch — it is an alert that carried no
    evidence either way, which "claimed but never corroborated" already says.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for assessment, rule_id, rule_name in rows:
        if not isinstance(assessment, dict):
            continue
        claims = [c for c in (assessment.get("techniques") or []) if isinstance(c, dict)]
        found = [a for a in (assessment.get("additional_techniques") or []) if isinstance(a, dict)]
        if not claims or not found:
            continue
        # A run where something *was* confirmed is not a mismatch, whatever else
        # it also found.
        if any(c.get("status") == "confirmed" for c in claims):
            continue

        key = (str(rule_id or ""), str(rule_name or "").strip() or "(unnamed rule)")
        bucket = grouped.setdefault(key, {
            "rule_id": key[0] or None,
            "rule_name": key[1],
            "runs": 0,
            "_claimed": defaultdict(int),
            "_found": defaultdict(int),
            "_found_names": {},
            "_claimed_names": {},
            "_ai_only": set(),
        })
        bucket["runs"] += 1

        for claim in claims:
            technique = str(claim.get("id") or "")
            if technique:
                bucket["_claimed"][technique] += 1
                bucket["_claimed_names"][technique] = claim.get("name")
        for item in found:
            technique = str(item.get("id") or "")
            if not technique:
                continue
            bucket["_found"][technique] += 1
            bucket["_found_names"][technique] = item.get("name")
            # Tracked so the UI can separate a deterministic signal from a
            # model's suggestion. One is a rule that mapped the wrong thing;
            # the other is a lead worth reading before rewriting anything.
            if item.get("source") == "ai_suggested":
                bucket["_ai_only"].add(technique)
            else:
                bucket["_ai_only"].discard(technique)

    out: list[dict[str, Any]] = []
    for bucket in grouped.values():
        claimed_names = bucket.pop("_claimed_names")
        found_names = bucket.pop("_found_names")
        ai_only = bucket.pop("_ai_only")
        claimed_counts = bucket.pop("_claimed")
        found_counts = bucket.pop("_found")
        bucket["claimed"] = [
            {"id": tid, "name": claimed_names.get(tid) or (describe_technique(tid) or {}).get("name"),
             "runs": count}
            for tid, count in sorted(claimed_counts.items(), key=lambda kv: -kv[1])
        ][:8]
        bucket["evidenced_instead"] = [
            {"id": tid, "name": found_names.get(tid) or (describe_technique(tid) or {}).get("name"),
             "runs": count, "ai_only": tid in ai_only}
            for tid, count in sorted(found_counts.items(), key=lambda kv: -kv[1])
        ][:8]
        out.append(bucket)

    out.sort(key=lambda item: -item["runs"])
    return out[:limit]
