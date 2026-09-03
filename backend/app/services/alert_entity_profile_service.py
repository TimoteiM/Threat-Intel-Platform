"""Everything this platform knows about one machine, in one place.

The correlated-cases list answers "is something happening on this host". It
cannot answer the question an analyst asks next — what IS this machine, what
does it normally do, and which part of what it did is actually unusual. That
answer exists already, scattered across three thousand alert runs; this
assembles it.

Nothing here is a new measurement. Rules, tactics, verdicts and indicators are
read back from stored runs, and the session spine supplies the history. The one
judgement it makes is which of that is worth surfacing first, and it makes that
by counting rather than by ranking on severity — a rule that fires two hundred
times is what the host does, not what happened to it.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.alert_correlation_service import _tactics_of as correlation_tactics
from app.models.database import (
    AlertBodyInvestigationRun,
    AlertCaseSnapshot,
    AlertCaseSpine,
)

logger = logging.getLogger(__name__)

# How many of each list the profile carries. The point of the window is to be
# read, not to be complete — the full set is a click away in the alert list.
TOP_RULES = 12
TOP_INDICATORS = 15
TIMELINE_LIMIT = 400

# An indicator at or above this concluded risk is called out separately rather
# than left in the communications list. Matches the watchlist auto-enrol floor,
# so "worth re-checking later" and "worth reading now" agree.
NOTABLE_RISK = 40


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _event_time(row: Any) -> datetime | None:
    return getattr(row, "event_time", None) or getattr(row, "created_at", None)


def _tactics_of(assessment: Any) -> set[str]:
    """The tactics the investigation evidenced, via the correlation service.

    Deliberately delegated rather than reimplemented. The first version of this
    read `technique["evidence"]`, which does not exist — the real shape carries
    `tactics`/`tactic` behind a confirmed-status check — so every host came back
    with an empty behaviour profile and nothing failed. A second copy of a
    parsing rule is a second thing to get wrong silently.
    """
    evidenced, _claimed = correlation_tactics(assessment)
    return evidenced


def _indicators_of(result_json: Any) -> list[dict[str, Any]]:
    if not isinstance(result_json, dict):
        return []
    summary = result_json.get("indicator_summary")
    if not isinstance(summary, dict):
        return []
    items = summary.get("indicators")
    return [item for item in items or [] if isinstance(item, dict)]


async def build_entity_profile(
    db: AsyncSession, *, host: str, days: int = 30
) -> dict[str, Any]:
    """Assemble one host's profile from what is already stored about it."""
    cutoff = datetime.now(timezone.utc).replace(microsecond=0)

    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.title,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.event_time,
                AlertBodyInvestigationRun.entity_host,
                AlertBodyInvestigationRun.entity_user,
                AlertBodyInvestigationRun.alert_source,
                AlertBodyInvestigationRun.alert_client,
                AlertBodyInvestigationRun.alert_kind,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.overall_verdict,
                AlertBodyInvestigationRun.highest_risk_score,
                AlertBodyInvestigationRun.result_attack_assessment,
                AlertBodyInvestigationRun.result_json,
            )
            .where(AlertBodyInvestigationRun.entity_host == host)
            .order_by(AlertBodyInvestigationRun.event_time.desc().nullslast())
        )
    ).all()

    if not rows:
        return {"host": host, "found": False, "alert_count": 0}

    ordered = sorted(rows, key=lambda r: _event_time(r) or cutoff)

    sources = Counter(str(r.alert_source or "unknown") for r in rows)
    clients = Counter(str(r.alert_client or "unknown") for r in rows)
    verdicts = Counter(str(r.overall_verdict or "unknown") for r in rows)
    users = Counter(str(r.entity_user) for r in rows if r.entity_user)

    # What this host does, by volume. Deliberately not sorted by severity: the
    # question this answers is "what is normal here", and the loudest rule is
    # the answer whether or not it is the most dangerous one.
    rule_counts: Counter[tuple[str, str]] = Counter()
    rule_last: dict[tuple[str, str], datetime | None] = {}
    rule_risk: dict[tuple[str, str], int] = defaultdict(int)
    tactic_counts: Counter[str] = Counter()
    timeline: list[dict[str, Any]] = []

    for row in ordered:
        rule_id = str(row.detection_rule_id or "")
        rule_name = str(row.detection_rule_name or row.title or "")
        key = (rule_id, rule_name)
        if rule_id or rule_name:
            rule_counts[key] += 1
            when = _event_time(row)
            if when and (rule_last.get(key) is None or when > rule_last[key]):
                rule_last[key] = when
            rule_risk[key] = max(rule_risk[key], int(row.highest_risk_score or 0))

        tactics = _tactics_of(row.result_attack_assessment)
        for tactic in tactics:
            tactic_counts[tactic] += 1

        if len(timeline) < TIMELINE_LIMIT:
            timeline.append(
                {
                    "run_id": str(row.id),
                    "event_time": _iso(_event_time(row)),
                    "rule": rule_name or rule_id or "unattributed",
                    "tactics": sorted(tactics),
                    "verdict": row.overall_verdict,
                    "risk": int(row.highest_risk_score or 0),
                }
            )

    # Who this machine talks to. Counted across runs, so a domain seen in forty
    # alerts reads as routine rather than as forty separate observations.
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for row in ordered:
        when = _iso(_event_time(row))
        for item in _indicators_of(row.result_json):
            kind = str(item.get("type") or "").strip().lower()
            value = str(item.get("value") or "").strip()
            if not kind or not value:
                continue
            entry = seen.setdefault(
                (kind, value),
                {
                    "type": kind, "value": value, "count": 0,
                    "risk": 0, "classification": None,
                    "excluded": bool(item.get("excluded")),
                    "first_seen": when, "last_seen": when,
                },
            )
            entry["count"] += 1
            entry["risk"] = max(entry["risk"], int(item.get("risk_score") or 0))
            classification = str(item.get("classification") or "").strip()
            # Keep the worst call ever made about it, not the most recent: an
            # indicator that concluded malicious once does not become benign
            # because a later alert did not re-check it.
            if classification and classification not in {"not_investigated", "benign"}:
                entry["classification"] = classification
            elif entry["classification"] is None and classification:
                entry["classification"] = classification
            if when:
                entry["last_seen"] = max(entry["last_seen"] or when, when)
                entry["first_seen"] = min(entry["first_seen"] or when, when)

    indicators = sorted(
        seen.values(), key=lambda item: (-item["risk"], -item["count"], item["value"])
    )
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in indicators:
        by_type[item["type"]].append(item)

    # What stands out. Not a score — a short list of the things an analyst would
    # otherwise have to open forty alerts to notice.
    notable: list[dict[str, Any]] = []
    for item in indicators:
        if item["risk"] >= NOTABLE_RISK and not item["excluded"]:
            notable.append(
                {
                    "kind": "indicator",
                    "text": f"{item['type'].upper()} {item['value']} concluded "
                            f"{item['classification'] or 'risky'} ({item['risk']}/100), "
                            f"seen in {item['count']} alert(s)",
                    "risk": item["risk"],
                }
            )
    malicious = verdicts.get("malicious", 0)
    if malicious:
        notable.append(
            {
                "kind": "verdict",
                "text": f"{malicious} alert(s) on this host concluded malicious",
                "risk": 100,
            }
        )
    rare = [name for (rid, name), n in rule_counts.items() if n == 1 and name]
    if rare:
        notable.append(
            {
                "kind": "rare",
                "text": f"{len(rare)} rule(s) fired exactly once here — "
                        f"{', '.join(rare[:3])}{'…' if len(rare) > 3 else ''}",
                "risk": 30,
            }
        )
    notable.sort(key=lambda item: -item["risk"])

    # History, from the spine written at read time.
    spine = (
        await db.execute(
            select(AlertCaseSpine)
            .where(AlertCaseSpine.entity_host == host)
            .order_by(AlertCaseSpine.session_started_at.desc())
        )
    ).scalars().all()
    keys = [row.case_key for row in spine]
    history: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if keys:
        snapshots = (
            await db.execute(
                select(AlertCaseSnapshot)
                .where(AlertCaseSnapshot.case_key.in_(keys))
                .order_by(AlertCaseSnapshot.computed_at.asc())
            )
        ).scalars().all()
        for snapshot in snapshots:
            history[snapshot.case_key].append(
                {
                    "computed_at": _iso(snapshot.computed_at),
                    "score": snapshot.score,
                    "member_count": snapshot.member_count,
                    "emitted_event": snapshot.emitted_event,
                }
            )

    sessions = [
        {
            "case_key": row.case_key,
            "session_seq": row.session_seq,
            "started_at": _iso(row.session_started_at),
            "last_activity_at": _iso(row.last_activity_at),
            "status": row.status,
            "assignee": row.assignee,
            "peak_score": row.peak_score,
            "superseded_by": row.superseded_by_case_key,
            "history": history.get(row.case_key, []),
        }
        for row in spine
    ]

    return {
        "host": host,
        "found": True,
        "alert_count": len(rows),
        "first_seen": _iso(_event_time(ordered[0])),
        "last_seen": _iso(_event_time(ordered[-1])),
        "sources": [{"name": n, "count": c} for n, c in sources.most_common()],
        "clients": [{"name": n, "count": c} for n, c in clients.most_common()],
        # Reported with its own coverage, because entity_user is populated on a
        # small minority of runs and some stored values are domain fragments
        # rather than principals. Showing the count beside them stops the list
        # reading as "these are the users of this machine".
        "users": {
            "values": [{"name": n, "count": c} for n, c in users.most_common(10)],
            "runs_with_user": sum(users.values()),
            "runs_total": len(rows),
        },
        "verdicts": [{"name": n, "count": c} for n, c in verdicts.most_common()],
        "max_risk": max((int(r.highest_risk_score or 0) for r in rows), default=0),
        "rules": [
            {
                "id": rid or None,
                "name": name or rid or "unattributed",
                "count": count,
                "last_seen": _iso(rule_last.get((rid, name))),
                "max_risk": rule_risk[(rid, name)],
            }
            for (rid, name), count in rule_counts.most_common(TOP_RULES)
        ],
        "rules_total": len(rule_counts),
        "tactics": [{"name": n, "count": c} for n, c in tactic_counts.most_common()],
        "indicators": {
            kind: items[:TOP_INDICATORS] for kind, items in by_type.items()
        },
        "indicator_totals": {kind: len(items) for kind, items in by_type.items()},
        "notable": notable[:8],
        "sessions": sessions,
        "timeline": timeline,
    }
