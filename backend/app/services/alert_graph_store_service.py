"""Writing extracted entities to the tables, and reading them back as a graph.

The brief's requirement: the case graph should be a join, not a re-parse. So
extraction happens once per alert and lands in `alert_graph_entity` and
`alert_graph_edge`; a case graph is a select on `run_id`, and a pivot — "where
else has this binary been seen" — is an index hit on `merge_key`.

Idempotent by construction. Both tables carry a uniqueness constraint over
(run_id, identity), so re-running the extractor on an alert replaces that
alert's rows rather than accumulating duplicates. That matters because the
extractor will change: every time a field shape is understood better, the
backfill runs again over the same alerts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import (
    AlertBodyInvestigationRun,
    AlertGraphEdge,
    AlertGraphEntity,
)
from app.services.alert_graph_assembly_service import AlertEvidence, assemble
from app.services.alert_graph_extraction_service import Extracted, extract
from app.services.source_severity_service import reserve_for_unrated


def confirmed_ids(assessment: Any) -> list[str]:
    """The ATT&CK ids this alert's investigation actually corroborated.

    Anything a *rule* asserts is a claim: `rule.mitre.id` is its author's
    mapping, not a finding. 30,794 of the 30,834 mappings in this estate have
    never been corroborated, so reading the rule's opinion as a result would
    turn the graph into a confident fiction.
    """
    techniques = (assessment or {}).get("techniques")
    if not isinstance(techniques, list):
        return []
    return [
        str(t.get("id"))
        for t in techniques
        if isinstance(t, dict) and t.get("status") == "confirmed" and t.get("id")
    ]


async def materialise_run(
    db: AsyncSession,
    *,
    run_id: Any,
    alert_body: str | None,
    event_time: datetime | None,
    risk_score: int | None,
    assessment: Any = None,
    log_events: Any = None,
) -> tuple[int, int]:
    """Extract one alert and replace its rows. Returns (entities, edges).

    `log_events` are the SIEM events already retrieved around this alert.
    They carry the same dotted field names and are read through the same
    builder, which is where most of the registry and process detail lives:
    `targetObject` appears 5,805 times across stored log context against 25
    times across alert bodies.
    """
    found = extract(
        alert_body, risk_score=risk_score,
        confirmed_techniques=confirmed_ids(assessment),
        log_events=log_events or (),
    )
    # Remembered on the run, so a case with no extractable alerts can name the
    # source it could not read without re-parsing every body to find out.
    await db.execute(
        update(AlertBodyInvestigationRun)
        .where(AlertBodyInvestigationRun.id == run_id)
        .values(
            graph_source_type=found.source_type[:64],
            # The alert's own severity, so a bounded read can rank on severity
            # rather than on indicator reputation.
            source_severity=found.source_severity,
            source_severity_raw=found.source_severity_raw,
        )
    )
    await db.execute(delete(AlertGraphEntity).where(AlertGraphEntity.run_id == run_id))
    await db.execute(delete(AlertGraphEdge).where(AlertGraphEdge.run_id == run_id))
    for entity in found.entities:
        db.add(
            AlertGraphEntity(
                run_id=run_id, kind=entity.kind, merge_key=entity.merge_key[:512],
                label=(entity.label or "?")[:255], basis=entity.basis,
                attrs=entity.attrs, event_time=event_time,
                indicator_risk_score=(risk_score or None),
                source_severity=found.source_severity,
            )
        )
    for edge in found.edges:
        db.add(
            AlertGraphEdge(
                run_id=run_id, kind=edge.kind, source_key=edge.source[:512],
                target_key=edge.target[:512], basis=edge.basis,
                attrs=edge.attrs, event_time=event_time,
            )
        )
    return len(found.entities), len(found.edges)


#: What a bounded read is allowed to pull, measured in stored entity rows
#: rather than in alerts.
#:
#: Alerts were the wrong unit. Assembly time tracks the rows, and the rows per
#: alert vary by two orders of magnitude depending on how much log context the
#: alert carries: case #1849 holds 4,860 entities across 2,367 alerts (2 per
#: alert) while #61 holds 64,430 across 2,818 (23 per alert). Bounding at 300
#: alerts therefore meant 726 rows on one case and 31,555 on another — and
#: once the bound ranked on severity rather than on indicator reputation it
#: began selecting exactly the richest alerts, taking assembly from 215 ms to
#: 3,958 ms and node counts from 72 to 298.
#:
#: Calibrated on the measurement: 30k rows assembles in ~2.6s, so ~4k lands
#: near 350ms, inside the 400ms budget.
MAX_ENTITY_ROWS = 4000

#: A ceiling on alerts as well, so a case of a million trivial alerts cannot
#: spend the whole entity budget on rows that say nothing.
MAX_ALERTS_PER_GRAPH = 300


async def _bounded_selection(
    db: AsyncSession,
    run_ids: Sequence[Any],
    *,
    max_alerts: int,
    max_rows: int,
) -> tuple[list[Any], int, int]:
    """The alerts a bounded read will use, chosen by severity, bounded by rows.

    Returns (chosen, dropped_alerts, rows_read).
    """
    counts = dict(
        (
            await db.execute(
                select(AlertGraphEntity.run_id, func.count())
                .where(AlertGraphEntity.run_id.in_(run_ids))
                .group_by(AlertGraphEntity.run_id)
            )
        ).all()
    )
    rated = (
        await db.execute(
            select(AlertBodyInvestigationRun.id)
            .where(
                AlertBodyInvestigationRun.id.in_(run_ids),
                AlertBodyInvestigationRun.source_severity.isnot(None),
            )
            .order_by(
                AlertBodyInvestigationRun.source_severity.desc(),
                AlertBodyInvestigationRun.event_time.desc().nullslast(),
            )
        )
    ).scalars().all()
    unrated = (
        await db.execute(
            select(AlertBodyInvestigationRun.id)
            .where(
                AlertBodyInvestigationRun.id.in_(run_ids),
                AlertBodyInvestigationRun.source_severity.is_(None),
            )
            .order_by(AlertBodyInvestigationRun.event_time.desc().nullslast())
        )
    ).scalars().all()

    # Unrated alerts keep their share rather than sorting last. An alert whose
    # source states no severity is a gap in coverage, not a quiet alert, and
    # 892 of 15,255 are in that position.
    keep_unrated = reserve_for_unrated(len(run_ids), len(unrated), max_alerts)
    ordered = list(unrated[:keep_unrated]) + list(rated)

    chosen: list[Any] = []
    rows = 0
    for run_id in ordered:
        if len(chosen) >= max_alerts:
            break
        cost = int(counts.get(run_id, 0))
        if chosen and rows + cost > max_rows:
            break
        chosen.append(run_id)
        rows += cost
    return chosen, len(run_ids) - len(chosen), rows


async def graph_for_runs(
    db: AsyncSession,
    run_ids: Sequence[Any],
    *,
    max_alerts: int = MAX_ALERTS_PER_GRAPH,
    max_rows: int = MAX_ENTITY_ROWS,
) -> dict[str, Any]:
    """Assemble a graph from the stored rows of these alerts.

    This is the join the brief asked for: indexed selects and an in-memory
    merge, with no alert body read and no regex run.
    """
    if not run_ids:
        return assemble([])

    considered = list(run_ids)
    dropped_alerts = 0
    rows_read = 0
    if len(considered) > max_alerts:
        considered, dropped_alerts, rows_read = await _bounded_selection(
            db, considered, max_alerts=max_alerts, max_rows=max_rows
        )

    run_ids = considered
    # Columns, not ORM objects. Hydrating 4,000 AlertGraphEntity instances and
    # 3,000 AlertGraphEdge instances per case cost roughly 600ms of the 886ms
    # that case #61 took; the rows themselves are a cheap indexed read.
    entities = (
        await db.execute(
            select(
                AlertGraphEntity.run_id,
                AlertGraphEntity.kind,
                AlertGraphEntity.merge_key,
                AlertGraphEntity.label,
                AlertGraphEntity.basis,
                AlertGraphEntity.attrs,
                AlertGraphEntity.event_time,
                AlertGraphEntity.source_severity,
            ).where(AlertGraphEntity.run_id.in_(run_ids))
        )
    ).all()
    edges = (
        await db.execute(
            select(
                AlertGraphEdge.run_id,
                AlertGraphEdge.kind,
                AlertGraphEdge.source_key,
                AlertGraphEdge.target_key,
                AlertGraphEdge.basis,
                AlertGraphEdge.attrs,
                AlertGraphEdge.event_time,
            ).where(AlertGraphEdge.run_id.in_(run_ids))
        )
    ).all()

    # Rebuild the per-alert view the assembler expects, so stored rows and a
    # live extraction go through exactly the same merge, inference and status
    # logic. Two code paths that merge differently would mean the CLI could
    # pass the acceptance checks while the page failed them.
    meta = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_name,
                AlertBodyInvestigationRun.graph_source_type,
                AlertBodyInvestigationRun.event_time,
                AlertBodyInvestigationRun.source_severity,
            ).where(AlertBodyInvestigationRun.id.in_(run_ids))
        )
    ).all()
    rules = {str(rid): (rule, name) for rid, rule, name, _s, _t, _l in meta}
    sources = {str(rid): source for rid, _r, _n, source, _t, _l in meta}

    from app.services.alert_graph_extraction_service import (
        MAPPED_DECODERS,
        Edge,
        Entity,
    )

    grouped: dict[str, Extracted] = {}
    stamps: dict[str, datetime | None] = {}
    levels: dict[str, int | None] = {}
    for run_id, kind, merge_key, label, basis, attrs, when, severity in entities:
        key = str(run_id)
        grouped.setdefault(key, Extracted()).entities.append(
            Entity(
                kind=kind, merge_key=merge_key, label=label,
                basis=basis, attrs=dict(attrs or {}),
            )
        )
        stamps.setdefault(key, when)
        levels.setdefault(key, severity)
    for run_id, kind, source_key, target_key, basis, attrs, when in edges:
        key = str(run_id)
        grouped.setdefault(key, Extracted()).edges.append(
            Edge(
                kind=kind, source=source_key, target=target_key,
                basis=basis, attrs=dict(attrs or {}),
            )
        )
        stamps.setdefault(key, when)

    # Every alert asked for, including the ones that yielded nothing. Leaving
    # those out is how an unreadable source becomes an unexplained blank.
    for rid, _rule, _name, _source, when, level in meta:
        key = str(rid)
        if key not in grouped:
            grouped[key] = Extracted()
            stamps.setdefault(key, when)
            levels.setdefault(key, level)

    # The stored rows carry no source type of their own, so a graph read from
    # the tables would report every source as unmapped — including
    # `windows_eventchannel`, which is the one this platform does read.
    for rid, _rule, _name, source, _when, _level in meta:
        key = str(rid)
        found = grouped.get(key)
        if found is None:
            continue
        found.source_type = source or "unknown"
        found.mapped = (source or "") in MAPPED_DECODERS

    evidence = [
        AlertEvidence(
            run_id=key,
            rule_id=rules.get(key, (None, None))[0],
            detection=rules.get(key, (None, None))[1],
            event_time=stamps.get(key),
            rule_level=levels.get(key),
            extracted=found,
            source_type=sources.get(key),
        )
        for key, found in grouped.items()
    ]
    graph = assemble(evidence)
    graph["coverage"] = {
        "alerts_read": len(run_ids),
        "alerts_dropped": dropped_alerts,
        "entity_rows_read": rows_read,
        "ranked_by": "the severity each alert's own source states",
        "note": (
            f"Drawn from the {len(run_ids)} most severe of "
            f"{len(run_ids) + dropped_alerts} alerts in this case, ranked on "
            "the severity each alert's own source states; "
            f"{dropped_alerts} were not read."
        ) if dropped_alerts else None,
    }
    return graph


async def pivots_for(
    db: AsyncSession, merge_keys: Iterable[str], *, exclude_runs: Sequence[Any] = ()
) -> dict[str, int]:
    """How many other alerts touched each of these entities.

    A count, not a list of ids. Returning the ids cost 249 ms on case #71,
    because `host:windows-test-device` appears in 3,375 rows and every one of
    them came back over the wire to be measured with `len()`. Counting in the
    database puts it back inside the 200 ms the pivot lookup is budgeted.

    Stops at alerts deliberately: case membership is derived, so joining to it
    here would drag correlation — 270 to 1,108 ms per case — into a lookup
    that has to stay cheap.
    """
    keys = [k for k in dict.fromkeys(merge_keys) if k]
    if not keys:
        return {}
    query = (
        select(AlertGraphEntity.merge_key, func.count(AlertGraphEntity.run_id.distinct()))
        .where(AlertGraphEntity.merge_key.in_(keys))
        .group_by(AlertGraphEntity.merge_key)
    )
    if exclude_runs:
        query = query.where(AlertGraphEntity.run_id.notin_(exclude_runs))
    return {key: int(count) for key, count in (await db.execute(query)).all()}
