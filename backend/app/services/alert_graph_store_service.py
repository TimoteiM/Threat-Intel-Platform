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
    rule_level: int | None,
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
        alert_body, rule_level=rule_level,
        confirmed_techniques=confirmed_ids(assessment),
        log_events=log_events or (),
    )
    # Remembered on the run, so a case with no extractable alerts can name the
    # source it could not read without re-parsing every body to find out.
    await db.execute(
        update(AlertBodyInvestigationRun)
        .where(AlertBodyInvestigationRun.id == run_id)
        .values(graph_source_type=found.source_type[:64])
    )
    await db.execute(delete(AlertGraphEntity).where(AlertGraphEntity.run_id == run_id))
    await db.execute(delete(AlertGraphEdge).where(AlertGraphEdge.run_id == run_id))
    for entity in found.entities:
        db.add(
            AlertGraphEntity(
                run_id=run_id, kind=entity.kind, merge_key=entity.merge_key[:512],
                label=(entity.label or "?")[:255], basis=entity.basis,
                attrs=entity.attrs, event_time=event_time, rule_level=rule_level,
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


#: How many of a case's alerts the graph will read. Measured on the two worst
#: cases in this estate: #61 carries 2,818 alerts and #71 carries 2,154, which
#: are host-wide buckets rather than incidents — an artefact of membership
#: being derived from a time window. Reading all of #61 took 1,105 ms against
#: a 400 ms budget and produced 180 nodes against a 150 cap. Bounded at 300,
#: #61 comes in under both, and the payload says what was left out: a graph
#: that silently dropped 2,500 alerts reads as the whole picture.
MAX_ALERTS_PER_GRAPH = 300


async def graph_for_runs(
    db: AsyncSession,
    run_ids: Sequence[Any],
    *,
    max_alerts: int = MAX_ALERTS_PER_GRAPH,
) -> dict[str, Any]:
    """Assemble a graph from the stored rows of these alerts.

    This is the join the brief asked for: indexed selects and an in-memory
    merge, with no alert body read and no regex run.
    """
    if not run_ids:
        return assemble([])

    considered = list(run_ids)
    dropped_alerts = 0
    if len(considered) > max_alerts:
        # Keep the alerts most likely to carry the attack: worst rule level
        # first, then most recent. A severity-blind truncation would keep 300
        # routine level-3 events and drop the level-15 one the case is about.
        ranked = (
            await db.execute(
                select(AlertBodyInvestigationRun.id)
                .where(AlertBodyInvestigationRun.id.in_(considered))
                .order_by(
                    AlertBodyInvestigationRun.highest_risk_score.desc().nullslast(),
                    AlertBodyInvestigationRun.event_time.desc().nullslast(),
                )
                .limit(max_alerts)
            )
        ).scalars().all()
        dropped_alerts = len(considered) - len(ranked)
        considered = list(ranked)

    run_ids = considered
    entities = (
        await db.execute(
            select(AlertGraphEntity).where(AlertGraphEntity.run_id.in_(run_ids))
        )
    ).scalars().all()
    edges = (
        await db.execute(
            select(AlertGraphEdge).where(AlertGraphEdge.run_id.in_(run_ids))
        )
    ).scalars().all()

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
                AlertBodyInvestigationRun.highest_risk_score,
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
    for row in entities:
        key = str(row.run_id)
        grouped.setdefault(key, Extracted()).entities.append(
            Entity(
                kind=row.kind, merge_key=row.merge_key, label=row.label,
                basis=row.basis, attrs=dict(row.attrs or {}),
            )
        )
        stamps.setdefault(key, row.event_time)
        levels.setdefault(key, row.rule_level)
    for row in edges:
        key = str(row.run_id)
        grouped.setdefault(key, Extracted()).edges.append(
            Edge(
                kind=row.kind, source=row.source_key, target=row.target_key,
                basis=row.basis, attrs=dict(row.attrs or {}),
            )
        )
        stamps.setdefault(key, row.event_time)

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
        "note": (
            f"Drawn from the {len(run_ids)} most severe of "
            f"{len(run_ids) + dropped_alerts} alerts in this case; "
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
