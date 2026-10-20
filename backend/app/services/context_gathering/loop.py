"""The gathering loop: playbook, then one agent hop, inside a budget.

    playbook (no model)  ->  agent (depth 1)  ->  record  ->  purge

**The order is the design note's and it is load-bearing.** The playbook runs
first and its results are what the agent sees; an agent asked to plan from
nothing would re-derive the 81% a fixed table already covers, at a model call
each.

**Everything the agent touches is tokenised.** Results reach it through
`TokenBoundary.tokenize_records`, it emits template arguments as tokens, and
`detokenize_query` turns them back **locally, immediately before execution**.
The real hostname exists on one side of that call and nowhere else — not in
the record, not in anything the agent reads, not in a log line.

**The agent cannot name a source.** It picks a template; the template declares
a source *kind*; the tenant's entry in the client source map decides which
platform answers. A component that could name a source could name another
tenant's.

**A source that could not be read is `check_failed` with its name.** Never an
empty result. The DNS collector reported an outage as "no DNS records" across
2,602 runs by merging those two, and this is the same shape one layer up.

**The loop owns the investigation lifecycle**, so it purges the token map when
it finishes — the completion purge that `purge_expired`'s 24-hour ceiling
exists as a backstop for.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from app.services import token_boundary as tb
from app.services.absence import CHECK_FAILED, absent
from app.services.context_gathering import playbook as pb

logger = logging.getLogger(__name__)

#: How many DISTINCT `(source, template, arguments)` a single investigation
#: may run. Distinct, not total: a retry storm against a slow platform is also
#: a runaway loop, and a count of calls would not see it.
#:
#: 12 is `calibrated_on_self` — the largest playbook row costs 4 and a depth-1
#: hop can add a few more, so it is room to breathe rather than a measurement.
#: The real number comes from a lab corpus.
DEFAULT_MAX_QUERIES = 12

#: Wall clock for the whole stage. Well under the task's 1740s soft limit,
#: because this is one stage of a run and not the run.
DEFAULT_DEADLINE_SECONDS = 120.0

#: Stop when the record holds this many events across this many sources. The
#: design note prefers a rule to a judgement here, and the model only decides
#: inside the envelope.
DEFAULT_ENOUGH_EVENTS = 8
DEFAULT_ENOUGH_SOURCES = 2

#: How many pivots a single hop may take. A hash on 113 hosts is one query,
#: not 113 — the fan-out cap, applied to the agent's selections rather than
#: trusted to the agent.
DEFAULT_MAX_PIVOTS = 3


@dataclass
class Budget:
    """What this investigation may spend, and what it has spent.

    Both limits are configurable and both are recorded, because a budget that
    is not reported is a budget nobody can calibrate.
    """

    max_queries: int = DEFAULT_MAX_QUERIES
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    enough_events: int = DEFAULT_ENOUGH_EVENTS
    enough_sources: int = DEFAULT_ENOUGH_SOURCES
    max_pivots: int = DEFAULT_MAX_PIVOTS

    started_at: float = field(default_factory=time.monotonic)
    #: The distinct query signatures run so far.
    spent: set[tuple[str, str, str]] = field(default_factory=set)
    #: Why the loop stopped. Always set by the time a record is returned.
    stop_reason: str = ""

    @property
    def queries_run(self) -> int:
        return len(self.spent)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def exhausted(self) -> str:
        """The budget's own reason to stop, or "" if there is room left."""
        if self.queries_run >= self.max_queries:
            return f"query ceiling reached ({self.max_queries})"
        if self.elapsed >= self.deadline_seconds:
            return f"wall clock reached ({self.deadline_seconds:.0f}s)"
        return ""

    def would_repeat(self, signature: tuple[str, str, str]) -> bool:
        return signature in self.spent

    def charge(self, signature: tuple[str, str, str]) -> None:
        self.spent.add(signature)


@dataclass
class QueryOutcome:
    """One query, as the record holds it. Tokenised."""

    source: str
    source_kind: str
    template: str
    #: Why this was asked, in words — the template's purpose, so a reader sees
    #: the question and not a template id.
    purpose: str
    #: The arguments as TOKENS. A real hostname never enters the record.
    arguments: dict[str, str]
    #: `playbook` or `agent`, so the two can be costed separately.
    origin: str
    status: str                      # collected | empty | check_failed | skipped
    events: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    kept: int = 0
    absence: dict[str, Any] | None = None

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source": self.source,
            "source_kind": self.source_kind,
            "template": self.template,
            "purpose": self.purpose,
            "arguments": dict(self.arguments),
            "origin": self.origin,
            "status": self.status,
            "events_returned": len(self.events),
            "events_kept": self.kept,
        }
        if self.reason:
            out["reason"] = self.reason
        if self.absence is not None:
            out["absence"] = self.absence
        return out


@dataclass
class GatheringRecord:
    """What was queried, why, what came back, what was kept. All tokenised.

    This is what the analysis stage consumes, so it is the thing that has to
    be honest: a query that could not run appears here with its source named
    and an absence attached, never as a query that returned nothing.
    """

    tenant_id: str
    investigation_id: str
    event_class: str
    outcomes: list[QueryOutcome] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    budget: Budget | None = None

    def sources_answering(self) -> set[str]:
        return {o.source for o in self.outcomes if o.status == "collected"}

    def as_json(self) -> dict[str, Any]:
        budget = self.budget or Budget()
        playbook_calls = sum(1 for o in self.outcomes if o.origin == "playbook")
        agent_calls = sum(1 for o in self.outcomes if o.origin == "agent")
        failed = [o for o in self.outcomes if o.status == "check_failed"]
        return {
            "tenant_id": self.tenant_id,
            "investigation_id": self.investigation_id,
            "event_class": self.event_class or None,
            "queries": [o.as_json() for o in self.outcomes],
            "skipped": list(self.skipped),
            "notes": list(self.notes),
            "events": list(self.events),
            "cost": {
                "queries_run": budget.queries_run,
                "playbook_queries": playbook_calls,
                "agent_queries": agent_calls,
                "max_queries": budget.max_queries,
                "elapsed_seconds": round(budget.elapsed, 3),
                "deadline_seconds": budget.deadline_seconds,
                "stop_reason": budget.stop_reason,
            },
            "coverage": {
                "events_kept": len(self.events),
                "sources_answering": sorted(self.sources_answering()),
                # Named, never counted. "2 sources failed" beside "late: []"
                # is how a number drifts upward with nobody noticing.
                "sources_failed": sorted({o.source for o in failed}),
            },
        }


def _signature(source: str, template: str, arguments: Mapping[str, str]) -> tuple[str, str, str]:
    """What makes a query distinct. Arguments included, sorted, so the same
    template on two hosts is two queries and the same one twice is one."""
    rendered = ",".join(f"{k}={arguments[k]}" for k in sorted(arguments))
    return (source, template, rendered)


def _resolve(kind: str, registry: Mapping[str, Any]) -> Any | None:
    """Which source answers this kind, for this tenant.

    The registry stands in for the client source map: in production it is
    built from `client_sources.sources_for(tenant_id, scope=...)`, so the map
    decides where a template goes and the agent never does.
    """
    return registry.get(kind)


def _run_one(
    *,
    boundary: tb.TokenBoundary,
    registry: Mapping[str, Any],
    template: pb.QueryTemplate,
    token_arguments: Mapping[str, str],
    origin: str,
    budget: Budget,
) -> QueryOutcome | None:
    """One query, from tokens to tokenised events. `None` if it was not run."""
    source = _resolve(template.source_kind, registry)
    if source is None:
        return QueryOutcome(
            source=f"<no {template.source_kind} source>",
            source_kind=template.source_kind,
            template=template.name, purpose=template.purpose,
            arguments=dict(token_arguments), origin=origin,
            status="check_failed",
            reason=(
                f"this tenant's source map has no {template.source_kind} "
                f"platform, so the query was never sent"
            ),
            absence=absent(
                CHECK_FAILED,
                f"No {template.source_kind} source is configured for this "
                f"tenant, so {template.name} could not run.",
                raw=template.source_kind,
            ).as_json(),
        )

    signature = _signature(source.name, template.name, token_arguments)
    if budget.would_repeat(signature):
        return None
    stop = budget.exhausted()
    if stop:
        budget.stop_reason = stop
        return None
    budget.charge(signature)

    # **The boundary, at the last possible moment.** Tokens go in, real values
    # come out, the call is made, and the real values are not retained. An
    # invented or foreign token is a refusal here rather than a query against
    # the wrong estate.
    try:
        resolved = {
            name: boundary.detokenize_query(token).text
            for name, token in token_arguments.items()
        }
    except tb.TokenBoundaryError as exc:
        return QueryOutcome(
            source=source.name, source_kind=template.source_kind,
            template=template.name, purpose=template.purpose,
            arguments=dict(token_arguments), origin=origin,
            status="check_failed",
            reason=f"the query could not be resolved: {type(exc).__name__}",
            absence=absent(
                CHECK_FAILED,
                f"A token in this query did not resolve, so {template.name} "
                f"was not sent to {source.name}.",
                raw=template.name,
            ).as_json(),
        )

    try:
        raw_events = source.query(template.name, resolved)
    except Exception as exc:  # noqa: BLE001 - every source failure is this
        # Named, not counted, and never an empty result.
        return QueryOutcome(
            source=source.name, source_kind=template.source_kind,
            template=template.name, purpose=template.purpose,
            arguments=dict(token_arguments), origin=origin,
            status="check_failed",
            reason=f"{source.name} could not be read ({type(exc).__name__})",
            absence=absent(
                CHECK_FAILED,
                f"{source.name} could not be read, so what it holds about "
                f"this is unknown — not absent.",
                raw=source.name,
            ).as_json(),
        )

    tokenised = _blind_opaque_fields(boundary.tokenize_records(raw_events))
    return QueryOutcome(
        source=source.name, source_kind=template.source_kind,
        template=template.name, purpose=template.purpose,
        arguments=dict(token_arguments), origin=origin,
        status="collected" if tokenised else "empty",
        events=tokenised,
        reason="" if tokenised else "the source answered with no matching events",
    )


def gather(
    *,
    tenant_id: str,
    investigation_id: str,
    alert_fields: Mapping[str, Any],
    selectors: Mapping[str, str],
    registry: Mapping[str, Any],
    boundary: tb.TokenBoundary | None = None,
    budget: Budget | None = None,
    agent: Callable[..., Sequence[Any]] | None = None,
    db: Any = None,
) -> GatheringRecord:
    """Run the stage for one alert and return the record.

    `selectors` are the join keys in **real** values — the host, the user, the
    hash the alert carried. They are tokenised here, once, and every later
    stage sees tokens only.

    `db` is optional: with one, the token map is purged on completion through
    `purge_investigation`; without one, the in-memory boundary dies with the
    call and there is nothing to purge.
    """
    from app.services.context_gathering.agent import default_agent

    budget = budget or Budget()
    boundary = boundary or tb.in_memory(
        tenant_id=tenant_id, investigation_id=investigation_id
    )
    agent = agent or default_agent

    event_class = pb.event_class_of(alert_fields)
    record = GatheringRecord(
        tenant_id=tenant_id, investigation_id=investigation_id,
        event_class=event_class, budget=budget,
    )

    token_selectors = _tokenise_selectors(boundary, selectors)

    try:
        templates, skipped = pb.templates_for(event_class, token_selectors)
        record.skipped.extend(skipped)
    except pb.NoPlaybookRow:
        templates = ()
        record.notes.append(
            f"no_playbook: no fixed row for event class "
            f"{event_class or '(absent)'}; the agent selects from the same "
            f"template set"
        )

    for template in templates:
        arguments = {s: token_selectors[s] for s in template.selectors}
        outcome = _run_one(
            boundary=boundary, registry=registry, template=template,
            token_arguments=arguments, origin="playbook", budget=budget,
        )
        if outcome is None:
            break
        record.outcomes.append(outcome)
        _keep(record, outcome)

    # ── the one hop ──
    #
    # The agent sees what the playbook gathered, in tokens, and decides what
    # is still missing. Depth 1: a pivot's own results are never pivoted on,
    # which is enforced here by not calling it twice rather than by asking it
    # to stop.
    if not budget.stop_reason:
        reason = _enough(record, budget)
        if reason:
            budget.stop_reason = reason
        else:
            selections = agent(
                record=record,
                selectors=token_selectors,
                budget=budget,
            )
            # A cold start (no playbook row ran) selects from the alert's own
            # keys, so the `pivotable` restriction does not apply to it: that
            # restriction exists to bound pivots onto evidence the alert did
            # not carry. Decided from what the record holds, not from a flag
            # the agent sets, so an agent cannot declare its way past it.
            cold_start = not record.outcomes
            cap = budget.max_queries if cold_start else budget.max_pivots
            for selection in list(selections)[:cap]:
                template = pb.TEMPLATES.get(selection.template)
                if template is None:
                    record.notes.append(
                        f"agent selected {selection.template!r}, which is not "
                        f"a known template; refused"
                    )
                    continue
                if not cold_start and not template.pivotable:
                    record.notes.append(
                        f"agent selected {selection.template!r} as a pivot, "
                        f"which is not a pivotable template; refused"
                    )
                    continue
                outcome = _run_one(
                    boundary=boundary, registry=registry, template=template,
                    token_arguments=selection.arguments, origin="agent",
                    budget=budget,
                )
                if outcome is None:
                    break
                outcome.reason = outcome.reason or selection.because
                record.outcomes.append(outcome)
                _keep(record, outcome)

    if not budget.stop_reason:
        budget.stop_reason = _enough(record, budget) or "nothing further to ask"

    # ── the loop owns the lifecycle, so it purges ──
    if db is not None:
        try:
            result = tb.purge_investigation(
                db, tenant_id=tenant_id, investigation_id=investigation_id
            )
            record.notes.append(
                f"token map purged on completion ({result.deleted} row(s))"
            )
        except Exception as exc:  # noqa: BLE001
            # A purge failure must not fail the investigation — the 24-hour
            # ceiling sweep is the backstop and will catch it, loudly.
            logger.warning(
                "[gathering] token map purge failed for %s/%s: %s",
                tenant_id, investigation_id, type(exc).__name__,
            )
            record.notes.append(
                "token map purge failed; the ceiling sweep will catch it"
            )
    return record


#: Event fields that are OPAQUE identifiers: read for equality, never for
#: content.
#:
#: A vendor builds these out of whatever it has, and what it has includes the
#: hostname — the mock's `key` is `EXPDC001:10:0`, which is representative
#: rather than careless. No detector recognises a hostname inside a composite
#: key, because there is no key beside it to recognise it by, so three real
#: hostnames reached the record through this field while `agent.name` and
#: `full_log` beside them were correctly tokenised.
#:
#: Digested rather than tokenised. A token would be wrong: these are not
#: identifiers of anything in the estate, they are the vendor's row numbers,
#: and the only thing anything downstream does with them is compare them for
#: equality. A stable digest preserves that exactly and carries nothing.
OPAQUE_FIELDS = ("key", "id")


def _opaque(value: str) -> str:
    """A stable, meaningless stand-in for a vendor's row identifier."""
    import hashlib

    text = str(value or "")
    if not text:
        return text
    return "ev-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _blind_opaque_fields(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace composite row identifiers with digests of themselves."""
    for event in events:
        for field_name in OPAQUE_FIELDS:
            if isinstance(event.get(field_name), str):
                event[field_name] = _opaque(event[field_name])
    return events


#: How a selector is tokenised: the class it is, where the class is known.
#:
#: **This is not decoration.** `tokenize()` reads prose and needs context —
#: `computer="FILESERVER"` is a host because of the key beside it, and a bare
#: `EXPDC001` is indistinguishable from an ordinary word. The first version
#: of this stage passed selectors through `tokenize()` and a real hostname
#: went straight into the record, which a test caught before anything ran for
#: real. A caller holding a join key knows what it is, and
#: `tokenize_value` is how it says so.
SELECTOR_KINDS = {"host": "HOST", "user": "ACCOUNT"}


def _tokenise_selectors(
    boundary: tb.TokenBoundary, selectors: Mapping[str, str]
) -> dict[str, str]:
    """The alert's join keys, through the boundary, once.

    Everything downstream — the playbook's arguments, the agent's view, the
    record — sees the output of this and never the input.

    Three groups, and the differences are deliberate:

    * `host` and `user` are declared, because their detectors are keyed and a
      bare value carries no key;
    * `ip` needs no declaration — an address looks like an address — so the
      pattern pass finds it;
    * `hash`, `process` and `pipe` go through the pattern pass and mostly come
      back unchanged. A SHA-256 identifies a binary the whole industry can
      look up, not this customer's estate, and tokenising it would be the
      over-tokenisation that buys no safety and costs the analysis. A process
      path *can* carry an account — a users directory under a profile name —
      and the pattern pass is what catches that.
    """
    out: dict[str, str] = {}
    for name, value in selectors.items():
        if not value:
            continue
        kind = SELECTOR_KINDS.get(name)
        out[name] = (
            boundary.tokenize_value(value, kind) if kind
            else boundary.tokenize(value)
        )
    return out


def _keep(record: GatheringRecord, outcome: QueryOutcome) -> None:
    """Add an outcome's events to the record, without duplicating.

    Dedup on the event `key`, because the same event legitimately arrives
    from two templates — a process tree and a hash prevalence query both see
    the same execution — and counting it twice would inflate every coverage
    number the stop rule reads.
    """
    seen = {e.get("key") for e in record.events}
    kept = 0
    for event in outcome.events:
        key = event.get("key")
        if key in seen:
            continue
        seen.add(key)
        record.events.append(event)
        kept += 1
    outcome.kept = kept


def _enough(record: GatheringRecord, budget: Budget) -> str:
    """The stop rule, as a rule rather than a judgement."""
    if (len(record.events) >= budget.enough_events
            and len(record.sources_answering()) >= budget.enough_sources):
        return (
            f"enough gathered ({len(record.events)} events across "
            f"{len(record.sources_answering())} sources)"
        )
    return ""
