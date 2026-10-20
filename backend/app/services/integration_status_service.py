"""Which tools each tenant has, and whether they are actually working.

The status model, and why it has five states
--------------------------------------------
**"Enabled" is the word that cost seven months.** ThreatFox was enabled,
configured, present in the collector registry, and returning HTTP 401 on
every single call for seven months. Every flag the platform had said
healthy. So nothing here is a boolean somebody set — every state is derived
from a fact that cannot be asserted into existence:

| state | derived from |
|---|---|
| `not_implemented` | no connector in `COLLECTOR_REGISTRY` declares this tool |
| `not_configured` | no `tenant_integrations` row for this tenant and tool |
| `configured_unverified` | a row exists, and nothing has ever made a real call |
| `verified_ok` | the last real authenticated call succeeded, at T |
| `verified_failing` | the last real authenticated call failed, at T, with a reason |

`configured_unverified` is the state that did not exist before and matters
most: a credential that has been saved and never exercised is not a working
integration, and the previous vocabulary had no way to say so.

Two directions, never one badge
-------------------------------
An integration that answers queries and has stopped delivering detections is
healthy by one measure and dead by the other. One status would show green
through exactly that, so `enrichment` and `ingest` are tracked independently
and a tool reports a state per direction it actually has. A tool that only
does enrichment reports only enrichment — it is not `not_configured` for a
direction it does not possess.

The catalogue is derived
------------------------
From `COLLECTOR_REGISTRY`, filtered to connectors that set
`integration = True`. There is no list of tool names anywhere, because a list
would be the ninth hand-maintained registry here and the eight before it each
swallowed a feature silently. `test_integration_catalogue.py` fails if a
hard-coded tool list appears.

Isolation is at the query layer
-------------------------------
Every read takes a `TenantScope` as a **required keyword** and goes through
`tenant_scope.apply`. Not a default of `None` meaning "no filter": a
parameter someone forgets to pass must never be the one that opens a read up.
A restricted scope with no tenants resolves to SQL `false`, not to an absent
filter — `test_integration_isolation.py` asserts a restricted principal sees
nothing, and that the test fails if the restriction is removed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import tenant_scope
from app.services.absence import (
    NEVER_OBSERVED,
    OUT_OF_SCOPE,
    TOO_LITTLE_HISTORY,
    absent,
)

#: The five states. Ordered worst-known-first for a UI that sorts by concern;
#: `not_implemented` last because it is not a fault, it is an absence of
#: capability.
VERIFIED_FAILING = "verified_failing"
CONFIGURED_UNVERIFIED = "configured_unverified"
NOT_CONFIGURED = "not_configured"
VERIFIED_OK = "verified_ok"
NOT_IMPLEMENTED = "not_implemented"

#: Worked before, and is not working now. **The state the defect removes.**
#:
#: `verified_failing` catches "configured but unusable". It does not catch a
#: configuration that *vanished*: SIEM log enrichment stopped on 2026-10-12
#: because `OPENSEARCH_TENANT_VALUES` went empty, which makes the integration
#: read as `not_configured` — and on a page listing unconfigured tools that is
#: invisible. Two days passed.
#:
#: So the distinguishing fact goes beside the status. It was already stored:
#: `alert_log_context` rows up to 2026-10-12 and none after. A tool that is
#: not working **and has a last success** is an incident; one that never
#: worked is an absence. First in STATES because the overall badge is the
#: worst direction by this index, and a stopped direction must not hide behind
#: a healthy one.
STOPPED = "stopped"

STATES = (
    STOPPED,
    VERIFIED_FAILING,
    CONFIGURED_UNVERIFIED,
    NOT_CONFIGURED,
    VERIFIED_OK,
    NOT_IMPLEMENTED,
)


#: What established a `verified_ok`. Named constants rather than a boolean,
#: the same shape as a technique carrying `RULE_CONFIRMED` against
#: `RULE_ONLY`: the state says it works, the warrant says how that is known.
#:
#: These are **different claims and are never conflated.** `api_ping` proves
#: the api process can reach the service; `collector_output` proves the
#: collection path produced a result from the worker. On 2026-10-14 a green
#: api ping sat beside a worker that had no configuration at all, which is
#: exactly why the card must render which one it has.
WARRANT_API_PING = "api_ping"
WARRANT_COLLECTOR_OUTPUT = "collector_output"

_WARRANT_META = {
    WARRANT_API_PING: (
        "api",
        "An authenticated ping from the api process succeeded. This does "
        "not establish that the worker — which runs the collection — can "
        "reach the service, because the two read their environments "
        "separately.",
    ),
    WARRANT_COLLECTOR_OUTPUT: (
        "worker",
        "The collector produced output: a real authenticated query that "
        "succeeded end to end, from the worker process that does the work.",
    ),
}


def warrant_for(
    kind: str, *, at: Any, now: Any = None, current: Any = None
) -> dict[str, Any]:
    """What the `verified_ok` rests on, with its age.

    The age is part of the warrant rather than beside it, because every one
    of these is a claim about a moment in the past.
    """
    from datetime import datetime, timezone

    process, what = _WARRANT_META.get(kind, ("unknown", "Unrecorded basis."))
    reference = now or datetime.now(timezone.utc)
    age = None
    if at is not None:
        age = round(max(0.0, (reference - at).total_seconds() / 3600.0), 1)
    return {
        "kind": kind,
        "process": process,
        "what": what,
        "at": None if at is None else at.isoformat(),
        "age_hours": age,
        # Whether this warrant is still current, as a field rather than as a
        # sentence. The 6–18h band keeps its base state, and that state is
        # the same value a never-produced integration carries — so without
        # this a consumer reading `state` alone (the all-customers matrix,
        # for one) could not tell "collected 7h ago" from "never collected",
        # and the collapse would have moved to the render layer instead of
        # closing. Stale collector output is still collector output.
        "current": None if current is None else bool(current),
    }


#: States that collection evidence may promote to `verified_ok`. A verified
#: FAILURE is deliberately absent: that is evidence about now, and output
#: from the past does not clear a present failure.
_PROMOTABLE = frozenset({NOT_CONFIGURED, CONFIGURED_UNVERIFIED})


#: States in which a last success means the tool has STOPPED rather than
#: merely being absent. `not_implemented` is excluded deliberately: no
#: connector exists, so there is nothing that could have stopped.
_CAN_HAVE_STOPPED = frozenset({
    NOT_CONFIGURED, VERIFIED_FAILING, CONFIGURED_UNVERIFIED,
})


#: How much longer than its own expectation an integration must be silent
#: before this calls it stopped. 3x, so ordinary jitter in alert arrival does
#: not produce an outage: the log store produces a row per analysed alert, and
#: alerts do not arrive on a schedule.
SILENCE_MULTIPLIER = 3.0


def continuity(
    *,
    state: str,
    last_succeeded_at: Any = None,
    now: Any = None,
    expected_interval_hours: float | None = None,
    #: Which warrant `last_succeeded_at` is evidence of, and therefore which
    #: consumer it speaks for. Defaults to collector output because that is
    #: what `last_success_for` returns for every tool today. Passing the
    #: wrong one here is the error this parameter exists to make visible:
    #: promoting an on-demand api path on the worker's collection evidence
    #: claims a consumer was witnessed that nothing witnessed.
    warrant_kind: str = WARRANT_COLLECTOR_OUTPUT,
    #: Which direction this verdict is about, carried through to the output so
    #: a reader of one entry knows which consumer it describes.
    direction: str | None = None,
) -> dict[str, Any]:
    """Split "never worked" from "worked until Monday".

    Returns the state possibly upgraded to `stopped`, plus how long it has
    been silent, plus `last_success` as a value or a named absence — never as
    a zero date, because a rendered epoch reads as a measurement.
    """
    from datetime import datetime, timezone

    at = now or datetime.now(timezone.utc)
    if last_succeeded_at is None:
        return {
            "state": state,
            "stopped": False,
            "silent_for_hours": None,
            "expected_interval_hours": expected_interval_hours,
            "direction": direction,
            "warrant_kind": warrant_kind,
            "threshold_hours": None,
            "silence_verdict": None,
            "promoted": False,
            "warrant": None,
            "warrants": [],
            "compound": False,
            "compound_note": None,
            "badge_qualifier": None,
            "last_success": absent(
                NEVER_OBSERVED,
                "This integration has never produced a result, so there is "
                "nothing it could have stopped doing. Absence of "
                "configuration, not an outage.",
            ).as_json(),
        }

    delta = at - last_succeeded_at
    # Clamped at zero: clock skew must not make a stopped tool look recent,
    # and a negative duration would sort as the freshest thing on the page.
    hours = max(0.0, delta.total_seconds() / 3600.0)

    # `stopped` requires actual SILENCE, not merely a state that is not
    # verified_ok. The first version asserted stopped as soon as a last
    # success existed, which put STOPPED ("an outage") directly above "silent
    # 0.2h" on the log-store card — twelve minutes reported as an outage. Both
    # numbers were right; the model joining them was wrong, and a badge that
    # goes red while the thing works is the cry-wolf failure the
    # source-coverage work already paid for once.
    threshold = (
        None if expected_interval_hours is None
        else float(expected_interval_hours) * SILENCE_MULTIPLIER
    )
    promoted = False
    warrant: Any = None

    if threshold is None:
        # No declared expectation, so no claim. Guessing an interval would
        # invent outages, and "I do not know how often this should produce"
        # is an absence rather than a verdict of healthy.
        silence_verdict: Any = absent(
            TOO_LITTLE_HISTORY,
            "This integration does not declare how often it should produce a "
            "result, so whether this silence is an outage cannot be judged "
            "from it. The last success date is reported; the verdict is not.",
        ).as_json()
        stopped = False
    else:
        stopped = state in _CAN_HAVE_STOPPED and hours > threshold
        # Which threshold promotes: the DECLARED EXPECTATION, not the flag.
        #
        # Inside the expectation, silence is normal and the last success is
        # current evidence that the path works — so it is promoted, with its
        # warrant. Past the expectation we no longer have current evidence,
        # and `verified_ok` must not stretch to cover the band between the
        # expectation and the flag: a feed silent 17h rendering green is the
        # same collapse this whole state model exists to prevent, one level
        # in. The band keeps the base state and says it is overdue, which is
        # honest — not currently witnessed, not yet an outage.
        within_expectation = hours <= float(expected_interval_hours)
        promoted = within_expectation and state in _PROMOTABLE
        # Attached whether or not it promotes. A stale warrant is still a
        # warrant, and `current` carries which it is.
        warrant = warrant_for(
            warrant_kind, at=last_succeeded_at, now=at,
            current=within_expectation,
        )
        if promoted:
            silence_verdict = (
                f"Produced output {round(hours, 1)}h ago, inside its "
                f"{expected_interval_hours}h expectation."
            )
        elif not stopped and not within_expectation:
            silence_verdict = (
                f"OVERDUE: silent {round(hours, 1)}h against an expected "
                f"{expected_interval_hours}h, short of the "
                f"{round(threshold, 1)}h outage threshold. Not currently "
                f"witnessed working, and not yet an outage."
            )
        else:
            silence_verdict = (
                f"Silent {round(hours, 1)}h against an expected "
                f"{expected_interval_hours}h (flagged beyond "
                f"{round(threshold, 1)}h)."
            )

    resolved = STOPPED if stopped else (VERIFIED_OK if promoted else state)

    # Every warrant, not a winner. Precedence between an api ping and
    # collector output would make them commensurable again — the opposite of
    # why they are named separately — and a 09:00 ping failure outranking
    # output at 09:05 hides a real compound condition: the api cannot reach
    # the cluster, log context still flows, and the on-demand estate lookup
    # breaks the day it is wired.
    #
    # The badge still shows the worse CONSUMER condition, which is a product
    # decision about consumers rather than a claim that api evidence beats
    # worker evidence. Separating them properly needs the two direction
    # states in backlog 18; until then the compound is stated beside the
    # badge so nothing is hidden.
    warrants = [w for w in (warrant,) if w]
    compound = bool(warrant) and state in (VERIFIED_FAILING,)
    compound_note = None
    # Which consumer the badge is about. `FAILING` alone reads as "the log
    # store is down"; beside a live collector that is the misread to prevent,
    # so the badge names the failing consumer — FAILING (api). The failing
    # evidence is always the api-side verification here, since the collector
    # warrant is what makes it compound in the first place.
    badge_qualifier = "api" if compound else None
    if compound:
        compound_note = (
            f"Compound condition: the api-side check is failing while the "
            f"collector produced output {round(hours, 1)}h ago. Both are true "
            f"and they describe different consumers — log context can keep "
            f"flowing while an on-demand api lookup fails."
        )
    return {
        "state": resolved,
        "stopped": stopped,
        "promoted": promoted,
        "warrant": warrant,
        "warrants": warrants,
        "compound": compound,
        "compound_note": compound_note,
        "badge_qualifier": badge_qualifier,
        "silent_for_hours": round(hours, 1),
        "expected_interval_hours": expected_interval_hours,
        "direction": direction,
        "warrant_kind": warrant_kind,
        "threshold_hours": None if threshold is None else round(threshold, 1),
        "silence_verdict": silence_verdict,
        "last_success": last_succeeded_at.isoformat(),
        "note": (
            f"Last produced a result {round(hours, 1)}h ago, past the "
            f"{round(threshold, 1)}h this integration should never exceed. It "
            f"worked before, so this is an outage and not an absence of "
            f"configuration."
        ) if stopped else None,
    }

#: States in which this tool is not known to be working. Deliberately
#: includes `configured_unverified`: a saved credential nobody has exercised
#: is not a working integration, and the whole point of the fifth state is
#: that it must not read as the fourth.
NOT_WORKING = frozenset({VERIFIED_FAILING, CONFIGURED_UNVERIFIED,
                         NOT_CONFIGURED, NOT_IMPLEMENTED})

ENRICHMENT = "enrichment"
INGEST = "ingest"

#: A consumer that queries only when a person asks. Added when the estate
#: lookup got an API route (2026-10-15), which expired the argument that let
#: the log store report one direction.
#:
#: That argument was a *superset* claim: collection evidence proved more than
#: an api ping could, because no api-side code queried the cluster at all —
#: the only api contact was `ping()` in the health endpoint. The estate DNS
#: route broke it. Now the worker's collection and an analyst's on-demand
#: lookup are two consumers of one cluster with different failure modes, and
#: the worker can be answering while the analyst's lookup fails: different
#: process, different credentials path, different network position.
#:
#: Unlike `enrichment` this direction declares **no interval**. An analyst
#: triggers it or nobody does, so elapsed silence is not evidence of
#: anything — the same shape as Falcon's, and the reason backlog 18 argues a
#: conditional expectation rather than a number. Its witness is therefore the
#: api-side verification alone, and collector output must never promote it.
ON_DEMAND = "on_demand"

DIRECTIONS = (ENRICHMENT, INGEST, ON_DEMAND)


@dataclass(frozen=True)
class ToolSpec:
    """One implemented integration, as the code declares it."""

    tool: str
    label: str
    directions: tuple[str, ...]
    #: `edr` | `firewall` | `email` | ... — see CollectorBase. Grouping key
    #: for the page, derived from the connector's own declaration.
    category: str = "other"
    #: Where this integration's configuration lives.
    #:
    #: `credential_store` — a per-tenant `tenant_integrations` row, written
    #: through the API, verified by opening the stored secret.
    #: `deployment` — the deployment's own environment, read-only from the
    #: API. The log store is this: its config is the global `OPENSEARCH_*`
    #: values, there is no row to open, and "Test connection" returned HTTP
    #: 400 "not configured" because it asked the credential store about an
    #: integration that is not kept there. The UI uses this to decide whether
    #: to offer a form at all.
    managed: str = "credential_store"
    #: How often this integration should produce a result, in hours. Declared
    #: by the integration, because only it knows. `None` means "no claim",
    #: and `continuity()` then reports the last success without a verdict —
    #: a guessed interval invents outages.
    expected_interval_hours: float | None = None
    #: Per-direction overrides of the two facts that make a direction's state
    #: its own: how often it should produce, and which warrant may promote it.
    #:
    #: Empty means every direction shares the tool-level expectation, which is
    #: right for a tool whose directions have one consumer. It is wrong for
    #: the log store, where `enrichment` is produced by the worker on a
    #: measurable rhythm and `on_demand` only when an analyst asks. Letting
    #: the 6h expectation cover both would promote the on-demand path on
    #: evidence from the collection path — one warrant standing in for two
    #: consumers, which is the collapse `ON_DEMAND` exists to prevent.
    direction_expectations: dict[str, float | None] = field(default_factory=dict)
    #: Which `WARRANT_*` kind is admissible evidence for a direction.
    direction_warrants: dict[str, str] = field(default_factory=dict)
    config_fields: dict[str, str] = field(default_factory=dict)
    secret_fields: dict[str, str] = field(default_factory=dict)

    def expectation_for(self, direction: str) -> float | None:
        """This direction's interval. Indexed through a declared default.

        `.get(direction, self.expected_interval_hours)` rather than
        `.get(direction) or ...`: a direction that declares `None` means "no
        claim", and `or` would silently replace that refusal with the
        tool-level number — an absence read as a value, in the one place where
        the absence is the whole point.
        """
        if direction in self.direction_expectations:
            return self.direction_expectations[direction]
        return self.expected_interval_hours

    def warrant_for_direction(self, direction: str) -> str:
        return self.direction_warrants.get(direction, WARRANT_COLLECTOR_OUTPUT)

    def as_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "label": self.label,
            "category": self.category,
            "managed": self.managed,
            "expected_interval_hours": self.expected_interval_hours,
            "direction_expectations": {
                d: self.expectation_for(d) for d in self.directions
            },
            "direction_warrants": {
                d: self.warrant_for_direction(d) for d in self.directions
            },
            "directions": list(self.directions),
            "config_fields": dict(self.config_fields),
            # Names and descriptions only. A secret field is declared so the
            # UI can render an input; its value is never read back.
            "secret_fields": dict(self.secret_fields),
            # Whether code exists that can talk to this tool, as against
            # fields being declared for it. The UI needs the difference: a
            # platform with a spec and no connector can have its connection
            # details recorded, and cannot be tested. Offering "Save and test"
            # for one of those is what produced seven HTTP 400s against a
            # credential that had saved correctly every time.
            "implemented": has_connector(self.tool),
        }


#: Integrations that are not collectors, and so cannot declare themselves
#: through `COLLECTOR_REGISTRY`. Each module that owns one exposes an
#: `INTEGRATION_SPEC`, so the declaration lives beside the thing it describes
#: and this module carries no tool names, labels or categories of its own —
#: which is what the catalogue-derivation tests require.
_SPEC_MODULES = (
    "app.services.opensearch_tenants",
    # The per-client platforms (Exabeam, SentinelOne, Cortex), declared
    # together because they share a shape and a loader. They arrive through
    # `INTEGRATION_SPECS` (plural) below.
    "app.services.client_sources",
)


def _declared_elsewhere() -> dict[str, dict[str, Any]]:
    """`INTEGRATION_SPEC` or `INTEGRATION_SPECS` from every declaring module.

    Both forms, because one module can own several tools of the same shape —
    `client_sources` declares the three per-client platforms together, and
    splitting them into three near-empty modules to satisfy a singular name
    would be bookkeeping, not structure.
    """
    import importlib

    out: dict[str, dict[str, Any]] = {}
    for path in _SPEC_MODULES:
        module = importlib.import_module(path)
        spec = getattr(module, "INTEGRATION_SPEC", None)
        if isinstance(spec, dict) and spec.get("tool"):
            out[str(spec["tool"])] = spec
        for many in getattr(module, "INTEGRATION_SPECS", None) or ():
            if isinstance(many, dict) and many.get("tool"):
                out[str(many["tool"])] = many
    return out


def catalogue() -> dict[str, ToolSpec]:
    """Every implemented integration, derived rather than enumerated.

    Adding a connector that sets `integration = True` adds a tool here with
    nothing to update. Integrations that are not collectors come from
    `NON_COLLECTOR_INTEGRATIONS`, which declares the same fields.
    """
    from app.collectors.registry import COLLECTOR_REGISTRY

    out: dict[str, ToolSpec] = {}
    for name, decl in _declared_elsewhere().items():
        out[name] = ToolSpec(
            tool=name,
            label=str(decl["label"]),
            category=str(decl["category"]),
            managed=str(decl.get("managed") or "deployment"),
            expected_interval_hours=decl.get("expected_interval_hours"),
            direction_expectations=dict(
                decl.get("direction_expectations") or {}),
            direction_warrants=dict(decl.get("direction_warrants") or {}),
            directions=tuple(decl["directions"]),
            config_fields=dict(decl.get("config_fields") or {}),
            secret_fields=dict(decl.get("secret_fields") or {}),
        )
    for name, cls in sorted(COLLECTOR_REGISTRY.items()):
        if not getattr(cls, "integration", False):
            continue
        # Filtered against DIRECTIONS, not a literal pair. The literal was
        # `(ENRICHMENT, INGEST)`, so a collector declaring a direction added
        # later would have had it silently dropped — the ninth hand-maintained
        # list, in the one function whose job is to avoid having one.
        directions = tuple(
            d for d in getattr(cls, "integration_directions", ()) or ()
            if d in DIRECTIONS
        )
        out[name] = ToolSpec(
            tool=name,
            label=str(getattr(cls, "integration_label", "") or name),
            category=str(getattr(cls, "integration_category", "") or "other"),
            directions=directions or (ENRICHMENT,),
            config_fields=dict(getattr(cls, "integration_config_fields", {}) or {}),
            secret_fields=dict(getattr(cls, "integration_secret_fields", {}) or {}),
        )
    return out


def has_connector(tool: str) -> bool:
    """Whether code exists that can actually talk to this tool.

    Derived by import, like every other dispatch in this module — a list of
    implemented tools here would be the tenth hand-maintained registry, and a
    tool missing from it would be unconfigurable with nothing to say so.

    **A spec and a connector are different things**, which is what this
    function exists to separate. `client_sources` declares Exabeam,
    SentinelOne and Cortex so their connection fields have one definition and
    the credential store knows their shape; none of them has a client module
    yet. Before this existed, `not_implemented` meant "absent from the
    catalogue", so declaring a spec silently promoted a platform to
    configurable-and-testable, and "Save and test" answered HTTP 400 from an
    import error.
    """
    import importlib.util

    spec = catalogue().get(tool)
    if spec is None:
        return False
    if spec.managed == "deployment":
        return deployment_verifier_for(tool) is not None
    try:
        return importlib.util.find_spec(f"app.integrations.{tool}_client") is not None
    except (ImportError, ValueError):
        return False


def deployment_verifier_for(tool: str) -> Any:
    """The `verify` coroutine from the module that owns this integration.

    Resolved by import, like `last_success_for` and for the same reason: a
    `if tool == "opensearch"` here is the hand-maintained list wearing an
    if-statement, and this module's own source guard refuses it.
    """
    import importlib

    for path in _SPEC_MODULES:
        module = importlib.import_module(path)
        spec = getattr(module, "INTEGRATION_SPEC", None)
        if isinstance(spec, dict) and spec.get("tool") == tool:
            return getattr(module, "verify", None)
    return None


async def last_success_for(
    db: AsyncSession, tenant_id: str, tool: str, row: Any = None
) -> Any:
    """When this integration last actually produced something, or None.

    Derived from evidence the platform already stores, never from a flag, and
    **this module names no tool**: an integration that knows what its own
    evidence looks like exposes `last_success(db, tenant_id)` from the module
    that owns it. The first version of this branched on `tool == "opensearch"`
    and the catalogue's own source guard rejected it, correctly — that branch
    is the hand-listing the derivation rules exist to prevent.

    Returns None for "no evidence of ever having worked", which `continuity()`
    turns into a named absence rather than a date.
    """
    import importlib

    for path in _SPEC_MODULES:
        module = importlib.import_module(path)
        spec = getattr(module, "INTEGRATION_SPEC", None)
        resolver = getattr(module, "last_success", None)
        if isinstance(spec, dict) and spec.get("tool") == tool and resolver:
            return await resolver(db, tenant_id)

    # Everything else records its own verification outcomes on the row, keyed
    # by direction. The newest passing one is the last success.
    health = getattr(row, "health", None) or {}
    if not isinstance(health, dict):
        return None
    from datetime import datetime

    best = None
    for entry in health.values():
        if not isinstance(entry, dict) or entry.get("state") != VERIFIED_OK:
            continue
        stamp = entry.get("checked_at")
        if not stamp:
            continue
        try:
            when = datetime.fromisoformat(str(stamp))
        except ValueError:
            continue
        if best is None or when > best:
            best = when
    return best


def _state_for_direction(row: Any, direction: str) -> dict[str, Any]:
    """The state of one direction of one configured integration.

    `row` is a `TenantIntegration`. Called only when a row exists, so
    `not_configured` and `not_implemented` are decided above this.
    """
    health = row.health if isinstance(row.health, dict) else {}
    entry = health.get(direction)
    if not isinstance(entry, dict) or not entry.get("checked_at"):
        return {
            "state": CONFIGURED_UNVERIFIED,
            "checked_at": None,
            "reason": (
                "A credential is stored and no real call has ever been made "
                "with it. Saved is not working — run Test connection."
            ),
        }
    state = str(entry.get("state") or "").strip()
    if state not in (VERIFIED_OK, VERIFIED_FAILING):
        # An unrecognised stored state is not quietly read as healthy.
        return {
            "state": VERIFIED_FAILING,
            "checked_at": entry.get("checked_at"),
            "reason": (
                f"The last verification recorded a state this code does not "
                f"recognise ({state or 'missing'!r}), so it is not read as "
                "working."
            ),
            "failure_kind": "unrecognised",
        }
    out = {
        "state": state,
        "checked_at": entry.get("checked_at"),
        "reason": entry.get("reason"),
    }
    # A verified success says what proved it, the same way the log store's
    # promoted verified_ok does. Both cards then show one label and two
    # different warrants, which is the point: `api_ping` and
    # `collector_output` are different claims and neither is weakened into
    # the other. A FAILURE gets no warrant — there is nothing to justify,
    # and attaching one would read as partial credit.
    if state == VERIFIED_OK:
        from datetime import datetime

        at = None
        try:
            at = datetime.fromisoformat(str(entry.get("checked_at")))
        except (TypeError, ValueError):
            at = None
        out["warrant"] = warrant_for(WARRANT_API_PING, at=at)
    for extra in ("failure_kind", "token", "base_url"):
        if entry.get(extra) is not None:
            out[extra] = entry[extra]
    return out


def status_of(spec: ToolSpec | None, row: Any, tool: str) -> dict[str, Any]:
    """The full per-direction status of one tenant × tool.

    `spec is None` means no connector implements this tool — the state that
    is true of every EDR in this platform today, so the page has to render it
    sensibly rather than treat it as an error.
    """
    if spec is None:
        return {
            "tool": tool,
            "label": tool,
            "category": "other",
            "overall": NOT_IMPLEMENTED,
            "directions": {},
            "configured": False,
            "note": absent(
                OUT_OF_SCOPE,
                "No connector in this platform implements this tool, so it "
                "cannot be configured for any tenant. This is an absence of "
                "capability, not a fault.",
                raw=tool,
            ).as_json(),
        }

    # Deployment-managed: the verdict comes from the deployment, row or no
    # row. Branching on `row is None` meant a stray credential row — one a
    # real operator created through a form that should never have been
    # offered — flipped this back to credential-store rules and the false
    # claim that a credential is stored.
    if spec.managed == "deployment":
        # No `tenant_integrations` row, and there never will be: this
        # integration is configured from the deployment. Judging it by
        # credential rules produced `configured_unverified`, whose meaning is
        # "a credential is stored" — false by construction — and a footer
        # saying "no credential stored" two lines below it. Its state comes
        # from whether the deployment config is usable, which only its own
        # verifier can answer, so until one runs this is unverified *without*
        # claiming anything about a secret.
        per_direction = {
            d: {
                "state": CONFIGURED_UNVERIFIED,
                "checked_at": None,
                "reason": (
                    "Configured by the deployment (.env). No test call has "
                    "been made from this process yet — there is no stored "
                    "credential involved either way."
                ),
            }
            for d in spec.directions
        }
        return {
            "tool": spec.tool,
            "label": spec.label,
            "category": spec.category,
            "managed": spec.managed,
            "overall": CONFIGURED_UNVERIFIED,
            "directions": per_direction,
            "configured": True,
            # Explicitly absent rather than False: this integration has no
            # secret in the credential store, so "no credential stored" is
            # not a finding about it.
            "secret_set": None,
            # A row that exists and is never read. Surfaced rather than
            # ignored: somebody created it and believes they configured
            # something, and silence would leave them believing it.
            "stray_credential_row": None if row is None else {
                "configured_by": getattr(row, "configured_by", None),
                "config": getattr(row, "config", None),
                "note": (
                    "A credential-store row exists for this integration and "
                    "is NOT read — its configuration comes from the "
                    "deployment. Nothing here takes effect. It can be "
                    "removed; the form that wrote it should not have been "
                    "offered."
                ),
            },
        }

    if row is None:
        per_direction = {
            d: {
                "state": NOT_CONFIGURED,
                "checked_at": None,
                "reason": "No credential is stored for this tenant.",
            }
            for d in spec.directions
        }
        return {
            "tool": spec.tool,
            "label": spec.label,
            "category": spec.category,
            "overall": NOT_CONFIGURED,
            "directions": per_direction,
            "configured": False,
        }

    per_direction = {d: _state_for_direction(row, d) for d in spec.directions}
    # The overall badge is the worst direction, by the order in STATES. A
    # tool answering queries while delivering nothing must not read green.
    overall = min(
        (per_direction[d]["state"] for d in per_direction),
        key=lambda s: STATES.index(s) if s in STATES else 0,
        default=NOT_CONFIGURED,
    )
    return {
        "tool": spec.tool,
        "label": spec.label,
        "category": spec.category,
        "overall": overall,
        "directions": per_direction,
        "configured": True,
        "secret_set": bool(row.secret_ciphertext),
        "secret_set_at": row.secret_set_at.isoformat() if row.secret_set_at else None,
        # Non-secret config only. A test asserts no credential-shaped key
        # reaches this payload.
        "config": row.config if isinstance(row.config, dict) else {},
        "configured_by": row.configured_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _rows(db: AsyncSession, *, scope: tenant_scope.TenantScope,
                tenant_id: str | None = None) -> list[Any]:
    """Every integration row this scope may read.

    `scope` is a required keyword throughout this module. A default of `None`
    meaning "no filter" is how a scoped read quietly becomes an unscoped one,
    and this table holds credentials.
    """
    from app.models.database import TenantIntegration

    # The table carries a row-level policy; an unbound session reads zero rows
    # and this function would report every integration as unconfigured. It did
    # exactly that for a day after migration 072 — silently, which is why the
    # binding is here and not only on the write path. See migration 073.
    await tenant_scope.bind(db, scope)
    stmt = select(TenantIntegration)
    if tenant_id:
        stmt = stmt.where(TenantIntegration.tenant_id == tenant_id)
    stmt = tenant_scope.apply(stmt, TenantIntegration.tenant_id, scope)
    return list((await db.execute(stmt)).scalars().all())


def _continuity_per_direction(
    entry: dict[str, Any], spec: Any, last_succeeded_at: Any
) -> dict[str, Any]:
    """One continuity verdict per direction, for tools that need them.

    Returns `{}` for a tool whose directions share one consumer, so nothing
    changes for the other fifteen integrations. A tool opts in by declaring
    `direction_expectations` or `direction_warrants`.

    `last_succeeded_at` is passed to the direction whose admissible warrant it
    actually is, and withheld from the others. That withholding is the whole
    point: handing the worker's collection time to the on-demand direction
    would promote it to `verified_ok` on evidence about a different process,
    and the card would claim an analyst's lookup was witnessed working when
    nothing had run it.
    """
    directions = tuple(getattr(spec, "directions", ()) or ())
    if not directions:
        return {}
    if not (getattr(spec, "direction_expectations", None)
            or getattr(spec, "direction_warrants", None)):
        return {}

    base = entry.get("directions") or {}
    out: dict[str, Any] = {}
    for direction in directions:
        admissible = spec.warrant_for_direction(direction)
        # Today every `last_success_for` value is collector output. A
        # direction whose witness is something else has no evidence yet, and
        # `None` is the honest input — `continuity` turns it into
        # `never_observed` rather than a silence verdict.
        evidence = (last_succeeded_at
                    if admissible == WARRANT_COLLECTOR_OUTPUT else None)
        state = (base.get(direction) or {}).get("state") or entry["overall"]
        out[direction] = continuity(
            state=state, last_succeeded_at=evidence,
            expected_interval_hours=spec.expectation_for(direction),
            warrant_kind=admissible, direction=direction,
        )
    return out


async def for_tenant(
    db: AsyncSession, tenant_id: str, *, scope: tenant_scope.TenantScope
) -> dict[str, Any]:
    """The per-tenant card grid: every implemented tool, with its status."""
    tenant_scope.assert_can_read(scope, tenant_id)
    rows = {r.tool: r for r in await _rows(db, scope=scope, tenant_id=tenant_id)}
    cat = catalogue()

    tools = []
    for t in sorted(cat):
        entry = status_of(cat.get(t), rows.get(t), t)
        # The fact that splits "never worked" from "worked until Monday".
        # Attached to every tool, because the state it upgrades is
        # `not_configured` — the one a vanished configuration produces, and
        # the one that is invisible on a page of unconfigured tools.
        last = await last_success_for(db, tenant_id, t, rows.get(t))
        spec = cat.get(t)
        entry["continuity"] = continuity(
            state=entry["overall"], last_succeeded_at=last,
            expected_interval_hours=getattr(
                spec, "expected_interval_hours", None),
        )
        # Per direction as well, for a tool whose directions have different
        # consumers. The tool-level `continuity` above stays — the card's
        # footer reads it — but the overall state comes from the WORST
        # direction, because a tool answering one consumer while failing
        # another must not read green. Same rule as the `overall` badge.
        per = _continuity_per_direction(entry, spec, last)
        if per:
            entry["direction_continuity"] = per
            entry["overall"] = min(
                (v["state"] for v in per.values()),
                key=lambda s: STATES.index(s) if s in STATES else 0,
            )
        else:
            entry["overall"] = entry["continuity"]["state"]
        tools.append(entry)
    # A row for a tool no connector implements any more — a connector
    # removed while its configuration remains. Surfaced rather than hidden,
    # because a stored credential nothing can use is worth knowing about.
    orphans = [
        status_of(None, rows[t], t) for t in sorted(rows) if t not in cat
    ]
    return {
        "tenant_id": tenant_id,
        "tools": tools + orphans,
        "counts": _counts(tools + orphans),
    }


async def matrix(
    db: AsyncSession, *, scope: tenant_scope.TenantScope
) -> dict[str, Any]:
    """The cross-tenant matrix: which tenants have which tools.

    This is the view that answers "who has no EDR", so it lists every tenant
    this scope may read — including tenants with no integrations at all,
    because a tenant missing from the matrix reads as a tenant with nothing
    to report rather than a tenant with no tools.
    """
    from app.models.database import Tenant

    stmt = select(Tenant)
    stmt = tenant_scope.apply(stmt, Tenant.tenant_id, scope)
    tenants = [
        {"tenant_id": t.tenant_id, "name": t.name, "status": t.status}
        for t in (await db.execute(stmt)).scalars().all()
    ]

    rows = await _rows(db, scope=scope)
    by_tenant: dict[str, dict[str, Any]] = {}
    for r in rows:
        by_tenant.setdefault(r.tenant_id, {})[r.tool] = r

    cat = catalogue()
    # Continuity here too, not only on the card grid. Attaching it to one view
    # and not the other is how a stopped integration keeps reading as
    # `not_configured` in the matrix — the same invisibility, surviving in the
    # view whose whole job is "who has nothing working". The join test caught
    # this: the component reads `continuity` and one payload branch lacked it.
    cells: dict[str, dict[str, Any]] = {}
    for t in tenants:
        tid = t["tenant_id"]
        row_for = by_tenant.get(tid, {})
        cells[tid] = {}
        for tool in sorted(cat):
            entry = status_of(cat.get(tool), row_for.get(tool), tool)
            last = await last_success_for(db, tid, tool, row_for.get(tool))
            entry["continuity"] = continuity(
                state=entry["overall"], last_succeeded_at=last,
                expected_interval_hours=getattr(
                    cat.get(tool), "expected_interval_hours", None),
            )
            entry["overall"] = entry["continuity"]["state"]
            cells[tid][tool] = entry
    return {
        "tenants": sorted(tenants, key=lambda t: t["tenant_id"]),
        "tools": [cat[t].as_json() for t in sorted(cat)],
        "cells": cells,
        # Named, not just counted: a count tells nobody which tenant to go
        # and configure.
        "tenants_without_any_working": sorted(
            t["tenant_id"] for t in tenants
            if not any(
                cells[t["tenant_id"]][tool]["overall"] == VERIFIED_OK
                for tool in cells[t["tenant_id"]]
            )
        ),
    }


def _counts(tools: list[dict[str, Any]]) -> dict[str, int]:
    out = {s: 0 for s in STATES}
    for t in tools:
        state = t.get("overall")
        if state in out:
            out[state] += 1
    return out
