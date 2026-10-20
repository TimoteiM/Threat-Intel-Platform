"""The fixed part: which queries an event class always deserves.

Keyed on **event class**, because that is what the corpus concentrates on.
Measured over 7,516 runs in 30 days (docs/design/context-gathering-stage.md §3):

    rule_name            744 distinct, top ten cover 41%  — a long tail
    event_id + channel   144 distinct, top ten cover 81%  — and Sysmon
                         10/18/17 alone are 62%
    alert_source         2 distinct, "Siembiot" 94%       — not a discriminator
    detection_rule_name  absent on 100% of runs           — keyed on nothing

So ten rows cover four alerts in five, and no model is involved in any of it.
A row is a list of template names; a template declares what it needs and what
it costs, and the cost of a run is therefore known from its event class before
it starts.

**An agent never composes a query.** It picks a template from this table and
fills the template's selectors with tokens. That is what keeps the
detokenisation boundary tractable and the cost bounded, and it is why the
template — not a query string — is the unit everywhere below.

**A template names a source KIND, never a source.** `siem` and `edr` are
resolved per tenant through the client source map, so the same template
reaches Exabeam for one client and whatever the next client runs for them.
An agent that could name a source could name another tenant's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

#: The join keys a template can pivot on. These are the selector names an
#: agent fills with tokens, and the only vocabulary it has.
SELECTORS = ("host", "user", "hash", "ip", "process", "pipe")

#: Source kinds. A tenant's map says which platform answers each.
SIEM = "siem"
EDR = "edr"
SOURCE_KINDS = (SIEM, EDR)


@dataclass(frozen=True)
class QueryTemplate:
    """One query this platform knows how to ask, of a kind of source."""

    name: str
    #: What this asks, in words. Goes into the record as the *why*, so an
    #: analyst reading it later sees the question rather than a template id.
    purpose: str
    #: Which selectors must be filled for it to run. A template whose
    #: selectors are not available is `skipped`, with the missing key named —
    #: 75% of runs carry no principal, and "no user" is a fact about the
    #: alert, not an empty result from the source.
    selectors: tuple[str, ...]
    source_kind: str
    #: How many calls this costs. Declared, so a run's cost is known from its
    #: event class before the first query.
    declared_calls: int = 1
    #: Whether a second hop may select this template. The pivot templates are
    #: the cheap, bounded ones: a hash's prevalence is one query whatever the
    #: answer, where re-running a process tree on every result is the runaway
    #: loop in §5.
    pivotable: bool = False


TEMPLATES: dict[str, QueryTemplate] = {t.name: t for t in (
    QueryTemplate(
        name="process_tree",
        purpose="the process tree around this process on this host",
        selectors=("host", "process"),
        source_kind=EDR,
        declared_calls=2,
    ),
    QueryTemplate(
        name="hash_prevalence",
        purpose="how many hosts have executed this image hash",
        selectors=("hash",),
        source_kind=EDR,
        declared_calls=1,
        # One query whatever the answer. A hash on 113 hosts (measured) is
        # one call, not 113 — the fan-out cap §5 asks for, expressed as a
        # property of the template rather than a rule a caller must honour.
        pivotable=True,
    ),
    QueryTemplate(
        name="pipe_creator",
        purpose="the process that opened this named pipe, and its parent",
        selectors=("host", "pipe"),
        source_kind=EDR,
        declared_calls=2,
    ),
    QueryTemplate(
        name="host_logons",
        purpose="authentication activity on this host in the window",
        selectors=("host",),
        source_kind=SIEM,
        declared_calls=1,
    ),
    QueryTemplate(
        name="source_address_logons",
        purpose="other authentication attempts from this address in the window",
        selectors=("ip",),
        source_kind=SIEM,
        declared_calls=1,
        pivotable=True,
    ),
    QueryTemplate(
        name="user_sessions",
        purpose="this account's sessions in the window",
        selectors=("user",),
        source_kind=SIEM,
        declared_calls=1,
        pivotable=True,
    ),
    QueryTemplate(
        name="user_risk_timeline",
        purpose="this account's risk timeline",
        selectors=("user",),
        source_kind=SIEM,
        declared_calls=1,
    ),
    QueryTemplate(
        name="host_threat_state",
        purpose="this host's current threat state",
        selectors=("host",),
        source_kind=EDR,
        declared_calls=1,
    ),
)}


#: event class -> the templates it always deserves.
#:
#: The ten rows that cover 81%. Each row's cost is the sum of its templates'
#: `declared_calls`, so a Sysmon 10 run costs 3 before anything runs.
PLAYBOOK: dict[str, tuple[str, ...]] = {
    # Sysmon 10, process access — 26% of the corpus on its own.
    "10": ("process_tree", "hash_prevalence"),
    # Sysmon 18 and 17, named pipe — 36% together.
    "18": ("pipe_creator", "hash_prevalence"),
    "17": ("pipe_creator", "hash_prevalence"),
    # SQL logon failure — 5%.
    "18456": ("source_address_logons", "user_sessions"),
    # Account change — 1%.
    "4738": ("user_sessions", "user_risk_timeline"),
    # Process create / file create — 2%.
    "1": ("hash_prevalence", "process_tree"),
    "29": ("hash_prevalence", "process_tree"),
}

#: Run for every class, when the key is present. The design note's "*any*"
#: row: a host's threat state and a user's risk score are cheap and always
#: worth having.
ALWAYS: tuple[str, ...] = ("host_threat_state", "user_risk_timeline")


class NoPlaybookRow(LookupError):
    """This event class has no fixed row.

    A distinct type because it is a **measurable gap**, not an error: 19% of
    alerts fall outside the top ten, and the honest record says
    `no_playbook` for the class rather than silently gathering nothing.
    """


def event_class_of(alert_fields: Mapping[str, object]) -> str:
    """The playbook key for an alert.

    `event_id` arrives as `"10 | ThreatHunting"` — the class and the channel
    in one string — so the class is the part before the pipe. Returns `""`
    when the field is absent, which is a different state from an unknown
    class and is recorded as such.
    """
    raw = str(alert_fields.get("event_id") or "").strip()
    if not raw:
        return ""
    return raw.split("|", 1)[0].strip()


def templates_for(
    event_class: str, available: Mapping[str, str]
) -> tuple[tuple[QueryTemplate, ...], tuple[dict[str, str], ...]]:
    """The templates to run, and what was skipped with the reason.

    `available` maps selector name -> token. A template whose selectors are
    not all present is **skipped with the missing selector named**: "no
    principal on this alert" is a fact about the alert, and reporting it as
    an empty result would be the absence-as-value defect this codebase keeps
    finding.

    Raises `NoPlaybookRow` when the class has no row, so the caller records
    the gap deliberately rather than receiving an empty tuple that looks like
    "nothing to do".
    """
    row = PLAYBOOK.get(event_class)
    if row is None:
        raise NoPlaybookRow(event_class)

    chosen: list[QueryTemplate] = []
    skipped: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in (*row, *ALWAYS):
        if name in seen:
            continue
        seen.add(name)
        template = TEMPLATES[name]
        missing = [s for s in template.selectors if not available.get(s)]
        if missing:
            skipped.append({
                "template": name,
                "reason": f"no {', '.join(missing)} on this alert",
                "missing": ",".join(missing),
            })
            continue
        chosen.append(template)
    return tuple(chosen), tuple(skipped)


def declared_cost(templates: tuple[QueryTemplate, ...]) -> int:
    """What this set of templates costs in calls, before any of it runs."""
    return sum(t.declared_calls for t in templates)
