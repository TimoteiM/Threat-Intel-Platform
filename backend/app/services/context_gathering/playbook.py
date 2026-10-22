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
    # **Added for the answer-key cases, 2026-10-21.** Two of the five
    # analyst-closed cases on `c00` had NO playbook row at all: #1050 is
    # entirely class 15 (Sysmon FileCreateStreamHash) and #1184 entirely
    # class 1102 ("The audit log was cleared"). Depth on cases with a known
    # answer before breadth on cases without, so this exists to cover those
    # two rather than to raise corpus-wide coverage.
    #
    # Keyed on `host` alone, which is what those classes carry: measured,
    # class 15 has a host on 202 of 202 runs and a user on only 39; class
    # 1102 has a host on 20 of 20 and a **user on none**. A user-keyed
    # template could never fire on 1102.
    #
    # Two declared calls — the id query and the hydrate, which is what
    # `FalconSource._host_detections` really spends.
    # ── indicator-led, added 2026-10-22. **Estate-wide and still answerable
    # when the alerting host has no sensor**, which is 16.0% of the last 400
    # closed c00 cases — the cases where every host-led template is useless.
    #
    # Each one is here because a positive control returned non-zero against a
    # value that is actually in the estate. A filter that accepts a synthetic
    # value and returns 0 proves nothing, and two of the three originally
    # asked for failed exactly that way:
    #
    #   sha256:'<real>'      -> total 1   USABLE  (hash_prevalence, existing)
    #   source_ips:'<real>'  -> total 2   USABLE  (ip_seen_anywhere)
    #   filename:'<real>'    -> total 9   USABLE  (file_name_prevalence)
    #   md5:'<real>'         -> total 8   USABLE
    #   domain               -> field absent on 200/200 alerts, 0% fill
    #   indicators/queries/devices/v1 -> HTTP 403 scope not permitted
    #
    # So "has any host contacted this domain" has **no template**, because the
    # field does not exist — the falcon-panel note already called that
    # `no_field_map` and the probe confirms it. And "how many machines carry
    # this file" is a **credential scope gap**, not an API gap: it needs the
    # IOC scope added in the Falcon console, which is a human action.
    QueryTemplate(
        name="ip_seen_anywhere",
        purpose="whether any host in the estate has an alert naming this address",
        selectors=("ip",),
        source_kind=EDR,
        declared_calls=2,
        pivotable=True,
    ),
    QueryTemplate(
        name="file_name_prevalence",
        purpose="whether this filename appears on other hosts in the estate",
        selectors=("filename",),
        source_kind=EDR,
        declared_calls=2,
        pivotable=True,
    ),
    QueryTemplate(
        name="host_detections_window",
        purpose="what the EDR itself flagged on this host around the alert",
        selectors=("host",),
        source_kind=EDR,
        declared_calls=2,
        pivotable=False,
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
    # ── the classes the five analyst-closed cases involve that had no row,
    # added 2026-10-21. Deliberately NOT the corpus-wide top ten: these five
    # are the only cases on this platform with a human answer to check
    # against, and two of them were uncovered entirely.
    #
    # 15   Sysmon FileCreateStreamHash — a file stream was written. The
    #      question is what wrote it and whether the payload is known, so the
    #      hash first and the host's own detections second. Case #1050.
    "15": ("hash_prevalence", "host_detections_window"),
    # 1102 "The audit log was cleared" — 20 of 20 runs carry no user, so
    #      nothing user-keyed can run. What is answerable is whether the EDR
    #      saw anything else on that host in the window. Case #1184.
    "1102": ("host_detections_window",),
    # 7    Sysmon image loaded. The corpus rules here are "debug/dump
    #      library" and "credential-related library", so the loaded image's
    #      hash is the question. Appears inside case #61.
    "7": ("hash_prevalence", "host_detections_window"),
    # 11   Sysmon FileCreate — "executable dropped", "LOLBin certutil wrote
    #      exe". Same shape as 15. Appears inside case #61.
    "11": ("hash_prevalence", "host_detections_window"),
    # ── the seven classes the Exabeam shippers actually carry, added
    # 2026-10-22 once `event_id` extraction was fixed. Before that these
    # alerts had no class at all and matched no row: 25 of 52 lin/pov runs
    # carried `<EventID>N</EventID>` in the body and nothing in
    # `alert_fields`.
    #
    # **Rows written to what can actually fire, not to what the class means.**
    # Measured across those 25 runs, `host` and `user` are sparse — 0 to 3
    # occurrences per class — while an IP is present on every class and a
    # hash on 3 of the 4 class-4688 runs. So the indicator-led templates,
    # which run first regardless, are what will answer most of these, and the
    # host/user templates below will often skip with the selector named.
    # Writing rows that read well and never fire would be worse than writing
    # none.
    #
    # 4624 logon, 4625 failed logon — account and origin.
    "4624": ("host_logons", "user_sessions"),
    "4625": ("host_logons", "user_sessions"),
    # 4768 Kerberos TGT requested — purely account-centric.
    "4768": ("user_sessions",),
    # 4688 process create. The image's hash and name are the question, and
    # both are answerable estate-wide; `process_tree` is deliberately NOT
    # here — it has no source (Falcon's alerts API holds detections, not raw
    # process events) and `process` was absent on all 25 runs anyway.
    "4688": ("hash_prevalence", "file_name_prevalence"),
    # 4697 service installed, 5140/5145 network share accessed.
    #
    # **These three are the ones that need something new, and I have not
    # added it.** The class-specific question — which service binary, which
    # share, and has either been seen elsewhere — would need a
    # `service_name_prevalence` / `share_name_prevalence` template, and
    # **no configured source can answer either**: Falcon's alerts API has no
    # service or share field, and the Exabeam search returns rows with no
    # fields at all. A template with no source produces `check_failed` on
    # every alert, which is what the absent `domain` template already taught.
    #
    # So these rows carry what IS answerable and the gap is recorded rather
    # than papered over with a template that cannot run.
    "4697": ("user_sessions", "file_name_prevalence"),
    "5140": ("host_logons", "user_sessions"),
    "5145": ("host_logons", "user_sessions"),
}

#: Run for every class, when the key is present. The design note's "*any*"
#: row: a host's threat state and a user's risk score are cheap and always
#: worth having.
#: **`host_threat_state` is no longer in here.** Measured across the last 400
#: closed c00 cases: the host carries a non-closed Falcon detection on
#: **15.5%**, carries none on ~68.5%, and **has no sensor at all on 16.0%** —
#: where a "0 open detections" headline is not a low number, it is false.
#: Running it unconditionally on every alert made a non-discriminating panel
#: the first thing a reader saw. It is still run where it can corroborate (see
#: `CORROBORATING`), and `FalconSource` now refuses to report a count for an
#: unmanaged host without saying so in the same breath.
#: **Run FIRST, before the class row.** Estate-wide questions keyed on an
#: indicator rather than on the alerting host, so they still answer when that
#: host has no sensor — 16.0% of the last 400 closed c00 cases. Each is
#: evidenced by a positive control against a value actually in the estate;
#: see the template comments for the probe results and for the two questions
#: that have no template (domain: field absent; device-count-per-hash: HTTP
#: 403, credential scope).
INDICATOR_LED: tuple[str, ...] = (
    "hash_prevalence", "ip_seen_anywhere", "file_name_prevalence",
)

ALWAYS: tuple[str, ...] = ("user_risk_timeline",)

#: Run after the indicator-led templates, and only then: a host's threat state
#: is worth having as corroboration of a real negative, not as a headline.
CORROBORATING: tuple[str, ...] = ("host_threat_state",)


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
    # Order is load-bearing: the playbook row first, then the always-run
    # user template, then the corroborating host panel LAST. The record and
    # the report are read top-down, so a non-discriminating panel placed
    # first is the thing a reader sees first.
    for name in (*INDICATOR_LED, *row, *ALWAYS, *CORROBORATING):
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
