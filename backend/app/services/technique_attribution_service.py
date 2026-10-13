"""Who named this ATT&CK technique: the rule, the evidence, or both.

Corroboration was a boolean, and it collapsed two independent statements into
one. Two namers exist for every alert:

    the detection rule   `rule.mitre.id` — its author's mapping, written
                         before this alert existed
    the assessment       techniques the gathered evidence supports, via
                         `_evidenced_techniques` and `_collector_techniques`

Treating "corroborated" as `rule ∧ model` kept only the agreements and threw
the rest away, including the most interesting case. Measured on
`alert_body_investigation_runs.result_attack_assessment`, 2026-10-12:

    16,531  assessments
       768  had ANY supporting evidence (4.6%)       684 production, 84 rig
        41  of those confirmed a technique the rule had claimed
       727  of those found evidence for a technique the rule had NOT claimed

So the scarcity is not in the evidence and it is not the test rig: **94.7% of
the alerts where evidence supports a technique are discarded because the rule
named a different one.** 2,188 assessments carry `additional_techniques`, and
nothing drew them.

Four states, because there are four things that can be true
-----------------------------------------------------------
    rule_confirmed  the assessment marked the rule's OWN id `confirmed`.
    rule_only       the rule claimed it and the assessment did not confirm it.
    model_only      the evidence supports it and no rule claimed it. Derived
                    from reading the telemetry — not corroboration, and never
                    counted as such.
    disagreement    rule says X, evidence says Y on the same alert. Both are
                    drawn and the conflict is marked.

This state was called `both` until 2026-10-13, and the name was doing damage.
"Both" says *two sources independently named this* — two witnesses. The code
says the assessment endorsed the id the rule had already supplied: one witness
and an endorsement, which is a weaker claim. The label travelled into the UI
and into every conversation about the data, and it produced a wrong hypothesis
about the comparison being broken before anyone read the code. A field name is
worse than a misleading comment for exactly that reason. Renamed to what it
computes.

The other three were then audited rather than assumed, because one of four
lying is no reason to trust the rest:

    rule_only    accurate. It would be false if a rule-claimed id also
                 appeared in `additional_techniques` as deterministically
                 supported — `states.setdefault` would leave it `rule_only`
                 while two sources had in fact named it. Measured across all
                 16,725 assessments: **0 overlap**. True by the assessment's
                 construction rather than by anything enforced here, so
                 `test_technique_attribution` pins it.
    model_only   accurate.
    disagreement accurate as stated. It compares exact ids, so a rule claiming
                 a parent and the telemetry supporting its sub-technique is
                 recorded here as a disagreement; the 202 cases where that
                 happens are separated downstream by the CLI and are the
                 subject of docs/problems/provenance-at-different-depths.md.

Never collapse two statements into one — show both and say who said what.

The disagreement is the one worth a human
------------------------------------------
22 runs have a model reading the telemetry and concluding T1036 (Masquerading)
while the rule claims T1129 (Shared Modules). Either the rule is mis-mapped or
the model is wrong, and both are detection-engineering work. Keeping only the
rule's answer guarantees a wrong mapping stays wrong for ever.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

#: The states. `RULE_CONFIRMED` is the only one that means the assessment
#: endorsed the rule's own id — which is not two independent witnesses.
RULE_CONFIRMED = "rule_confirmed"
RULE_ONLY = "rule_only"
MODEL_ONLY = "model_only"
STATES = (RULE_CONFIRMED, RULE_ONLY, MODEL_ONLY)

#: What wins when two sources name the same id, strongest first.
#:
#: Written down on 2026-10-13 before it was needed. The code used
#: `setdefault`, which made first-writer-wins the policy by accident; the real
#: defect was not the collision but that a ranking existed and nobody had
#: chosen it. Whoever hits this should be applying a decision, not taking one
#: at an awkward hour.
#:
#:   1. **rule claimed it AND the telemetry independently supported it.**
#:      Two sources, arrived at separately. This is the strongest statement
#:      available and **has no state today** — 0 occurrences in 16,725
#:      assessments, pinned by `test_rule_only_would_be_a_lie_if_the_
#:      assessment_overlapped`. When that test fires, add a state for it
#:      rather than mapping it onto one of the three below. It must not
#:      become `rule_only`: that label reads as "nothing backed this up",
#:      which is the opposite of what happened, and absence of evidence is a
#:      worse error than the wrong kind of evidence.
#:   2. **rule_confirmed** — the rule claimed it and the assessment endorsed
#:      that same id. One witness plus an endorsement.
#:   3. **model_only** — the telemetry supports it and no rule claimed it.
#:      A finding, not corroboration.
#:   4. **rule_only** — the rule claimed it and nothing backed it up.
#:
#: The ordering principle: a state that asserts more evidence outranks one
#: that asserts less, and no state may be assigned that claims *less*
#: evidence than was actually found.
PRECEDENCE = (
    "rule_and_evidence (does not exist yet — see note)",
    RULE_CONFIRMED,
    MODEL_ONLY,
    RULE_ONLY,
)

#: Statuses the assessment writes for a technique the rule claimed.
CONFIRMED = "confirmed"
NOT_CORROBORATED = "not_corroborated"

#: `additional_techniques` holds entries the rule never claimed. Two kinds live
#: there and they are not the same evidence:
#:   "additional"    deterministic signals supported it
#:   anything else   an AI proposal, already validated but never deterministic
#: `assess_attack` keeps AI proposals out of `confirmed_count`, and so does
#: this: an AI suggestion is not the telemetry speaking.
ADDITIONAL = "additional"


def _loads(assessment: Any) -> dict[str, Any]:
    """The assessment as a mapping, or an empty one.

    Anything that is not a mapping yields nothing rather than raising: this is
    read on every case page and from the backfill, and a malformed row is an
    absence of an assessment, not a 500.
    """
    if isinstance(assessment, str):
        try:
            assessment = json.loads(assessment)
        except ValueError:
            return {}
    return assessment if isinstance(assessment, dict) else {}


def _entries(assessment: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = assessment.get(key)
    return [e for e in value if isinstance(e, dict)] if isinstance(value, list) else []


def _ids(entries: Iterable[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for entry in entries:
        tid = str(entry.get("id") or "").strip().upper()
        if tid and tid not in out:
            out.append(tid)
    return out


@dataclass(frozen=True)
class Attribution:
    """Every technique named for one alert, and who named it."""

    #: technique id -> one of STATES
    states: dict[str, str] = field(default_factory=dict)
    #: What each side named, when they named different things. ONE per alert.
    #:
    #: Deliberately not a cross product. The first version paired every
    #: unclaimed rule id with every supported model id, so a rule asserting
    #: five techniques against one piece of evidence produced five
    #: "disagreements" for a single alert — and the tell was 917 appearing
    #: five times in a row in the output. One alert, one disagreement, both
    #: sides stated.
    disagreement: tuple[tuple[str, ...], tuple[str, ...]] | None = None

    def of(self, technique_id: str) -> str | None:
        return self.states.get(str(technique_id or "").strip().upper())

    def corroborated(self) -> list[str]:
        """Only `rule_confirmed`. The word means one thing in this codebase —
        and note that it means the assessment endorsed the rule's id, not that
        two sources independently arrived at it."""
        return sorted(t for t, s in self.states.items() if s == RULE_CONFIRMED)

    def model_only(self) -> list[str]:
        return sorted(t for t, s in self.states.items() if s == MODEL_ONLY)

    def rule_only(self) -> list[str]:
        return sorted(t for t, s in self.states.items() if s == RULE_ONLY)

    def as_json(self) -> dict[str, Any]:
        return {
            "states": dict(self.states),
            "corroborated": self.corroborated(),
            "model_only": self.model_only(),
            "rule_only": self.rule_only(),
            "disagreement": (
                {
                    "rule_claimed": list(self.disagreement[0]),
                    "evidence_supports": list(self.disagreement[1]),
                }
                if self.disagreement
                else None
            ),
        }


def attribute(
    assessment: Any, *, rule_ids: Iterable[str] = ()
) -> Attribution:
    """Who named each technique on this alert.

    One function, read by every consumer. `confirmed_ids` computed this one
    way and `alert_correlation_service` another — one column with two meanings,
    which is the small version of the nine-membership-consumers defect and is
    fixed the same way: nobody computes it, everybody reads it.

    `rule_ids` is what the alert's own `rule.mitre.id` carried. It is passed in
    rather than re-parsed here, because the extractor has already read the body
    once and reading it twice is how two answers appear.
    """
    data = _loads(assessment)
    claimed = _entries(data, "techniques")
    extra = _entries(data, "additional_techniques")

    rules = [str(t).strip().upper() for t in rule_ids if str(t).strip()]
    # The assessment's own record of what the detection claimed, used when the
    # caller has not read the body.
    if not rules:
        rules = [
            str(t).strip().upper()
            for t in (data.get("detection_claimed") or [])
            if str(t).strip()
        ]

    states: dict[str, str] = {}
    for tid in rules:
        states[tid] = RULE_ONLY

    confirmed = {
        str(e.get("id") or "").strip().upper()
        for e in claimed
        if e.get("status") == CONFIRMED and e.get("id")
    }
    for tid in confirmed:
        if tid:
            states[tid] = RULE_CONFIRMED

    # Deterministic-signal entries only. An AI proposal rides in the same list
    # and is not the telemetry speaking.
    supported = [
        tid
        for tid in _ids(e for e in extra if e.get("status") == ADDITIONAL)
        if tid
    ]
    for tid in supported:
        # Written out rather than left as `setdefault`, because first-writer-
        # wins silently encodes a precedence between provenance states that
        # nobody chose. The behaviour is unchanged; the decision is now
        # stated, and PRECEDENCE below says what to do when it fires.
        if tid not in states:
            states[tid] = MODEL_ONLY
            continue
        # The collision: the rule claimed this id AND the telemetry
        # independently supported it. 0 occurrences across 16,725 assessments
        # as of 2026-10-13, and pinned by a test, so this branch is a
        # placeholder holding the current behaviour — not a decision deferred
        # by accident. See PRECEDENCE.
        if states[tid] == RULE_ONLY:
            states[tid] = RULE_ONLY

    # A disagreement needs both sides to have said something, and to differ.
    unconfirmed_rules = tuple(sorted(t for t in rules if states.get(t) == RULE_ONLY))
    unmatched_model = tuple(sorted(t for t in supported if states.get(t) == MODEL_ONLY))
    disagreement = (
        (unconfirmed_rules, unmatched_model)
        if unconfirmed_rules and unmatched_model
        else None
    )

    return Attribution(states=states, disagreement=disagreement)


def corroborated_ids(assessment: Any, *, rule_ids: Iterable[str] = ()) -> list[str]:
    """The ids this alert actually corroborated — `both`, and only `both`.

    Replaces `alert_graph_store_service.confirmed_ids`, which read
    `techniques[]` alone and so agreed with nothing else.
    """
    return attribute(assessment, rule_ids=rule_ids).corroborated()
