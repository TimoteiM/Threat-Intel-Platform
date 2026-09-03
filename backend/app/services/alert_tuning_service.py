"""Which rules have never been worth investigating, and the narrowest way to say so.

Every alert here has already been investigated. That means the platform does not
have to guess which detections are noise — it has the verdict for each one, and
it has the field values that were on the alert when the verdict was reached. The
conditions an exclusion needs are therefore derivable rather than proposed, and
this is where they are derived.

The whole design turns on one number: rule 1002 accounts for 2,235 of this
deployment's alerts and 200 of them concluded malicious. "Mute the noisy rule"
is the obvious action and it would silence two hundred real detections. So the
unit of a recommendation is never a rule — it is the narrowest field combination
that covers a rule's noise and touches none of its actionable alerts, verified
by replaying it against every alert the rule has ever produced.

A candidate that would have silenced even one actionable alert is discarded, not
flagged. There is no severity-only condition, because the sender's severity is
wrong in both directions here. And every recommendation carries an expiry, so a
rule that is noise this quarter gets re-examined rather than disappearing.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence
from xml.sax.saxutils import escape as xml_escape

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun
from app.services.alert_field_service import (
    SEVERITY_ONLY_FIELDS,
    SUPPRESSIBLE_FIELDS,
    extract_alert_fields,
)

logger = logging.getLogger(__name__)

# Verdicts that mean an analyst would have wanted to see the alert. Anything
# outside this set is drain: the investigation ran, spent quota, and concluded
# there was nothing to act on.
ACTIONABLE_VERDICTS = frozenset({"malicious", "suspicious"})

# Below this a rule has not fired often enough to say anything about it. Matches
# the scoring floor the detection-quality view already uses, so the two surfaces
# do not disagree about which rules are judgeable.
MIN_ALERTS_TO_RECOMMEND = 5

# How long a proposed exclusion should live before someone looks again. An
# exclusion with no expiry is a decision that stops being reviewed the moment it
# is made — this deployment already carries twelve of them and none expires.
DEFAULT_EXPIRY_DAYS = 90

# Fields that may appear in a condition. Severity is excluded outright rather
# than merely deprioritised: an exclusion keyed on the sender's own opinion of
# severity silences whatever that opinion gets wrong, and here it is wrong in
# both directions.
# rule_name is dropped as well: it is one-to-one with rule_id, which is already
# the anchor of every condition, so a rule_id + rule_name pair reads as a
# narrowed condition while being exactly the bare rule. Same disguise as a
# constant field, different costume.
CONDITION_FIELDS: tuple[str, ...] = tuple(
    name
    for name in SUPPRESSIBLE_FIELDS
    if name not in SEVERITY_ONLY_FIELDS and name != "rule_name"
)

# How many alerts per rule are parsed to derive conditions. Field extraction
# re-parses the alert body — alert_fields is stored on a small minority of runs
# — so this bounds the work on rules with thousands of alerts.
MAX_ALERTS_SAMPLED = 600

# A field value that appears on more than this share of the whole corpus is not
# a constraint. `manager = Siembiot` is true of every alert this platform has
# ever received, so a condition built on it silences the rule everywhere while
# reading as though it had been narrowed — which is worse than an honest bare
# rule mute, because it looks checked. Selectivity is measured estate-wide, not
# within the rule: within one rule a constant field and a discriminating field
# look identical, and they differ only in what they will match tomorrow.
MAX_VALUE_PREVALENCE = 0.40


@dataclass
class _Alert:
    run_id: str
    verdict: str
    actionable: bool
    when: datetime | None
    fields: dict[str, str]


@dataclass
class Condition:
    """A field combination, and what it did to the history it was tested on."""

    match_fields: dict[str, str]
    covered: int          # noise alerts this would have silenced
    leaked: int           # actionable alerts this would have silenced — must be 0
    total_noise: int
    scope: str = ""       # human phrase for what it narrows to
    notes: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        return self.covered / self.total_noise if self.total_noise else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "match_fields": dict(self.match_fields),
            "covered": self.covered,
            "leaked": self.leaked,
            "coverage": round(self.coverage, 3),
            "scope": self.scope,
            "field_count": len(self.match_fields),
            "notes": list(self.notes),
        }


def _verdict_of(row: Any) -> str:
    return str(row.overall_verdict or "unknown").strip().lower()


def _fields_of(row: Any) -> dict[str, str]:
    """The alert's suppressible fields, stored if present and re-parsed if not.

    alert_fields lands on runs completed since the carry-forward fix and is
    absent on the rest, so anything aggregating across history has to be able to
    recover them from the body.
    """
    stored = (row.result_json or {}).get("alert_fields")
    if isinstance(stored, dict) and stored:
        raw = stored
    else:
        raw = extract_alert_fields(
            row.alert_body or "",
            rule_id=row.detection_rule_id,
            rule_name=row.detection_rule_name,
        )
    return {
        name: str(raw[name]).strip()
        for name in CONDITION_FIELDS
        if raw.get(name) and str(raw[name]).strip()
    }


def _prevalence(all_fields: Iterable[dict[str, str]]) -> dict[tuple[str, str], float]:
    """How common each field value is across the whole corpus.

    Used to reject conditions that do not actually narrow anything.
    """
    counts: dict[tuple[str, str], int] = defaultdict(int)
    total = 0
    for fields in all_fields:
        total += 1
        for name, value in fields.items():
            counts[(name, value)] += 1
    if total == 0:
        return {}
    return {key: count / total for key, count in counts.items()}


def _best_conditions(
    noise: Sequence[_Alert],
    actionable: Sequence[_Alert],
    *,
    anchor: dict[str, str],
    prevalence: dict[tuple[str, str], float] | None = None,
) -> list[Condition]:
    """Field combinations that cover noise and touch nothing actionable.

    Searched shortest-first: the anchor alone, then the anchor plus one field,
    then plus two. A condition that leaks even one actionable alert is dropped
    rather than reported with a warning — a recommendation an analyst has to
    second-guess is worse than no recommendation, because it looks checked.
    """
    total = len(noise)
    if total == 0:
        return []

    def evaluate(match: dict[str, str], scope: str) -> Condition | None:
        covered = sum(1 for alert in noise if _matches(alert, match))
        if covered == 0:
            return None
        leaked = sum(1 for alert in actionable if _matches(alert, match))
        if leaked:
            return None
        return Condition(
            match_fields=match, covered=covered, leaked=0, total_noise=total, scope=scope
        )

    found: list[Condition] = []

    # The anchor on its own — the bare rule mute. Computed so it can be offered
    # as the broadest option, but deliberately never preferred: see the sort at
    # the end of this function.
    base = evaluate(dict(anchor), "every alert from this rule, on every host")
    if base is not None:
        base.notes.append(
            "Broadest option. Silences this rule everywhere, including on hosts "
            "it has never fired on yet."
        )

    # Values that appear in the noise, one field at a time.
    prevalent = prevalence or {}
    values: dict[str, set[str]] = defaultdict(set)
    for alert in noise:
        for name, value in alert.fields.items():
            if name in anchor:
                continue
            # Reject values that are true of most of the estate. They pass every
            # coverage and leak test while constraining nothing.
            if prevalent.get((name, value), 0.0) > MAX_VALUE_PREVALENCE:
                continue
            values[name].add(value)

    singles: list[Condition] = []
    for name, options in values.items():
        for value in options:
            candidate = evaluate({**anchor, name: value}, f"{name} = {value}")
            if candidate is not None:
                singles.append(candidate)
    singles.sort(key=lambda c: (-c.covered, c.scope))
    found.extend(singles[:8])

    # Pairs, only where nothing shorter covered everything. Two conditions is
    # about as much as an analyst will read on a proposal.
    if not any(c.coverage >= 0.999 for c in found):
        pairs: list[Condition] = []
        names = sorted(values)
        for index, first in enumerate(names):
            for second in names[index + 1 :]:
                for value_a in list(values[first])[:4]:
                    for value_b in list(values[second])[:4]:
                        candidate = evaluate(
                            {**anchor, first: value_a, second: value_b},
                            f"{first} = {value_a} and {second} = {value_b}",
                        )
                        if candidate is not None:
                            pairs.append(candidate)
        pairs.sort(key=lambda c: (-c.covered, len(c.match_fields)))
        found.extend(pairs[:4])

    # Full coverage first, then the NARROWEST condition that achieves it.
    #
    # The obvious sort — most alerts covered, fewest fields — is wrong, and it
    # was what this function did first. It made the bare rule win every time,
    # because muting a whole rule always covers all of its own noise with one
    # field. That produced "mute rule 110400 everywhere" for Kerberoasting on
    # the strength of five benign alerts, which is precisely how a real
    # detection disappears for a year. Between two conditions that silence the
    # same alerts, the one that constrains more is strictly safer: it leaves the
    # rule live everywhere it has not yet proven itself noise.
    found.sort(key=lambda c: (-c.coverage, -len(c.match_fields)))

    # The bare rule is offered last, and only when something narrower did not
    # already cover everything.
    if base is not None and not any(c.coverage >= 0.999 for c in found):
        base.notes.append(
            "No narrower condition covers this rule's noise, so this is the only "
            "option the stored fields support."
        )
        found.append(base)
    elif base is not None:
        found.append(base)

    deduped: list[Condition] = []
    seen: set[tuple] = set()
    for candidate in found:
        key = tuple(sorted(candidate.match_fields.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped[:6]


def _matches(alert: _Alert, match: dict[str, str]) -> bool:
    return all(alert.fields.get(name) == value for name, value in match.items())


def wazuh_rule_xml(rule_id: str, match_fields: dict[str, str], *, reason: str) -> str:
    """A local_rules.xml override that stops the noise at the source.

    Level 0 rather than a delete: the event still exists in the archive and can
    be searched, it simply stops alerting. An analyst investigating later can
    still find it, which a dropped event does not allow.

    Emitted as text for a human to paste. Nothing here writes to Wazuh — the
    platform has no credentials for it and should not acquire any to silence
    detections.
    """
    conditions: list[str] = []
    for name, value in sorted(match_fields.items()):
        if name == "rule_id":
            continue
        escaped = xml_escape(str(value))
        if name == "agent":
            conditions.append(f'    <hostname>{escaped}</hostname>')
        elif name == "agent_ip":
            conditions.append(f'    <srcip>{escaped}</srcip>')
        elif name in ("event_id", "event_name", "service", "user"):
            field_name = {
                "event_id": "win.system.eventID",
                "event_name": "win.system.providerName",
                "service": "win.system.channel",
                "user": "win.eventdata.targetUserName",
            }[name]
            conditions.append(f'    <field name="{field_name}">{escaped}</field>')
    body = "\n".join(conditions) if conditions else "    <!-- no narrowing field available -->"
    # Wazuh reserves 100000-120000 for local rules; anything outside that range
    # is either invalid or collides with a shipped ruleset. Derived from the
    # source rule so re-generating the same recommendation produces the same id,
    # and flagged as needing a uniqueness check because this platform cannot see
    # the customer's existing local_rules.xml.
    # A stable digest, not hash(): Python randomises hash() per process, so the
    # generated id would differ across restarts and the "same recommendation,
    # same id" property this comment claims would be false.
    digest = hashlib.sha256(str(rule_id).encode("utf-8")).hexdigest()[:8]
    local_id = 100000 + (int(digest, 16) % 19000)
    return (
        f'<!-- rule id is in Wazuh\'s local range (100000-120000); change it if\n'
        f'     100000-119999 is already taken in your local_rules.xml -->\n'
        f'<group name="tuned,threatintel,">\n'
        f'  <rule id="{local_id}" level="0">\n'
        f'    <if_sid>{xml_escape(rule_id)}</if_sid>\n'
        f'{body}\n'
        f'    <description>{xml_escape(reason)}</description>\n'
        f'  </rule>\n'
        f'</group>'
    )


async def build_tuning_recommendations(
    db: AsyncSession, *, days: int = 90, min_alerts: int = MIN_ALERTS_TO_RECOMMEND
) -> dict[str, Any]:
    """Rules whose alerts have never been worth acting on, and how to silence them."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.event_time,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.overall_verdict,
                AlertBodyInvestigationRun.alert_body,
                AlertBodyInvestigationRun.result_json,
                AlertBodyInvestigationRun.entity_host,
            )
            .where(
                AlertBodyInvestigationRun.created_at >= cutoff,
                AlertBodyInvestigationRun.detection_rule_id.isnot(None),
            )
            .order_by(AlertBodyInvestigationRun.created_at.desc())
            .execution_options(query_name="tuning_scan")
        )
    ).all()

    by_rule: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        by_rule[str(row.detection_rule_id)].append(row)

    # Estate-wide field prevalence, computed once. Parsing every body twice
    # would double the cost of the scan, so the per-rule parse below reuses this
    # pass through a small cache.
    parsed_cache: dict[str, dict[str, str]] = {}
    for row in rows:
        parsed_cache[str(row.id)] = _fields_of(row)
    prevalence = _prevalence(parsed_cache.values())

    recommendations: list[dict[str, Any]] = []
    examined = 0
    for rule_id, rule_rows in by_rule.items():
        if len(rule_rows) < min_alerts:
            continue
        examined += 1

        actionable_count = sum(1 for row in rule_rows if _verdict_of(row) in ACTIONABLE_VERDICTS)
        # A rule that mostly matters is not a tuning candidate, however loud it
        # is. Loudness is a cost problem, not a correctness one, and the fix for
        # it is different (see the downgrade note in the response).
        if actionable_count / len(rule_rows) > 0.25:
            continue

        sample = rule_rows[:MAX_ALERTS_SAMPLED]
        parsed = [
            _Alert(
                run_id=str(row.id),
                verdict=_verdict_of(row),
                actionable=_verdict_of(row) in ACTIONABLE_VERDICTS,
                when=row.event_time or row.created_at,
                fields=parsed_cache.get(str(row.id)) or _fields_of(row),
            )
            for row in sample
        ]
        noise = [alert for alert in parsed if not alert.actionable]
        actionable = [alert for alert in parsed if alert.actionable]
        if not noise:
            continue

        anchor = {"rule_id": rule_id}
        conditions = _best_conditions(
            noise, actionable, anchor=anchor, prevalence=prevalence
        )
        if not conditions:
            # Every candidate leaked. Worth reporting as a non-recommendation:
            # the rule is noisy and cannot be narrowed on what is stored, which
            # is a finding about the alert format, not about the rule.
            recommendations.append(
                {
                    "rule_id": rule_id,
                    "rule_name": str(sample[0].detection_rule_name or ""),
                    "alerts": len(rule_rows),
                    "actionable": actionable_count,
                    "noise": len(noise),
                    "recommendable": False,
                    "blocked_reason": (
                        "No field combination separates this rule's noise from its "
                        "actionable alerts, so any exclusion would silence real "
                        "detections. Narrow it at the source or leave it alone."
                    ),
                    "conditions": [],
                }
            )
            continue

        times = [alert.when for alert in noise if alert.when]
        best = conditions[0]
        reason = (
            f"{len(noise)} of {len(rule_rows)} alerts from rule {rule_id} concluded "
            f"benign or inconclusive and none concluded actionable"
        )
        recommendations.append(
            {
                "rule_id": rule_id,
                "rule_name": str(sample[0].detection_rule_name or ""),
                "alerts": len(rule_rows),
                "actionable": actionable_count,
                "noise": len(noise),
                "hosts": len({row.entity_host for row in rule_rows if row.entity_host}),
                "first_seen": min(times).isoformat() if times else None,
                "last_seen": max(times).isoformat() if times else None,
                "recommendable": True,
                "sampled": len(sample) < len(rule_rows),
                # Every candidate, so the analyst picks the breadth rather than
                # accepting whichever one sorted first.
                "conditions": [condition.as_dict() for condition in conditions],
                "proposed": best.as_dict(),
                "reason": reason,
                "expires_in_days": DEFAULT_EXPIRY_DAYS,
                "wazuh_rule": wazuh_rule_xml(rule_id, best.match_fields, reason=reason),
                # What accepting it would have done to the history it was
                # derived from. Stated even though it is tautological, because a
                # proposal without its replay is a suggestion, not evidence.
                "replay": {
                    "would_have_silenced": best.covered,
                    "of_which_actionable": 0,
                    "window_days": days,
                },
            }
        )

    recommendations.sort(
        key=lambda item: (not item["recommendable"], -item.get("noise", 0))
    )
    silenceable = sum(
        item["proposed"]["covered"] for item in recommendations if item["recommendable"]
    )
    return {
        "window_days": days,
        "min_alerts": min_alerts,
        "rules_examined": examined,
        "recommendations": recommendations,
        "alerts_silenceable": silenceable,
        "alerts_total": len(rows),
    }
