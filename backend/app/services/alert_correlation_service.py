"""
Alerts that are one event, seen from several angles.

A single alert is judged on what it carries. That is the right unit for a
verdict and the wrong unit for an attack: Kerberoasting on a domain controller
is suspicious, an account being changed is routine, and the two together on the
same machine within an hour is an intrusion. This deployment has exactly that
pair on ExpDC001 on two consecutive days, and nothing ever showed them together.

A case is (entity, window, the alerts inside it). What makes one worth raising
is not how many alerts it holds — forty repeats of one noisy rule is still one
noisy rule — but how many *independent* detections agree and how far the
behaviour travels across the kill chain. Those are the two things a single
alert can never tell you, so they are what the score is built from.

Suppressed alerts count. An alert an analyst muted as routine is exactly the one
that turns out to be step one, and the suppression only ever removed its
collector spend, never its record.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from sqlalchemy import func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun, AlertCaseSpine
from app.services.alert_baseline_service import (
    baseline_window_days,
    build_pair_baseline,
    case_surprise,
)
from app.config import get_settings
from app.services.alert_case_escalation import decide_emission, record_emission
from app.services.alert_case_narrative_service import (
    narrative_fingerprint,
    narrative_lead,
)
from app.services.alert_case_store import (
    case_reference,
    spines_for_entity,
    absorb_superseded,
    supersession_state,
    snapshot_if_changed,
    upsert_spine,
)
from app.services.alert_field_service import UNKNOWN_CLIENT, UNKNOWN_SOURCE
from app.services import tenant_scope
from app.tasks.case_event_task import dispatch
from app.tasks.case_narrative_task import dispatch as dispatch_narratives
from app.services import alert_case_closure_service as closure_rules
from app.services.alert_case_linkage_service import (
    cluster_linked,
    ubiquitous_values_across_estate,
)
from app.services.alert_session_service import (
    SCORE_VERSION,
    SESSION_GAP,
    SESSION_LOOKBACK_CHUNK,
    anchor_index,
    assign_sessions,
    case_key_for,
)

logger = logging.getLogger(__name__)

# Roughly the order an intrusion moves through. Used only to ask whether a case
# *advances* — a chain that reaches Impact from Discovery is a different animal
# from three alerts sitting in one stage — so precise ATT&CK ordering matters
# less than the direction of travel.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    # ATT&CK v19.2 split Defense Evasion into Stealth and Defense Impairment.
    # The catalogue this platform generates emits the new names; the old one was
    # still the only ranked spelling here, so every Stealth tactic was unranked
    # — contributing nothing to movement and invisible to progression, silently.
    # EXP-D0MY264 reached Execution and Stealth and scored as though it had
    # reached one tactic.
    "Stealth",
    "Defense Impairment",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_RANK = {name.casefold(): index for index, name in enumerate(TACTIC_ORDER)}

# Retired spellings, ranked where their replacement sits. Assessments stored
# before the rename still carry the old name, and a tactic that stops ranking
# because ATT&CK renamed it is a silent regression in every case that touches
# it — the kind that shows as a slightly lower score and never as an error.
_TACTIC_ALIASES = {
    "defense evasion": "Stealth",
    "defence evasion": "Stealth",
}
for _old, _new in _TACTIC_ALIASES.items():
    _TACTIC_RANK[_old] = _TACTIC_RANK[_new.casefold()]

# The alias table patches the past; it does not protect the future. MITRE will
# revise the taxonomy again, a new tactic name will emit, it will rank nowhere,
# and it will quietly zero the movement of every case that reaches it — which is
# precisely how the Stealth rename cost EXP-D0MY264 25 points for a month
# without producing a single error.
#
# So an unranked tactic is now loud. A non-zero reading here means the catalogue
# has outrun this ordering again, and the name in the log says which tactic to
# add. The same instinct as the naive-stamp counter: this one has already bitten
# once, and it announced itself only because the pipeline reports its working.
_UNRANKED_TACTICS: dict[str, int] = {}


def unranked_tactics_seen() -> dict[str, int]:
    """Tactic names scored cases carried that this kill chain does not rank."""
    return dict(_UNRANKED_TACTICS)


def _note_unranked(tactic: str) -> None:
    name = str(tactic or "").strip()
    if not name:
        return
    first_time = name not in _UNRANKED_TACTICS
    _UNRANKED_TACTICS[name] = _UNRANKED_TACTICS.get(name, 0) + 1
    if first_time:
        logger.warning(
            "ATT&CK tactic %r is not in TACTIC_ORDER — it contributes nothing to movement "
            "or progression. The catalogue has outrun this ordering; add it.", name
        )

DEFAULT_WINDOW_HOURS = 48
# How many independent detections a cluster needs before it becomes a case.
#
# This was 2, on the reasoning that one rule firing repeatedly is one
# detection however loud, and a case needs corroboration to be worth anyone's
# attention. That is a good rule for a page of *notable* cases and the wrong
# one for a page that has to account for every alert: measured over the
# estate, 863 of 890 linked clusters (97%) were dropped by it before a spine
# row was ever written, and 6,249 of 11,376 alerts (55%) were in no case at
# all. An analyst looking for this morning's alerts found nothing, because
# nothing had been created.
#
# Cases are the unit of coverage now — every alert belongs to one, and the
# score is what separates the interesting from the routine. Notability is
# still a threshold, but it belongs to escalation (see decide_emission and
# correlation_escalation_min_score), not to whether a case exists.
MIN_DISTINCT_RULES = 1


def _event_time(row: Any, fallback: datetime) -> datetime:
    """
    When this alert's event happened, with ingest time as the last resort.

    Runs stored before the event_time column existed have none, and a null would
    sort unpredictably against real timestamps. Falling back to created_at keeps
    every member on one comparable scale — the backfill then replaces the
    fallback with the real value wherever the body carries one.
    """
    return getattr(row, "event_time", None) or row.created_at or fallback


# A first-alert title has to be recognisable to the analyst who saw that alert
# arrive. These are the shapes that are not.
_TITLE_MIN_CHARS = 12
_TITLE_MAX_CHARS = 200
# Senders that put a whole payload in the title field. 760 stored runs carry a
# raw JSON object or a syslog line rather than a sentence.
_TITLE_REJECTED_PREFIXES = ("{", "[", "<")


def usable_alert_title(value: Any) -> str:
    """The alert's own title, when it is fit to name a case.

    Run titles are sender-supplied free text and the sender wins
    unconditionally, so some of them are a JSON body, a syslog line or a
    fragment ending in a colon. A case called "{" tells an analyst less than
    the host it happened on.
    """
    text = str(value or "").strip()
    if not text or text.startswith(_TITLE_REJECTED_PREFIXES):
        return ""
    # A pipe means a field-joined machine line, not a sentence.
    if "|" in text or text.endswith(":"):
        return ""
    if len(text) < _TITLE_MIN_CHARS:
        return ""
    text = text.rstrip(". ").rstrip("…").strip()
    return text[:_TITLE_MAX_CHARS].strip()


def case_label(
    *,
    host: str | None,
    users: Sequence[str],
    tactics: Sequence[str],
    members: Sequence[Any],
    ordered: Sequence[Any] | None = None,
) -> str:
    """What to call this case: the title of the alert that opened it.

    An analyst finds a case by recognising the alert that started it. The case
    used to be named `{host} — {earliest evidenced tactic}`, which is a
    summary of the whole case and bears no resemblance to anything they saw
    arrive: case #61 read "Windows-Test-Device — Execution" while the alert
    that opened it was "Windows-Test-Device - Credential Dumping".

    The composed form survives as the fallback, for the 760 runs whose title
    is a raw JSON body or a syslog line — see `usable_alert_title`.

    The identity half of that fallback names whoever the case is about. A host
    is the usual answer, but 167 stored alerts carry an account and no device
    at all, so "host" cannot be assumed to exist — the user is the fallback
    rather than an extra.

    More than one account on one device is reported as a count, not as the
    first one sorted. Naming one of three accounts is worse than naming none:
    it reads as a fact about the case.

    The descriptive half is the evidenced tactic that ranks earliest in the
    kill chain, because that is the question a list is scanned for. Failing
    that it is the rule that fired most, which is at least what the estate
    actually said. Neither is a conclusion — the verdict is elsewhere — so
    this stays a label and never grows into a claim.
    """
    named = [str(u).strip() for u in users if str(u or "").strip()]
    host_name = str(host or "").strip()

    # The first linked alert, which the caller has already sorted by event
    # time. Run titles already begin with the hostname — "Windows-Test-Device
    # - Credential Dumping" — so nothing is prepended to it, and the
    # duplicated host that produced "EXP-6FSKJR3 — EXP-6FSKJR3 - A .NET
    # application crashed" cannot arise.
    for member in (ordered if ordered is not None else members) or ():
        first = usable_alert_title(getattr(member, "title", None))
        if first:
            return first
        # Only the first member is consulted. Walking on to the second would
        # name the case after an alert that did not open it.
        break

    if host_name and len(named) == 1:
        identity = f"{host_name}/{named[0]}"
    elif host_name and len(named) > 1:
        identity = f"{host_name}/{len(named)} accounts"
    elif host_name:
        identity = host_name
    elif len(named) == 1:
        identity = named[0]
    elif named:
        identity = f"{len(named)} accounts"
    else:
        identity = "Unidentified entity"

    what = ""
    if tactics:
        what = str(tactics[0])
    else:
        counts: dict[str, int] = defaultdict(int)
        for member in members:
            # The detection first. Falling back to the carrier rule named a
            # case "exprevpxy002 — Unknown problem somewhere in the system",
            # which is the description of Wazuh rule 1002 and not what the
            # case is about.
            name = str(
                getattr(member, "detection_name", "")
                or getattr(member, "detection_rule_name", "")
                or ""
            ).strip()
            if name:
                counts[name] += 1
        if counts:
            what = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]

    # 7,448 runs on hyphenated hosts still carry the host inside
    # `detection_name`: migration 037 stripped the "<agent> - " prefix with
    # `^[^-]{1,80}? - `, a negated class that excludes the hyphen, so every
    # host with a hyphen in its name — EXP-6FSKJR3, Windows-Test-Device — was
    # skipped. Prepending the identity again produced the duplication.
    # Repairing the stored column changes detection identity and therefore
    # case membership, so that is its own measured change; this just stops the
    # label repeating itself.
    if host_name and what.casefold().startswith(f"{host_name.casefold()} - "):
        what = what[len(host_name) + 3:].strip()

    return f"{identity} — {what}" if what else identity


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _tactics_of(assessment: Any) -> tuple[set[str], set[str]]:
    """
    (evidenced, claimed) tactics — kept apart, because they are not equally true.

    A rule's ATT&CK mapping is its author's hypothesis. In this deployment every
    single claim is not_corroborated, and the mismatch view shows rules claiming
    Valid Accounts on alerts whose evidence is PowerShell and obfuscation. Wiring
    those claims into a case score would let a mismapped rule manufacture kill
    chain breadth out of nothing — the exact failure this platform keeps hitting
    when someone else's assertion is read as a finding.

    A technique the investigation established is a different kind of fact, so it
    is the one the score leans on.
    """
    if not isinstance(assessment, dict):
        return set(), set()

    def names(entry: Any) -> set[str]:
        if not isinstance(entry, dict):
            return set()
        raw = entry.get("tactics") or ([entry["tactic"]] if entry.get("tactic") else [])
        return {str(t).strip() for t in raw if str(t or "").strip().lower() not in ("", "unmapped")}

    evidenced: set[str] = set()
    claimed: set[str] = set()
    for entry in assessment.get("techniques") or []:
        # Only a confirmed claim counts as evidence of itself.
        (evidenced if (entry or {}).get("status") == "confirmed" else claimed).update(names(entry))
    for entry in assessment.get("additional_techniques") or []:
        evidenced.update(names(entry))
    return evidenced, claimed



# ── Behavioural shape: direction and pace ─────────────────────────────────────

# Two alerts stamped within a minute of each other are not evidence about which
# came first. Sensors batch, decoders round, and clocks drift by more than this
# between hosts — so anything inside the window is treated as unordered and
# contributes no transition at all, rather than a coin-flip one. A case is a
# partial order, not a sequence.
SIMULTANEITY_SECONDS = 60

# Inter-arrival spread on two alerts is one gap, not a distribution. Four
# members give three intervals, which is the least that can distinguish a burst
# from a pair that happened to land close together. Below it tempo is unknown —
# reported as unknown, never as a number.
MIN_MEMBERS_FOR_TEMPO = 4

# Median gap thresholds. Five minutes is faster than a person works through a
# host; four hours is slower than an intrusion usually pauses without being
# deliberate about it.
BURST_MEDIAN_GAP_SECONDS = 5 * 60
DWELL_MEDIAN_GAP_SECONDS = 4 * 3600

# Direction and pace modulate the movement the case already earned; they never
# add points of their own. A flat "burst bonus" would let a fast pair of noisy
# rules out-score a slow real chain, which is the opposite of what pace means.
#
# Progression scales movement between these bounds: a case whose stages run
# backwards keeps 0.6 of it, one that advances cleanly gets 1.4.
PROGRESSION_MIN_FACTOR = 0.6
PROGRESSION_MAX_FACTOR = 1.4

# A burst of *several distinct tactics* is an automated chain. Applied to
# movement, so a burst of one rule repeating multiplies a movement of zero and
# stays exactly as boring as it was.
TEMPO_BURST_FACTOR = 1.35
# Dwell is neutral, never a penalty. Low and slow is a technique, not an
# absence of one, and a chain that advances over three days is still a chain.
TEMPO_DWELL_FACTOR = 1.0


def _member_stage(row: Any) -> int | None:
    """
    How far along the kill chain one alert reached, or None if it says nothing.

    The furthest evidenced stage, not the earliest: an alert that evidences both
    Execution and Impact has reached Impact, and taking the minimum would report
    the case as never advancing past where it started.

    Evidenced tactics only. Claimed ones have never been corroborated on this
    deployment and the mismatch view shows rules claiming Valid Accounts where
    the evidence is PowerShell — a direction computed from those would be a
    direction through the rules' imagination.
    """
    evidenced, _claimed = _tactics_of(row.result_attack_assessment)
    ranks = [_TACTIC_RANK[t.casefold()] for t in evidenced if t.casefold() in _TACTIC_RANK]
    return max(ranks) if ranks else None


def progression_of(ordered: list[Any], fallback: datetime) -> dict[str, Any]:
    """
    How much of this case's movement runs forward along the kill chain.

    Walks adjacent staged members in event-time order. A transition counts as
    forward when the later member is at or beyond the earlier one's stage —
    ties included, because two alerts in the same tactic are not evidence of
    going backwards.

    Pairs closer together than SIMULTANEITY_SECONDS are skipped entirely. They
    are unordered with respect to each other, and scoring them either way would
    turn clock jitter into a claim about attacker behaviour.
    """
    staged = [
        (_event_time(row, fallback), stage)
        for row in ordered
        if (stage := _member_stage(row)) is not None
    ]
    if len(staged) < 2:
        return {"ratio": None, "forward": 0, "transitions": 0, "unordered": 0,
                "staged_members": len(staged)}

    forward = 0
    transitions = 0
    unordered = 0
    for (t_earlier, stage_earlier), (t_later, stage_later) in zip(staged, staged[1:]):
        if abs((t_later - t_earlier).total_seconds()) <= SIMULTANEITY_SECONDS:
            unordered += 1
            continue
        transitions += 1
        if stage_later >= stage_earlier:
            forward += 1

    return {
        "ratio": round(forward / transitions, 3) if transitions else None,
        "forward": forward,
        "transitions": transitions,
        "unordered": unordered,
        "staged_members": len(staged),
    }


def tempo_of(ordered: list[Any], fallback: datetime) -> dict[str, Any]:
    """
    The pace of a case: burst, steady, dwell, or honestly unknown.

    Reported from the median gap rather than the mean, so one long overnight
    pause in an otherwise rapid sequence does not turn a burst into a dwell.

    Under MIN_MEMBERS_FOR_TEMPO the answer is "unknown" and not a number. Two
    alerts produce a single interval, and a single interval is not a pace — a
    confident "tight burst" read off one gap is exactly the kind of number that
    looks like measurement and is not.
    """
    if len(ordered) < MIN_MEMBERS_FOR_TEMPO:
        return {"kind": "unknown", "median_gap_seconds": None, "span_seconds": None,
                "reason": f"fewer than {MIN_MEMBERS_FOR_TEMPO} alerts — one or two gaps is not a pace"}

    times = sorted(_event_time(row, fallback) for row in ordered)
    gaps = [(later - earlier).total_seconds() for earlier, later in zip(times, times[1:])]
    gaps.sort()
    median = gaps[len(gaps) // 2] if len(gaps) % 2 else (gaps[len(gaps) // 2 - 1] + gaps[len(gaps) // 2]) / 2
    span = (times[-1] - times[0]).total_seconds()

    if median <= BURST_MEDIAN_GAP_SECONDS:
        kind = "burst"
    elif median >= DWELL_MEDIAN_GAP_SECONDS:
        kind = "dwell"
    else:
        kind = "steady"

    return {"kind": kind, "median_gap_seconds": round(median, 1),
            "span_seconds": round(span, 1), "reason": None}


def shape_factor(progression: dict[str, Any], tempo: dict[str, Any]) -> float:
    """
    The multiplier applied to a case's movement, from its direction and pace.

    An interaction rather than two addends. Pace alone means nothing — a fast
    pair of noisy rules is still noise — so it scales movement the case already
    earned instead of contributing points, and a burst of one repeating rule
    multiplies a movement of zero and stays exactly as boring as it was.
    """
    ratio = progression.get("ratio")
    if ratio is None:
        # Not enough staged evidence to say which way it ran. Neutral, not
        # penalised: an absence of direction is not evidence of a bad one.
        factor = 1.0
    else:
        factor = PROGRESSION_MIN_FACTOR + (PROGRESSION_MAX_FACTOR - PROGRESSION_MIN_FACTOR) * ratio

    kind = tempo.get("kind")
    if kind == "burst":
        factor *= TEMPO_BURST_FACTOR
    elif kind == "dwell":
        factor *= TEMPO_DWELL_FACTOR
    return round(factor, 3)


def score_case(
    *,
    distinct_rules: int,
    tactics: set[str],
    max_risk: int,
    verdicts: list[str],
    claimed_only: set[str] | None = None,
    shape: float = 1.0,
) -> tuple[int, list[str]]:
    """
    How much this case deserves attention, and why in words.

    Deliberately not a function of alert count. Volume is what a noisy rule
    produces; agreement between independent detections, and movement across the
    kill chain, are what an attack produces.
    """
    reasons: list[str] = []
    score = 0

    # Rule agreement carries the most weight, because it is the one signal here
    # that does not depend on ATT&CK data being right. This deployment cannot
    # evidence a Kerberos attack at all — its collectors answer questions about
    # domains, addresses and files — so a domain controller showing Kerberoasting
    # and an account change has two independent detections and no evidenced
    # tactics whatsoever. Scoring only what can be evidenced would rank the most
    # interesting case on the estate last.
    if distinct_rules >= 2:
        score += 30 * min(distinct_rules - 1, 3)
        # "agree on this entity" was written when membership was device plus
        # clock, so it claimed corroboration for alerts that shared nothing but
        # a machine and an afternoon. Membership now requires shared evidence,
        # and the wording says what is actually true: these detections fired on
        # activity that is tied together.
        reasons.append(
            f"{distinct_rules} independent detections on linked activity"
        )

    for tactic in tactics:
        if tactic.casefold() not in _TACTIC_RANK:
            _note_unranked(tactic)

    ranks = sorted({_TACTIC_RANK[t.casefold()] for t in tactics if t.casefold() in _TACTIC_RANK})
    if len(ranks) >= 2:
        # Movement is earned from breadth and distance, then scaled by the
        # direction and pace it happened at.
        #
        # `shape` multiplies THIS TERM ONLY, never the running total, and that is
        # load-bearing rather than incidental. The noise case falls out of the
        # algebra instead of needing a rule:
        #
        #     any tempo × no movement = 0
        #
        # Two rules firing 30 seconds apart with nothing evidenced between them
        # multiply a movement of zero and stay exactly as boring as they were.
        # Applying shape to the total instead — the obvious "fix" for making
        # tempo always count — silently re-admits every single-rule burst this
        # excludes, and re-admits them at 1.35x. Do not move this multiplication
        # outward.
        movement = 15 * min(len(ranks) - 1, 3)
        span = TACTIC_ORDER[ranks[-1]]
        reasons.append(
            f"{len(ranks)} ATT&CK tactics touched, reaching {span}"
        )
        # Distance travelled, not just breadth: Discovery→Impact is the shape
        # that matters, and two neighbouring tactics is not that.
        if ranks[-1] - ranks[0] >= 4:
            movement += 20
            reasons.append(
                f"the behaviour advances from {TACTIC_ORDER[ranks[0]]} to {TACTIC_ORDER[ranks[-1]]}"
            )
        score += int(round(movement * shape))

    # Said, not scored. Breadth that exists only in rule mappings is worth
    # showing an analyst and worth nothing in the number.
    # Claimed tactics count for a little. A rule's mapping is its author's
    # hypothesis and this deployment has never once corroborated one, so it is
    # not evidence — but a Kerberoasting rule asserting Credential Access is
    # still information, and treating it as zero throws away the only ATT&CK
    # signal available for attacks the collectors cannot reach. Capped low, and
    # always named as unevidenced so nobody reads it as a finding.
    extra = {t for t in (claimed_only or set()) if t not in tactics}
    if extra:
        score += min(5 * len(extra), 15)
        reasons.append(
            f"{len(extra)} further tactic(s) claimed by the rules, not evidenced here"
        )

    # One bonus, not two. These were separate terms — `max_risk >= 70` and
    # `"malicious" in verdicts` — and they fire on the same population: by
    # dominant source over 1,009 live cases, both at 6.3% for
    # windows_eventchannel, both at 100.0% for appsec-agent, both at 38.6% for
    # Palo Alto syslog. Measured by joining `alert_case_spine` to
    # `alert_body_investigation_runs` and grouping on `graph_source_type`,
    # which is the right pairing because the spine holds the score and the runs
    # hold the source.
    #
    # The asymmetry is structural and worth seeing before changing this
    # function. `indicator_risk_score` (once `highest_risk_score`) is the
    # maximum over an alert's indicators of a seven-component phishing sum, so
    # a source that carries no URL, attachment or email body cannot reach 70
    # unless OpenCTI's step-floor fires. 93.7% of Windows cases therefore
    # cannot earn these points at all, while every appsec-agent case does.
    #
    # Left in place rather than re-scored: 30 points on a 100-point scale whose
    # dominant term is rule agreement (up to 90, source-neutral), and all three
    # of the estate's true positives still rank correctly — #1440 and #1106 at
    # 100, #1833 at 73. Re-scoring on a sample of three would be worse than the
    # bias. If a real severity input arrives, this is the term to replace.
    indicator_evidence = max_risk >= 70 or "malicious" in verdicts
    if indicator_evidence:
        score += 30
        why = []
        if max_risk >= 70:
            why.append(f"an alert's indicators scored {max_risk}/100")
        if "malicious" in verdicts:
            why.append("at least one alert concluded malicious")
        reasons.append(
            " and ".join(why)
            + " — indicator reputation, which endpoint-only sources rarely reach"
        )

    return min(score, 100), reasons


# The indicator values this alert carries. A column now, kept in step with
# `result_json` by a database trigger (migration 040): deriving it here with a
# correlated `jsonb_array_elements` subquery cost 2,398 ms against 30 ms for
# the same query without it — two and a half seconds of every page load spent
# re-deriving a value that never changes.
_IOCS = AlertBodyInvestigationRun.ioc_values.label("ioc_values")


_RUN_COLUMNS = (
    AlertBodyInvestigationRun.id,
    AlertBodyInvestigationRun.title,
    AlertBodyInvestigationRun.status,
    AlertBodyInvestigationRun.created_at,
    AlertBodyInvestigationRun.entity_host,
    AlertBodyInvestigationRun.entity_user,
    AlertBodyInvestigationRun.alert_source,
    AlertBodyInvestigationRun.alert_client,
    AlertBodyInvestigationRun.alert_kind,
    # Read so a case can say whose it is. Cases are grouped by client and host,
    # not by tenant, so without this the payload had no tenant to report and
    # the client selector had to count alert rows instead of cases.
    AlertBodyInvestigationRun.tenant_id,
    AlertBodyInvestigationRun.event_time,
    AlertBodyInvestigationRun.detection_rule_id,
    AlertBodyInvestigationRun.detection_rule_name,
    AlertBodyInvestigationRun.detection_name,
    AlertBodyInvestigationRun.overall_verdict,
    AlertBodyInvestigationRun.indicator_risk_score,
    AlertBodyInvestigationRun.result_attack_assessment,
    _IOCS,
)

# When the alert happened, falling back to when we were told. Runs predating the
# event_time backfill still have to be placeable, and dropping them would hide
# exactly the oldest history the anchor walk needs.
_EVT = func.coalesce(
    AlertBodyInvestigationRun.event_time, AlertBodyInvestigationRun.created_at
)


# The anchor walk pages backwards; this bounds how many pages before it gives up
# and treats what it holds as the session start. Hit only by a chain of unbroken
# sub-6h activity longer than 4 x 72h, which is worth a warning rather than an
# unbounded read.
MAX_ANCHOR_PAGES = 4


async def _extend_to_anchor(
    db: AsyncSession,
    *,
    source: str,
    client: str,
    host: str,
    members: list[Any],
    cutoff: datetime,
    scope: tenant_scope.TenantScope,
) -> list[Any]:
    """Prepend whatever history is needed to place the first member correctly.

    A window boundary landing mid-session invents a session start that never
    happened, and with it a case_key nothing else will ever compute — measured
    at 66.5% of keys disagreeing with the full-history answer. Walking back to a
    gap wider than SESSION_GAP takes that to zero, because a gap that wide splits
    regardless of anything before it.

    The walk cannot stop at SESSION_MAX. Gap-splits are local, but cap-splits are
    not: a chain of unbroken sub-6h activity has a boundary whose position
    depends on where the chain began, arbitrarily far back. Measured on stored
    runs, 46.8% of walks exhaust history without finding a gap at all, so this
    pages rather than assuming a bound.
    """
    ordered = members
    for page in range(MAX_ANCHOR_PAGES):
        earliest = _event_time(ordered[0], cutoff)
        older = (
            await db.execute(
                tenant_scope.apply(
                    select(*_RUN_COLUMNS, _EVT.label("evt")),
                    AlertBodyInvestigationRun.tenant_id,
                    scope,
                )
                .where(
                    AlertBodyInvestigationRun.entity_host == host,
                    _EVT < earliest,
                    _EVT >= earliest - SESSION_LOOKBACK_CHUNK,
                )
                .order_by(_EVT.asc())
                .execution_options(query_name="anchor_walk")
            )
        ).all()
        older = [
            row
            for row in older
            if str(row.alert_source or UNKNOWN_SOURCE) == source
            and str(row.alert_client or UNKNOWN_CLIENT) == client
            and str(row.alert_kind or "alert") != "incident"
        ]
        if not older:
            return ordered
        combined = older + ordered
        times = [_event_time(row, cutoff) for row in combined]
        index = anchor_index(times, len(older))
        if index > 0:
            return combined[index:]
        ordered = combined
    logger.warning(
        "anchor walk for %s gave up after %d pages — unbroken activity longer "
        "than the lookback, so this session start is the earliest event read, "
        "not a measured boundary", host, MAX_ANCHOR_PAGES,
    )
    return ordered


def _iocs_of(row: Any) -> list[str]:
    """The indicator values projected alongside the run, or none."""
    return list(getattr(row, "ioc_values", None) or ())


async def correlate_alerts(
    db: AsyncSession,
    *,
    scope: tenant_scope.TenantScope,
    hours: int = DEFAULT_WINDOW_HOURS,
    # An explicit range, when an analyst picked dates rather than a preset.
    # `hours` still governs how far back membership is computed; these two only
    # decide which of the resulting cases are listed.
    since: datetime | None = None,
    until: datetime | None = None,
    min_rules: int = MIN_DISTINCT_RULES,
    # Whether this pass may write. A *lookup* must not: correlation persists
    # the keys it computes, and the key depends on the window asked for, so
    # every read with a different `hours` minted fresh rows. The closing job
    # checks a hundred candidates a pass with a per-case window and was
    # creating up to a hundred orphans while retiring thirty-nine — the open
    # count went 281 -> 511 -> 570 in half an hour, which is the loop and not
    # the backlog.
    persist: bool = True,
    #: How many of a case's alerts travel in the `alerts` payload. The
    #: default is the long-standing 100; a caller measuring arrival times
    #: must raise it, because the cap keeps the EARLIEST alerts and drops
    #: precisely the late ones. `alerts_truncated` on each case says whether
    #: it bit.
    max_members: int = 100,
    # (source, client, host) — restricts the pass to one entity, for a caller
    # that wants one case rather than the estate.
    only_entity: tuple[str, str, str] | None = None,
    min_score: int = 0,
    limit: int = 50,
    emit: bool = False,
) -> dict[str, Any]:
    """Entities carrying more than one independent detection inside the window.

    `emit` decides whether this run may also *act* — fire case webhooks and
    commission AI narratives. It defaults to False because the usual caller is
    a page load, and a page load queueing a model call per changed case is how
    an analyst reading their queue became the thing that drives the AI bill.
    Reads compute and store; the hourly job in tasks/case_correlation_task.py
    is what acts on what they found.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, hours))
    window = timedelta(hours=max(1, hours))

    # The window is measured from the newest event on each entity, not from the
    # clock. Alerts arrive here replayed — one lagged 323 days — so "the last 48
    # hours" measured against now would empty a host's case the moment ingestion
    # caught up, while the behaviour it described sat unexamined. Relative to the
    # entity means a case stays computable for as long as its own evidence is
    # coherent, whenever we happened to be told about it.
    entity_latest = func.max(_EVT).over(
        partition_by=(
            AlertBodyInvestigationRun.alert_source,
            AlertBodyInvestigationRun.alert_client,
            AlertBodyInvestigationRun.entity_host,
        )
    )
    scoped = (
        tenant_scope.apply(
            select(*_RUN_COLUMNS, _EVT.label("evt"), entity_latest.label("entity_latest"))
            .where(AlertBodyInvestigationRun.entity_host.isnot(None)),
            AlertBodyInvestigationRun.tenant_id,
            scope,
        )
        .subquery()
    )
    entity_filter = []
    if only_entity:
        # One case's page asks for one case. Without this, opening a case ran
        # the whole estate's correlation over thirty days and then scanned the
        # result for a single key — and the Observables tab ran it again. Both
        # measured in seconds; both are one host's work.
        entity_filter = [
            scoped.c.alert_source == only_entity[0],
            scoped.c.alert_client == only_entity[1],
            scoped.c.entity_host == only_entity[2],
        ]

    rows = (
        await db.execute(
            select(scoped)
            .where(scoped.c.evt >= scoped.c.entity_latest - window, *entity_filter)
            .order_by(scoped.c.evt.desc())
            # Named so a reader — a log line, a test double — can tell the
            # three reads this function makes apart without parsing SQL.
            .execution_options(query_name="correlation_window")
        )
    ).all()

    # Learned once for the whole request. Familiarity is a property of the
    # estate, not of any one case, and rebuilding it per case would re-read
    # months of history for every host.
    #
    # The lookback is derived from the window being scored, never fixed: a case
    # is excluded from its own history, so it eats a slice of its baseline sized
    # by the query window, and the multiplier degrades continuously as the two
    # converge. See baseline_window_days.
    baseline = await build_pair_baseline(db, days=baseline_window_days(hours))

    # Keyed on (source, entity), never entity alone. Two platforms watching the
    # same estate name hosts their own way, so joining across them would build a
    # chain out of a Siembiot endpoint alert and an unrelated session alert
    # about a similarly named host — a fabrication that looks exactly like the
    # finding this exists to produce.
    grouped: dict[tuple[str, str, str], list[Any]] = defaultdict(list)
    # Pre-correlated payloads, each its own case. Held apart from `grouped`
    # so nothing can pool them with the alerts they summarise.
    incidents: list[Any] = []
    for row in rows:
        # A payload that is already a session is a case, not a member of one.
        # A TraceCat incident arrives carrying fifty events and their triggered
        # rules; grouping it beside single Wazuh alerts would compare a case to
        # its own parts and count one platform's summary as corroboration of
        # another's detail.
        if str(row.alert_kind or "alert") == "incident":
            # A payload that is already a session is a case, not a member of
            # one — grouping it beside single alerts would compare a case to
            # its own parts and count one platform's summary as corroboration
            # of another's detail.
            #
            # It used to be dropped here and nowhere picked up, so the premise
            # was never implemented: 18 incident rows on 8 hosts produced
            # exactly zero cases, with no SLA clock and nothing on the page.
            # It gets a case of its own instead, keyed on the row so it can
            # never be pooled with anything.
            incidents.append(row)
            continue
        grouped[(
            str(row.alert_source or UNKNOWN_SOURCE),
            str(row.alert_client or UNKNOWN_CLIENT),
            str(row.entity_host),
        )].append(row)

    # Learned once for the whole request, like the pair baseline above and for
    # the same reason: whether an indicator describes the estate or an incident
    # is not a property of any one case.
    # Estate-wide, computed independently of whatever this pass fetched. It
    # used to be derived from `rows`, so narrowing the pass to one entity
    # silently changed which indicators could link — and the same host came
    # back as 12 cases scoped and 34 unscoped.
    ubiquitous = await ubiquitous_values_across_estate(db, since=cutoff)
    # case_key -> the answered case it carries on from, filled while clusters
    # are assembled and read when the spine rows are written.
    continuations: dict[str, tuple[str, str | None]] = {}

    settings = get_settings()
    emissions: list[dict[str, Any]] = []
    narrative_jobs: list[tuple[str, dict[str, Any], str]] = []
    cases: list[dict[str, Any]] = []
    # Each incident becomes a group of its own, keyed on the row, so it forms
    # a single-member case and can never be pooled with the alerts it
    # summarises. Added before the loop below so it takes the same path as
    # everything else — session, spine row, case number, closure, SLA.
    for incident in incidents:
        grouped[(
            str(incident.alert_source or UNKNOWN_SOURCE),
            str(incident.alert_client or UNKNOWN_CLIENT),
            f"{incident.entity_host or 'unknown'}\x1fincident:{incident.id}",
        )].append(incident)

    for (source, client, entity), group_members in grouped.items():
        in_window = {m.id for m in group_members}
        # The window framed these members; the session they belong to may start
        # before it. Walk back to a real boundary before deciding where sessions
        # begin, or the first session's start is an artefact of the query.
        history = await _extend_to_anchor(
            db, source=source, client=client, host=entity,
            members=sorted(group_members, key=lambda m: _event_time(m, cutoff)),
            cutoff=cutoff,
            # The walk reads history outside the window. Unscoped it would pull
            # another client's alerts on a same-named host into this case, and
            # a session start is exactly the kind of thing nobody re-checks.
            scope=scope,
        )
        assignments = assign_sessions(
            [(row.id, _event_time(row, cutoff)) for row in history],
            source=source, client=client, host=entity,
        )
        sessions: dict[str, list[Any]] = defaultdict(list)
        session_of: dict[str, Any] = {}
        for assignment, row in zip(assignments, history):
            sessions[assignment.case_key].append(row)
            session_of.setdefault(assignment.case_key, assignment)

        # The session bounds a case in time; evidence decides who is in it.
        # Grouping by device and clock alone put a password change, a system
        # critical event six hours later and a .NET crash in one case, and
        # then told the analyst three independent detections agreed.
        linked_sessions: dict[str, list[Any]] = {}
        session_anchor: dict[str, Any] = {}
        for base_key, session_members in sessions.items():
            ordered_members = sorted(session_members, key=lambda m: _event_time(m, cutoff))
            clusters = cluster_linked(ordered_members, _iocs_of, ubiquitous=ubiquitous)
            for cluster in clusters:
                # Identity comes from the cluster's own earliest event, the same
                # way a session's does: a property of what happened, never of
                # where the query happened to start. Clusters that begin at the
                # same instant are told apart by their earliest run id, which is
                # stable for as long as the membership is.
                first = min(cluster, key=lambda m: (_event_time(m, cutoff), str(m.id)))
                # Always discriminated, never conditionally.
                #
                # This was `base_key if len(clusters) == 1 else ...`, which
                # made a case's identity depend on how many *other* cases its
                # session happened to contain. A session with one cluster
                # minted `base_key`; the moment a second cluster appeared —
                # one unrelated alert on the same host — the first cluster's
                # key became a different hash, and the spine row written under
                # the old one was orphaned. It could never be read, closed or
                # shown again, and it stayed `closed_at IS NULL` for ever.
                #
                # Measured: 31 of 31 open spine rows were orphaned this way,
                # including cases six minutes old, and every one of them was
                # being counted as an active case on the Reports page.
                #
                # Keyed on the cluster's own earliest member instead, which is
                # a property of this cluster and does not move when another
                # one appears beside it. An earlier alert joining *this*
                # cluster still changes it, which is what supersession exists
                # to follow.
                cluster_key = case_key_for(
                    source, client, entity, _event_time(first, cutoff),
                    discriminator=str(first.id),
                )
                linked_sessions[cluster_key] = cluster
                session_anchor[cluster_key] = session_of[base_key]

        # A case that has already been answered does not quietly grow. Alerts
        # that arrived after it closed are appended when they add nothing —
        # 99% of them, measured — and split into a continuation case when one
        # brings a detection the case never saw. Reopening is deliberately not
        # an option: closing stops the SLA clock, and a straggler at hour
        # sixteen would turn a four-minute resolution into a sixteen-hour one.
        existing = await spines_for_entity(db, source=source, client=client, host=entity)
        for closed_key in list(linked_sessions):
            spine_row = existing.get(closed_key)
            if spine_row is None or spine_row.closed_at is None:
                continue
            answered, late = closure_rules.split_after_closure(
                linked_sessions[closed_key], closed_at=spine_row.closed_at, now=cutoff,
            )
            if not late.needs_continuation:
                continue
            # The closed case keeps exactly what it was answered on. It does
            # not go on absorbing alerts: case #117 closed at 09:48 and was
            # still taking alerts at 10:59, so a morning of activity produced
            # no case an analyst could see.
            linked_sessions[closed_key] = answered
            follow_on = late.continuation
            first = min(follow_on, key=lambda m: (_event_time(m, cutoff), str(m.id)))
            follow_key = case_key_for(
                source, client, entity, _event_time(first, cutoff),
                discriminator=f"continues:{closed_key[:16]}",
            )
            linked_sessions[follow_key] = follow_on
            session_anchor[follow_key] = session_anchor[closed_key]
            # The parent, and whether this continuation can inherit its answer.
            # A continuation bringing nothing new is closed with the parent's
            # resolution and never reaches a model — 47% of them, measured.
            continuations[follow_key] = (
                closed_key,
                spine_row.resolution if late.inherits else None,
            )

        sessions = linked_sessions
        session_of = session_anchor
        # Computed before the loop below writes anything, so absorption can
        # never eat a case this very pass is about to produce.
        live_keys = frozenset(sessions)

        for case_key, members in sessions.items():
            # A session is shown when the window reaches any part of it, and is
            # then shown whole. The case is the session; showing only the slice
            # the window framed would report a fragment of an intrusion as its
            # extent, and would give it a start that never happened.
            if not any(m.id in in_window for m in members):
                continue
            session = session_of[case_key]
            # What fired, not what carried it.
            #
            # A case needs two *independent* detections. Counting by rule id
            # alone made every alert under a generic Wazuh carrier look like
            # one rule: exprevpxy002 holds 2,686 alerts under rule 1002, which
            # is three different detections counted as one, which is one short
            # of a case. The busiest host after the test machine formed none.
            #
            # detection_name is preferred where the alert carries one; the rule
            # id remains the identity when it does not.
            rules = {
                str(m.detection_name or m.detection_rule_id or m.detection_rule_name or "")
                for m in members
            }
            rules.discard("")
            # `rules` empty means the alerts carry no detection identity at
            # all — not that they carry too few. The threshold answers "did
            # enough independent detections agree", which is a question about
            # a cluster that has detections; applied to one that has none it
            # silently deleted the alerts. 805 rows estate-wide have no
            # detection_name, rule id or rule name, and 151 of them concluded
            # malicious: every one was invisible to the analyst and outside
            # MTTD and MTTR.
            if rules and len(rules) < min_rules:
                continue

            tactics: set[str] = set()
            claimed: set[str] = set()
            for member in members:
                evidenced_t, claimed_t = _tactics_of(member.result_attack_assessment)
                tactics |= evidenced_t
                claimed |= claimed_t

            # Ordered by when things happened on the host, not by when this
            # platform heard about them. Everything below reads this order.
            #
            # The id breaks ties, as it already does for continuations: the
            # case is now named after `ordered[0]`, and two alerts sharing an
            # event time would otherwise let the title flip between recomputes
            # depending on what the database happened to return first.
            ordered = sorted(members, key=lambda m: (_event_time(m, cutoff), str(m.id)))
            progression = progression_of(ordered, cutoff)
            tempo = tempo_of(ordered, cutoff)
            shape = shape_factor(progression, tempo)

            verdicts = [str(m.overall_verdict or "") for m in members]
            max_risk = max((int(m.indicator_risk_score or 0) for m in members), default=0)
            raw_score, reasons = score_case(
                shape=shape,
                distinct_rules=len(rules), tactics=tactics, max_risk=max_risk,
                verdicts=verdicts, claimed_only=claimed,
            )

            # How ordinary this combination is on this host, applied as a multiplier
            # rather than a subtraction. A penalty can be out-voted by enough
            # kill-chain shape; a multiplier cannot, which is the point — a pairing
            # that happens here every day should not become interesting merely by
            # happening in an interesting order.
            own_days = {_event_time(m, cutoff).date() for m in members}
            surprise, surprise_detail = case_surprise(
                baseline.pairs, source=source, client=client, host=entity,
                rules=rules, own_days=own_days,
            )
            score = int(round(raw_score * surprise))

            if progression["ratio"] is not None and progression["ratio"] >= 0.8:
                reasons.append(
                    f"{progression['forward']} of {progression['transitions']} stage transitions "
                    "run forward along the kill chain"
                )
            if tempo["kind"] == "burst":
                reasons.append(
                    f"burst — a median of {tempo['median_gap_seconds']:.0f}s between alerts"
                )
            elif tempo["kind"] == "dwell":
                reasons.append(
                    f"low and slow — a median of {tempo['median_gap_seconds'] / 3600:.1f}h between alerts"
                )

            if surprise_detail:
                familiar = min(surprise_detail, key=lambda item: item["surprise"])
                novel = surprise_detail[0]
                if novel["cooccurrence_days"] == 0:
                    reasons.append(
                        f"{novel['rules'][0]} + {novel['rules'][1]} have not co-fired on this "
                        "host before"
                    )
                elif surprise <= 0.25:
                    reasons.append(
                        f"routine for this host — {familiar['rules'][0]} + {familiar['rules'][1]} "
                        f"co-fire on {familiar['cooccurrence_days']} of the last "
                        f"{baseline.window_days} days"
                    )

            cases.append(
                {
                    # The session's identity, stable across query windows.
                    # session_seq rides along as a label only.
                    "case_key": case_key,
                    "session_seq": session.session_seq,
                    "session_started_at": _iso(session.session_started_at),
                    "source": source,
                    "client": client,
                    "entity_host": entity.split("\x1f", 1)[0],
                    # Whose case this is. Every member shares a client and a
                    # host, so a case has one tenant; `sorted(...)[0]` is a
                    # formality that also refuses to invent one when the
                    # members are unassigned.
                    "tenant_id": next(
                        iter(sorted({m.tenant_id for m in members if m.tenant_id})), None
                    ),
                    "entity_users": sorted({str(m.entity_user) for m in members if m.entity_user}),
                    # Computed once, server-side, so the list and the detail
                    # page cannot render the same case under two names.
                    "label": case_label(
                        # Split, because a pre-correlated incident's entity is
                        # the composite key `{host}\x1fincident:{id}`. 18
                        # stored titles carry a literal U+001F — the payload's
                        # own `entity_host` below already splits it, and these
                        # two had drifted apart.
                        host=str(entity).split("\x1f", 1)[0],
                        users=sorted({str(m.entity_user) for m in members if m.entity_user}),
                        tactics=sorted(tactics, key=lambda t: _TACTIC_RANK.get(t.casefold(), 99)),
                        members=members,
                        # The alert that opened the case, in event-time order.
                        ordered=ordered,
                    ),
                    "window_hours": hours,
                    # The span the behaviour occupied on the host. Reported from
                    # event time so a replayed alert does not stretch a case across
                    # days it did not happen in.
                    "first_seen": _iso(_event_time(ordered[0], cutoff)),
                    "last_seen": _iso(_event_time(ordered[-1], cutoff)),
                    "first_ingested": _iso(ordered[0].created_at),
                    "last_ingested": _iso(ordered[-1].created_at),
                    "alert_count": len(members),
                    # A run joins its case the moment it is created — the host, the rule
                    # and the event time are all set before the investigation starts, so
                    # a case is visible about a second after its second alert arrives.
                    # This says how much of it is still being worked out: without it an
                    # analyst reading a brand-new case sees a low score and no tactics
                    # and cannot tell "nothing here" from "not yet".
                    "members_investigating": sum(
                        1
                        for m in members
                        if str(getattr(m, "status", "") or "")
                        not in ("completed", "failed")
                    ),
                    "distinct_rules": len(rules),
                    "tactics": sorted(tactics, key=lambda t: _TACTIC_RANK.get(t.casefold(), 99)),
                    "tactics_claimed_only": sorted(
                        {t for t in claimed if t not in tactics},
                        key=lambda t: _TACTIC_RANK.get(t.casefold(), 99),
                    ),
                    "max_risk_score": max_risk,
                    # All three kept apart. When a case scores low the next question
                    # is always whether its shape was unremarkable or its rules were
                    # familiar, and one number cannot answer that.
                    "raw_score": raw_score,
                    # Direction and pace reported as measurements, not folded into
                    # the number they modulated. A case scoring 60 tells you nothing
                    # about whether it ran forwards.
                    "progression": progression,
                    "tempo": tempo,
                    "shape_factor": shape,
                    "surprise": round(surprise, 3),
                    "surprise_detail": surprise_detail[:8],
                    "score": score,
                    "reasons": reasons,
                    "alerts": [
                        {
                            "run_id": str(m.id),
                            "title": m.title,
                            "event_time": _iso(_event_time(m, cutoff)),
                            "created_at": _iso(m.created_at),
                            "detection_rule_id": m.detection_rule_id,
                            # What fired, and separately the rule that carried
                            # it. They are routinely different: rule 60104 is
                            # "Windows audit failure event" and the detection
                            # under it is "Denied Access To Remote Desktop".
                            # Both travel, because the detection is what the
                            # alert is about and the rule is what a tuning
                            # change acts on.
                            "detection_name": m.detection_name,
                            "detection_rule_name": m.detection_rule_name,
                            # Who ran it. The case is per-device, so the
                            # account is the one thing that distinguishes one
                            # person's activity on it from another's — and it
                            # has to be carried per alert, because a case can
                            # span several accounts and naming only the set
                            # loses which alert belonged to whom.
                            "entity_user": m.entity_user,
                            "overall_verdict": m.overall_verdict,
                            "highest_risk_score": m.indicator_risk_score,
                        }
                        for m in ordered
                    ][:max_members],
                    # Whether the list above is the whole case.
                    #
                    # It silently was not. `ordered` is ascending by event
                    # time, so the cap kept the EARLIEST alerts and discarded
                    # the latest: 24 cases are over it and 6,533 of 12,064
                    # memberships (54.2%) sit in the discarded tail. Any
                    # consumer measuring when alerts arrive was reading a list
                    # with exactly the late arrivals removed — #1849 shows the
                    # first 100 of 1,889 alerts, #71 the first 100 of 1,217.
                    #
                    # `alert_count` already differed from `len(alerts)`, so the
                    # truncation was detectable and nothing detected it. This
                    # says so outright, so the next consumer cannot miss it.
                    "alerts_truncated": len(members) > max_members,
                    "alerts_shown": min(len(members), max_members),
                }
            )

            # Persistence is an overlay. Membership was computed above from
            # event time and is deliberately not written down; what is stored is
            # only the part that has to survive the read — ownership, status,
            # and how the score moved.
            last_event = _event_time(ordered[-1], cutoff)
            case_payload = cases[-1]
            if not persist:
                # Read-only: attach whatever the stored row already says and
                # write nothing. A lookup that created a case was the loop
                # this exists to break.
                existing_row = await db.get(AlertCaseSpine, case_key)
                if existing_row is not None:
                    case_payload["case_number"] = existing_row.case_number
                    case_payload["lifecycle"] = {
                        "status": existing_row.status,
                        "closed_at": _iso(existing_row.closed_at),
                        "closure_kind": existing_row.closure_kind,
                        "resolution": existing_row.resolution,
                        "alerts_at_close": existing_row.alerts_at_close,
                        **closure_rules.metrics(
                            opened_at=existing_row.opened_at,
                            created_at=existing_row.created_at,
                            closed_at=existing_row.closed_at,
                        ),
                    }
                    case_payload["narrative"] = {
                        **narrative_lead(existing_row.narrative_markdown),
                        "status": existing_row.narrative_status,
                        "generated_at": _iso(existing_row.narrative_generated_at),
                    }
                continue
            await absorb_superseded(
                db,
                live_case_key=case_key,
                source=source,
                client=client,
                host=entity,
                session_started_at=session.session_started_at,
                session_ended_at=last_event,
                known=existing,
                # Every case key this pass is producing. A key in here is a
                # case that exists right now with its own alerts, so it is
                # never absorbed whatever the session arithmetic says — which
                # is the whole of the fix: a session yields several cases now,
                # and "another key inside this session" had come to mean "a
                # sibling about something else".
                protected_keys=live_keys,
            )
            spine = await upsert_spine(
                db,
                case_key=case_key,
                source=source,
                client=client,
                host=entity,
                # The client this case is for, from the alerts themselves
                # rather than from the label the sender attached. Taken from
                # the members, which the scope already selected, so it is the
                # same answer the query was asked under.
                tenant_id=next(
                    (str(m.tenant_id) for m in members if getattr(m, "tenant_id", None)),
                    None,
                ),
                session_started_at=session.session_started_at,
                first_alert_at=_event_time(first, cutoff),
                session_seq=session.session_seq,
                last_activity_at=last_event,
                score=score,
                score_version=SCORE_VERSION,
                # Stored so a closed case keeps the name it was closed under,
                # and a continuation can name the case it follows exactly as
                # that case names itself.
                title=case_payload.get("label"),
                known=existing,
            )
            # Said on the case itself, so an analyst reading a continuation can
            # see which answered case it carries on from without re-deriving
            # the chain from timestamps.
            if case_key in continuations and not spine.continues_case_key:
                parent_key, inherited = continuations[case_key]
                spine.continues_case_key = parent_key
                if inherited and not spine.resolution:
                    # An answer already given. The closing job sees a case that
                    # arrives with its resolution and closes it without asking
                    # a model the same question twice.
                    spine.resolution = inherited
            # Score history and escalation are the scheduled job's business,
            # not a page load's.
            #
            # These four queries per case ran on every read — 336 of the 618 a
            # single listing issued — and their results were then discarded
            # unless `emit`, because nothing is dispatched from a read. Worse,
            # `record_emission` below marks a snapshot as escalated, so a read
            # could consume an escalation that was never delivered.
            #
            # A read now computes the case and reports it. The hourly pass in
            # tasks/case_correlation_task.py is what writes down how the score
            # moved and what to notify about, which is what the snapshot
            # docstring asks for: record what the case did, not how often
            # someone opened it.
            outcome = None
            if emit:
                outcome = await snapshot_if_changed(
                    db,
                    case_key=case_key,
                    score=score,
                    raw_score=raw_score,
                    surprise=surprise,
                    member_count=len(members),
                    tactics=tactics,
                    score_version=SCORE_VERSION,
                )
            # The overall reading of the case, written out of band. Queued only
            # when the case says something different from what the narrative was
            # written about — analysing on every recompute would spend the token
            # budget on page loads. The stored narrative is attached either way,
            # so an unchanged case shows the reading it already has.
            fingerprint = narrative_fingerprint(
                score=score, member_count=len(members), tactics=tactics
            )
            if spine.narrative_fingerprint != fingerprint:
                narrative_jobs.append((case_key, case_payload, fingerprint))
            # The verdict and opening paragraph only. The full report is
            # fetched when someone opens it — shipping every word to every row
            # made this response 63% text nobody had asked to read, on a list
            # that refreshes every 30 seconds.
            # The lifecycle an analyst reads: the number they say out loud,
            # whether it has been answered, how long that took, and the case it
            # carries on from.
            case_payload["case_number"] = spine.case_number
            case_payload["lifecycle"] = {
                "status": spine.status,
                "closed_at": _iso(spine.closed_at),
                "closure_kind": spine.closure_kind,
                "resolution": spine.resolution,
                "alerts_at_close": spine.alerts_at_close,
                **closure_rules.metrics(
                    opened_at=spine.opened_at,
                    created_at=spine.created_at,
                    closed_at=spine.closed_at,
                ),
            }
            case_payload["continues"] = await case_reference(db, spine.continues_case_key)

            case_payload["narrative"] = {
                **narrative_lead(spine.narrative_markdown),
                "has_full": bool(spine.narrative_markdown),
                "status": (
                    spine.narrative_status
                    if spine.narrative_fingerprint == fingerprint
                    else ("stale" if spine.narrative_markdown else "queued")
                ),
                "generated_at": _iso(spine.narrative_generated_at),
                "assistant_session_id": spine.narrative_session_id,
                "error": spine.narrative_error,
            }

            emission = None if outcome is None else await decide_emission(
                db,
                case_key=case_key,
                outcome=outcome,
                score=score,
                score_version=SCORE_VERSION,
                escalation_delta=settings.correlation_escalation_delta,
                escalation_min_score=settings.correlation_escalation_min_score,
                opened_high_min_score=settings.correlation_opened_high_min_score,
            )
            if emission is not None:
                # Recorded now, delivered after the commit below. A receiver
                # that reacts instantly must not be able to beat the record it
                # is reacting to.
                record_emission(outcome, emission)
                emissions.append(
                    {
                        "event": emission.event,
                        "case_key": emission.case_key,
                        "entity_host": entity,
                        "source": source,
                        "client": client,
                        "score": emission.score,
                        "reference_score": emission.reference_score,
                        "score_version": emission.score_version,
                        "delta_config": emission.delta_config,
                        "min_score_config": emission.min_score_config,
                        "reason": emission.reason,
                        "session_started_at": _iso(session.session_started_at),
                        "alert_count": len(members),
                        "tactics": sorted(tactics),
                    }
                )

    # The overlay is written for every case that formed, not only the ones this
    # request will display: a case filtered out by min_score is still a case
    # that happened, and its history should not depend on how the page happened
    # to be filtered when it was last opened.
    await db.commit()

    # Only now. Everything above is a record; these are the only lines that
    # speak to anyone outside the process, and they speak about facts already
    # stored — which is why they are safe to withhold from a read and do later.
    if emit:
        if emissions:
            dispatch(emissions)
        if narrative_jobs:
            dispatch_narratives(narrative_jobs)
    elif emissions or narrative_jobs:
        logger.debug(
            "correlation found %s emission(s) and %s narrative job(s); left for the scheduled run",
            len(emissions), len(narrative_jobs),
        )

    # The window does two jobs, and they are not the same job.
    #
    # Membership is measured from the entity's own newest event, which is what
    # lets a chain replayed weeks late still form a case at all. Listing is
    # measured from now, because "48 hours" on a control an analyst clicks means
    # "what has been happening lately" — and without this it did not: a case
    # whose alerts were three weeks old appeared under 48 hours because they sat
    # within 48 hours of each other, so every window showed the same cases at
    # the top and the control looked broken.
    # An explicit range says exactly which cases to list and is used as given.
    # Without one the window is the rolling "what has been happening lately".
    horizon = since or (datetime.now(timezone.utc) - timedelta(hours=max(1, hours)))

    def within_window(case: dict[str, Any]) -> bool:
        last_seen = case.get("last_seen")
        if not last_seen:
            return True
        try:
            when = datetime.fromisoformat(str(last_seen))
        except ValueError:
            return True
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if until is not None and when > until:
            return False
        return when >= horizon

    cases = [case for case in cases if within_window(case)]

    if min_score:
        cases = [case for case in cases if case["score"] >= min_score]
    cases.sort(key=lambda case: (-case["score"], -case["distinct_rules"]))
    return {
        "window_hours": hours,
        # Reported so a multiplier of 1.0 can be read correctly. "Never seen
        # before" and "nothing has been seen yet" produce the same number and
        # mean opposite things.
        "baseline": baseline.as_dict(),
        # Watched rather than merely logged: the supersession gate is the one
        # path real data has not exercised yet, and it activates first on the
        # noisiest host in the estate.
        "supersession": await supersession_state(db),
        "entities_seen": len(grouped),
        "sources_seen": len({key[0] for key in grouped}),
        "clients_seen": len({key[1] for key in grouped}),
        "cases": cases[:limit],
        "total_cases": len(cases),
    }


async def case_for_run(
    db: AsyncSession, run_id: Any, *, scope: tenant_scope.TenantScope,
    hours: int = DEFAULT_WINDOW_HOURS,
) -> dict[str, Any] | None:
    """
    The case this one alert belongs to, if any.

    What the alert page asks: an analyst reading a single alert has no way to
    know it is one of five on that machine tonight, and that is the fact that
    changes what they do next.
    """
    run = await db.get(AlertBodyInvestigationRun, run_id)
    if run is None or not run.entity_host:
        return None

    result = await correlate_alerts(db, scope=scope, hours=hours, limit=500)
    for case in result["cases"]:
        if case["source"] != str(run.alert_source or UNKNOWN_SOURCE):
            continue
        if case["client"] != str(run.alert_client or UNKNOWN_CLIENT):
            continue
        if case["entity_host"] == run.entity_host and any(
            alert["run_id"] == str(run.id) for alert in case["alerts"]
        ):
            return case
    return None


async def case_by_key(
    db: AsyncSession, case_key: str, *, scope: tenant_scope.TenantScope,
    hours: int = 720, max_members: int = 100
) -> dict[str, Any] | None:
    """One case, found by the identity that survives a change of window.

    Recomputed rather than read back from the spine, because membership is not
    stored: the spine carries who owns the case and how its score moved, and the
    alerts in it are always derived from event time. Looking the case up by key
    is exactly what the stable identity was built to make possible — the same
    key resolves to the same case whether the caller asks over 48 hours or 30
    days, so a bookmarked case page does not depend on the window it was opened
    with.
    """
    # The spine row names the entity, so the pass can be restricted to it.
    # Correlating the whole estate to find one case took seconds, and the case
    # page paid it twice — once for the case, once for its observables.
    spine = await db.get(AlertCaseSpine, case_key)
    only_entity = (
        (spine.alert_source, spine.alert_client, spine.entity_host) if spine else None
    )
    result = await correlate_alerts(
        db, scope=scope, hours=hours, limit=500, only_entity=only_entity,
        # A lookup never writes. This is called a hundred times a pass by the
        # closing job, each with its own window, and correlation persists the
        # keys it computes — so looking for a case was minting new ones.
        persist=False,
        # Threaded through, because a caller that draws the case needs all of
        # it. The default keeps every existing caller's payload size; the graph
        # endpoint raises it, having been handed the earliest 100 alerts of a
        # 1,889-alert case and drawing that as the incident.
        max_members=max_members,
    )
    for case in result["cases"]:
        if case.get("case_key") == case_key:
            return case
    # A continuation or a split cluster carries a synthetic entity key, and an
    # unknown case_key has no spine row to narrow by. Falling back to the full
    # pass keeps those answerable rather than returning a wrong "no such case".
    if only_entity is None:
        return None
    result = await correlate_alerts(db, scope=scope, hours=hours, limit=500)
    for case in result["cases"]:
        if case.get("case_key") == case_key:
            return case
    return None
