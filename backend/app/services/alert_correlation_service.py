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
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun
from app.services.alert_baseline_service import (
    baseline_window_days,
    build_pair_baseline,
    case_surprise,
)
from app.services.alert_case_store import (
    absorb_superseded,
    snapshot_if_changed,
    upsert_spine,
)
from app.services.alert_field_service import UNKNOWN_CLIENT, UNKNOWN_SOURCE
from app.services.alert_session_service import (
    SCORE_VERSION,
    SESSION_GAP,
    SESSION_LOOKBACK_CHUNK,
    anchor_index,
    assign_sessions,
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
# One rule firing repeatedly is one detection, however loud. A case needs two
# independent rules to agree before it is worth anyone's attention.
MIN_DISTINCT_RULES = 2


def _event_time(row: Any, fallback: datetime) -> datetime:
    """
    When this alert's event happened, with ingest time as the last resort.

    Runs stored before the event_time column existed have none, and a null would
    sort unpredictably against real timestamps. Falling back to created_at keeps
    every member on one comparable scale — the backfill then replaces the
    fallback with the real value wherever the body carries one.
    """
    return getattr(row, "event_time", None) or row.created_at or fallback


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
        reasons.append(f"{distinct_rules} independent detections agree on this entity")

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

    if max_risk >= 70:
        score += 15
        reasons.append(f"an alert in this window scored {max_risk}/100 on its own")
    if "malicious" in verdicts:
        score += 15
        reasons.append("at least one alert concluded malicious")

    return min(score, 100), reasons


_RUN_COLUMNS = (
    AlertBodyInvestigationRun.id,
    AlertBodyInvestigationRun.title,
    AlertBodyInvestigationRun.created_at,
    AlertBodyInvestigationRun.entity_host,
    AlertBodyInvestigationRun.entity_user,
    AlertBodyInvestigationRun.alert_source,
    AlertBodyInvestigationRun.alert_client,
    AlertBodyInvestigationRun.alert_kind,
    AlertBodyInvestigationRun.event_time,
    AlertBodyInvestigationRun.detection_rule_id,
    AlertBodyInvestigationRun.detection_rule_name,
    AlertBodyInvestigationRun.overall_verdict,
    AlertBodyInvestigationRun.highest_risk_score,
    AlertBodyInvestigationRun.result_attack_assessment,
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
                select(*_RUN_COLUMNS, _EVT.label("evt"))
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


async def correlate_alerts(
    db: AsyncSession,
    *,
    hours: int = DEFAULT_WINDOW_HOURS,
    min_rules: int = MIN_DISTINCT_RULES,
    min_score: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Entities carrying more than one independent detection inside the window."""
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
        select(*_RUN_COLUMNS, _EVT.label("evt"), entity_latest.label("entity_latest"))
        .where(AlertBodyInvestigationRun.entity_host.isnot(None))
        .subquery()
    )
    rows = (
        await db.execute(
            select(scoped)
            .where(scoped.c.evt >= scoped.c.entity_latest - window)
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
    for row in rows:
        # A payload that is already a session is a case, not a member of one.
        # A TraceCat incident arrives carrying fifty events and their triggered
        # rules; grouping it beside single Wazuh alerts would compare a case to
        # its own parts and count one platform's summary as corroboration of
        # another's detail.
        if str(row.alert_kind or "alert") == "incident":
            continue
        grouped[(
            str(row.alert_source or UNKNOWN_SOURCE),
            str(row.alert_client or UNKNOWN_CLIENT),
            str(row.entity_host),
        )].append(row)

    cases: list[dict[str, Any]] = []
    for (source, client, entity), group_members in grouped.items():
        in_window = {m.id for m in group_members}
        # The window framed these members; the session they belong to may start
        # before it. Walk back to a real boundary before deciding where sessions
        # begin, or the first session's start is an artefact of the query.
        history = await _extend_to_anchor(
            db, source=source, client=client, host=entity,
            members=sorted(group_members, key=lambda m: _event_time(m, cutoff)),
            cutoff=cutoff,
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

        for case_key, members in sessions.items():
            # A session is shown when the window reaches any part of it, and is
            # then shown whole. The case is the session; showing only the slice
            # the window framed would report a fragment of an intrusion as its
            # extent, and would give it a start that never happened.
            if not any(m.id in in_window for m in members):
                continue
            session = session_of[case_key]
            rules = {str(m.detection_rule_id or m.detection_rule_name or "") for m in members}
            rules.discard("")
            if len(rules) < min_rules:
                continue

            tactics: set[str] = set()
            claimed: set[str] = set()
            for member in members:
                evidenced_t, claimed_t = _tactics_of(member.result_attack_assessment)
                tactics |= evidenced_t
                claimed |= claimed_t

            # Ordered by when things happened on the host, not by when this
            # platform heard about them. Everything below reads this order.
            ordered = sorted(members, key=lambda m: _event_time(m, cutoff))
            progression = progression_of(ordered, cutoff)
            tempo = tempo_of(ordered, cutoff)
            shape = shape_factor(progression, tempo)

            verdicts = [str(m.overall_verdict or "") for m in members]
            max_risk = max((int(m.highest_risk_score or 0) for m in members), default=0)
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
                    "entity_host": entity,
                    "entity_users": sorted({str(m.entity_user) for m in members if m.entity_user}),
                    "window_hours": hours,
                    # The span the behaviour occupied on the host. Reported from
                    # event time so a replayed alert does not stretch a case across
                    # days it did not happen in.
                    "first_seen": _iso(_event_time(ordered[0], cutoff)),
                    "last_seen": _iso(_event_time(ordered[-1], cutoff)),
                    "first_ingested": _iso(ordered[0].created_at),
                    "last_ingested": _iso(ordered[-1].created_at),
                    "alert_count": len(members),
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
                            "detection_rule_name": m.detection_rule_name,
                            "overall_verdict": m.overall_verdict,
                            "highest_risk_score": m.highest_risk_score,
                        }
                        for m in ordered
                    ][:100],
                }
            )

            # Persistence is an overlay. Membership was computed above from
            # event time and is deliberately not written down; what is stored is
            # only the part that has to survive the read — ownership, status,
            # and how the score moved.
            last_event = _event_time(ordered[-1], cutoff)
            await absorb_superseded(
                db,
                live_case_key=case_key,
                source=source,
                client=client,
                host=entity,
                session_started_at=session.session_started_at,
                session_ended_at=last_event,
            )
            await upsert_spine(
                db,
                case_key=case_key,
                source=source,
                client=client,
                host=entity,
                session_started_at=session.session_started_at,
                session_seq=session.session_seq,
                last_activity_at=last_event,
                score=score,
                score_version=SCORE_VERSION,
            )
            await snapshot_if_changed(
                db,
                case_key=case_key,
                score=score,
                raw_score=raw_score,
                surprise=surprise,
                member_count=len(members),
                tactics=tactics,
                score_version=SCORE_VERSION,
            )

    # The overlay is written for every case that formed, not only the ones this
    # request will display: a case filtered out by min_score is still a case
    # that happened, and its history should not depend on how the page happened
    # to be filtered when it was last opened.
    await db.commit()

    if min_score:
        cases = [case for case in cases if case["score"] >= min_score]
    cases.sort(key=lambda case: (-case["score"], -case["distinct_rules"]))
    return {
        "window_hours": hours,
        # Reported so a multiplier of 1.0 can be read correctly. "Never seen
        # before" and "nothing has been seen yet" produce the same number and
        # mean opposite things.
        "baseline": baseline.as_dict(),
        "entities_seen": len(grouped),
        "sources_seen": len({key[0] for key in grouped}),
        "clients_seen": len({key[1] for key in grouped}),
        "cases": cases[:limit],
        "total_cases": len(cases),
    }


async def case_for_run(db: AsyncSession, run_id: Any, *, hours: int = DEFAULT_WINDOW_HOURS) -> dict[str, Any] | None:
    """
    The case this one alert belongs to, if any.

    What the alert page asks: an analyst reading a single alert has no way to
    know it is one of five on that machine tonight, and that is the fact that
    changes what they do next.
    """
    run = await db.get(AlertBodyInvestigationRun, run_id)
    if run is None or not run.entity_host:
        return None

    result = await correlate_alerts(db, hours=hours, limit=500)
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
