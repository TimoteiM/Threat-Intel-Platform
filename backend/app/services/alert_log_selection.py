"""Choosing which retrieved log events go to the model, and saying why.

An alert's window can hold five hundred events. The model gets a few dozen. The
whole question is which, and the answer has to be defensible to an analyst
reading a verdict: *these nine events were considered, these four hundred were
not, and here is the rule that decided.*

Three things it deliberately is not.

**It is not a second AI call.** Asking a model which logs to send a model costs
the thing it is meant to save and makes the selection unexplainable. Every rule
here is arithmetic over fields, and `explain()` prints the whole score.

**It is not a severity sort.** Wazuh `rule.level` and rule groups are ranking
signals, not truth — level 3 noise is where a real chain hides, and level 12 is
frequently a misconfigured scanner. They contribute points; they do not decide.

**A low rank is not a verdict.** Nothing here means an omitted event is safe.
The analyst sees every retrieved event in the log view and can add any of them
by hand. The counts of found / selected / omitted travel with the analysis so
the reader knows how much was left out.

The budget is divided before it is spent, so one burst cannot take it all:

    before   35%   events preceding the alert
    after    35%   events following it
    near     15%   events closest to the alert timestamp, either side
    open     15%   whatever scores highest overall

Near-duplicates are grouped rather than repeated: a hundred identical firewall
denies become one representative plus "99 more like this, 12:01–12:09".
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

# Roughly four characters per token for English-plus-JSON. Deliberately an
# estimate and deliberately conservative: it is used to *stay under* a budget,
# and the measured input tokens are reported separately so the estimate can be
# corrected against real calls rather than trusted.
CHARS_PER_TOKEN = 4.0

DEFAULT_BUDGET_TOKENS = 6000

# How the budget is split. Reserving before/after is what stops one noisy
# minute consuming the context an analyst needs from the other side of the
# alert.
LANE_SHARES: tuple[tuple[str, float], ...] = (
    ("before", 0.35),
    ("after", 0.35),
    ("near", 0.15),
    ("open", 0.15),
)

# Event significance, as a ranking signal only. Keyed on Wazuh rule groups and
# Windows event ids, which are the two vocabularies this estate actually emits.
SIGNIFICANT_GROUPS: dict[str, int] = {
    "authentication_failed": 5,
    "authentication_success": 3,
    "authentication_failures": 5,
    "win_authentication_failed": 5,
    "privilege_escalation": 7,
    "policy_changed": 5,
    "account_changed": 6,
    "adduser": 7,
    "sysmon_event1": 5,      # process creation
    "sysmon_event3": 4,      # network connection
    "sysmon_event11": 3,     # file created
    "sysmon_eventid_13": 3,  # registry set
    "attack": 6,
    "mitre": 4,
    "ossec": 1,
    "firewall": 2,
    "ids": 4,
    "web": 2,
    "virus": 8,
    "rootcheck": 4,
    "audit": 3,
}

SIGNIFICANT_EVENT_IDS: dict[str, int] = {
    "1": 5,      # Sysmon process create
    "3": 4,      # Sysmon network connect
    "4624": 3,   # logon
    "4625": 5,   # failed logon
    "4672": 6,   # special privileges assigned
    "4688": 5,   # process created
    "4720": 7,   # user account created
    "4728": 6,   # member added to security group
    "4732": 6,
    "4740": 5,   # account locked out
    "7045": 6,   # service installed
    "1102": 7,   # audit log cleared
}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_WORD = re.compile(r"[A-Za-z0-9._:/\\-]{3,}")


@dataclass
class AlertPivots:
    """What the alert itself names. Exact matches against these score highest."""

    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not any((self.hosts, self.users, self.ips, self.hashes, self.processes, self.domains))


def pivots_from_alert(
    *,
    entity_host: str | None,
    entity_user: str | None,
    alert_body: str | None,
    alert_fields: dict[str, Any] | None = None,
    indicators: Iterable[dict[str, Any]] | None = None,
) -> AlertPivots:
    """The identifiers an event can be *exactly* linked to this alert by.

    Only fields the platform already trusts elsewhere: the extracted entity, the
    parsed alert fields, and the indicators the extractor found. Free text is
    read for IPs and hashes, which have unambiguous shapes, and for nothing
    else — scraping words out of a log body produces pivots like "the" and
    makes every event a match.
    """
    fields = alert_fields or {}
    pivots = AlertPivots()

    for value in (entity_host, fields.get("agent"), fields.get("entity_id")):
        if value and str(value).strip():
            pivots.hosts.add(str(value).strip().casefold())
    if entity_user and str(entity_user).strip():
        # Both halves of DOMAIN\user, because a log may carry either.
        raw = str(entity_user).strip()
        pivots.users.add(raw.casefold())
        if "\\" in raw:
            pivots.users.add(raw.split("\\", 1)[1].casefold())
        if "@" in raw:
            pivots.users.add(raw.split("@", 1)[0].casefold())
    for value in (fields.get("agent_ip"), fields.get("src"), fields.get("dst")):
        if value and _IPV4.fullmatch(str(value).strip()):
            pivots.ips.add(str(value).strip())
    if fields.get("rule_id"):
        pivots.rule_ids.add(str(fields["rule_id"]).strip())

    body = str(alert_body or "")[:200_000]
    pivots.ips.update(_IPV4.findall(body))
    pivots.hashes.update(h.casefold() for h in _HASH.findall(body))

    for indicator in indicators or []:
        kind = str(indicator.get("type") or "").lower()
        value = str(indicator.get("value") or "").strip()
        if not value:
            continue
        if kind in ("ip", "ipv4"):
            pivots.ips.add(value)
        elif kind in ("domain", "url"):
            pivots.domains.add(value.casefold())
        elif kind in ("hash", "sha256", "md5", "sha1"):
            pivots.hashes.add(value.casefold())
        elif kind in ("process", "file"):
            pivots.processes.add(value.casefold())

    return pivots


@dataclass
class Scored:
    record: dict[str, Any]
    score: float
    reasons: list[str]
    lane: str
    offset_seconds: float
    group_key: str

    @property
    def key(self) -> str:
        return str(self.record.get("key") or "")


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    # Wazuh writes +0000 rather than +00:00.
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _text_of(record: dict[str, Any]) -> str:
    parts = [
        str(record.get("full_log") or ""),
        str((record.get("process") or {}).get("command_line") or ""),
        str((record.get("process") or {}).get("image") or ""),
        " ".join(str(u) for u in (record.get("users") or [])),
        str((record.get("rule") or {}).get("description") or ""),
    ]
    return " ".join(p for p in parts if p)


def group_key_for(record: dict[str, Any]) -> str:
    """What makes two events 'the same thing happening again'.

    Rule, host, event id and the shape of the process — not the timestamp and
    not the numbers inside the message. A hundred identical firewall denies
    differ only in port and sequence, and showing all hundred spends the budget
    on one fact.
    """
    rule = record.get("rule") or {}
    process = record.get("process") or {}
    message = str(record.get("full_log") or rule.get("description") or "")
    # Digits and hex blobs are what vary between repeats of one event.
    skeleton = re.sub(r"\b[0-9a-fA-F]{6,}\b", "#", message)
    skeleton = re.sub(r"\d+", "#", skeleton)[:180]
    basis = "|".join([
        str(rule.get("id") or ""),
        str((record.get("agent") or {}).get("name") or ""),
        str(record.get("event_id") or ""),
        str(process.get("image") or ""),
        skeleton,
    ])
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]


def score_record(
    record: dict[str, Any], *, pivots: AlertPivots, alert_time: datetime, window_seconds: float
) -> Scored:
    """One event's score, with the reason for every point it got."""
    score = 0.0
    reasons: list[str] = []

    agent = record.get("agent") or {}
    rule = record.get("rule") or {}
    network = record.get("network") or {}
    process = record.get("process") or {}
    haystack = _text_of(record).casefold()

    # -- exact links to the alert (the strongest signal, by design) ----------
    host = str(agent.get("name") or "").casefold()
    if host and host in pivots.hosts:
        score += 10
        reasons.append("same device as the alert")
    users = {str(u).casefold() for u in (record.get("users") or [])}
    users |= {u.split("\\", 1)[-1] for u in users if "\\" in u}
    if users & pivots.users:
        score += 10
        reasons.append("same account as the alert")
    event_ips = {str(network.get("src_ip") or ""), str(network.get("dst_ip") or "")} - {""}
    event_ips |= set(_IPV4.findall(str(record.get("full_log") or "")))
    shared_ips = event_ips & pivots.ips
    if shared_ips:
        score += 8
        reasons.append(f"shares IP {sorted(shared_ips)[0]} with the alert")
    event_hashes = {h.casefold() for h in _HASH.findall(str(record.get("full_log") or ""))}
    if event_hashes & pivots.hashes:
        score += 9
        reasons.append("carries a file hash named in the alert")
    image = str(process.get("image") or "").casefold()
    if image and any(p in image or image.endswith(p) for p in pivots.processes):
        score += 8
        reasons.append("same process image as the alert")
    if any(d in haystack for d in pivots.domains):
        score += 7
        reasons.append("mentions a domain from the alert")
    if str(rule.get("id") or "") in pivots.rule_ids:
        score += 4
        reasons.append("same detection rule as the alert")

    # -- significance, as a ranking signal only ------------------------------
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    matched_groups = [g for g in (str(x).lower() for x in groups) if g in SIGNIFICANT_GROUPS]
    if matched_groups:
        best = max(SIGNIFICANT_GROUPS[g] for g in matched_groups)
        score += best
        reasons.append(f"significant activity ({', '.join(sorted(matched_groups)[:3])})")
    event_id = str(record.get("event_id") or "")
    if event_id in SIGNIFICANT_EVENT_IDS:
        score += SIGNIFICANT_EVENT_IDS[event_id]
        reasons.append(f"event id {event_id}")
    if process.get("command_line"):
        score += 2
        reasons.append("carries a command line")
    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0
    if level:
        # Capped low on purpose: a ranking nudge, never a verdict.
        score += min(level, 12) * 0.25
        reasons.append(f"rule level {level}")

    # -- time proximity ------------------------------------------------------
    stamp = _parse_time(record.get("timestamp"))
    offset = (stamp - alert_time).total_seconds() if stamp else window_seconds
    closeness = max(0.0, 1.0 - (abs(offset) / max(window_seconds, 1.0)))
    score += closeness * 3
    if abs(offset) <= 60:
        reasons.append("within a minute of the alert")

    lane = "near" if abs(offset) <= 120 else ("before" if offset < 0 else "after")
    return Scored(
        record=record, score=round(score, 3), reasons=reasons, lane=lane,
        offset_seconds=round(offset, 1), group_key=group_key_for(record),
    )


def estimate_tokens(value: Any) -> int:
    text = value if isinstance(value, str) else json.dumps(value, default=str, separators=(",", ":"))
    return int(len(text) / CHARS_PER_TOKEN) + 1


@dataclass
class SelectionResult:
    selected: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    found: int = 0
    # Retrieved events covered by what was sent, counting the members a grouped
    # entry stands for. Distinct from `selected`, which counts prompt entries.
    represented: int = 0
    omitted: int = 0
    budget_tokens: int = DEFAULT_BUDGET_TOKENS
    used_tokens: int = 0
    pinned: list[str] = field(default_factory=list)
    # Analyst picks that did not fit the budget. Recorded rather than dropped
    # quietly: someone who selected thirty events is entitled to know which
    # seven the model never saw.
    pinned_dropped: list[str] = field(default_factory=list)
    # What the ranking judged worth reading, captured before any caller narrows
    # `selected` down to what a person actually chose. This is the advice the
    # log view marks as "relevant"; `selected` is what was sent.
    relevant_refs: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "events_found": self.found,
            # Three different numbers, because collapsing them hides the work:
            # 297 events can become 22 prompt entries that still stand for all
            # 297, and an analyst reading "22 of 297" would wrongly conclude
            # that 275 were dropped.
            "events_selected": len(self.selected),
            "events_represented": self.represented,
            "events_omitted": self.omitted,
            "duplicate_groups": len(self.groups),
            "budget_tokens": self.budget_tokens,
            "used_tokens": self.used_tokens,
            "analyst_pinned": list(self.pinned),
            "analyst_pinned_dropped": list(self.pinned_dropped),
            # `ref`, not `key`: _for_prompt names it `ref` because that is what
            # the model is told to cite. Reading `key` here produced a list of
            # Nones, so nothing was ever marked as having been sent.
            "selected_refs": [s.get("ref") for s in self.selected if s.get("ref")],
            # Stays the full ranking even when `selected` has been narrowed to
            # an analyst's picks — the two answer different questions.
            "relevant_refs": list(self.relevant_refs),
            "note": (
                "Selection is deterministic and rank-ordered. A low rank means an event was "
                "not sent to the model; it does not mean the event is benign. Every retrieved "
                "event remains visible in the log view."
            ),
        }


def select_for_ai(
    records: Sequence[dict[str, Any]],
    *,
    pivots: AlertPivots,
    alert_time: datetime,
    window_seconds: float = 600.0,
    budget_tokens: int = DEFAULT_BUDGET_TOKENS,
    pinned_keys: Sequence[str] = (),
) -> SelectionResult:
    """Rank, group, and fill the budget lane by lane.

    `pinned_keys` are events an analyst chose by hand. They are placed first and
    charged to the budget before anything else, because a person asking for a
    specific event to be considered is a stronger signal than any rule here.
    """
    result = SelectionResult(found=len(records), budget_tokens=budget_tokens)
    if not records or budget_tokens <= 0:
        result.omitted = len(records)
        return result

    scored = [
        score_record(r, pivots=pivots, alert_time=alert_time, window_seconds=window_seconds)
        for r in records
    ]

    pinned_set = {str(k) for k in pinned_keys if str(k)}

    # Group near-duplicates; the highest-scoring member represents the group.
    #
    # Pinned events are never grouped. A group has one representative, so two
    # picks sharing a signature meant only one was sent — measured, six of
    # eight arrived. An analyst who ticks two rows is asking for two rows, and
    # "one of them stands for the other" is not an answer to that.
    by_group: dict[str, list[Scored]] = {}
    for item in scored:
        if item.key in pinned_set:
            continue
        by_group.setdefault(item.group_key, []).append(item)

    representatives: list[Scored] = [s for s in scored if s.key in pinned_set]
    for key, members in by_group.items():
        members.sort(key=lambda s: (-s.score, abs(s.offset_seconds)))
        representative = members[0]
        if len(members) > 1:
            times = sorted(
                t for t in (_parse_time(m.record.get("timestamp")) for m in members) if t
            )
            representative.record = dict(representative.record)
            representative.record["duplicate_count"] = len(members)
            representative.record["duplicate_span"] = (
                f"{times[0].isoformat()} .. {times[-1].isoformat()}" if times else None
            )
            representative.record["duplicate_refs"] = [m.key for m in members[1:6]]
            result.groups.append({
                "group": key,
                "count": len(members),
                "span": representative.record["duplicate_span"],
                "example_ref": representative.key,
                "rule": (representative.record.get("rule") or {}).get("description"),
            })
        representatives.append(representative)

    chosen: dict[str, Scored] = {}
    used = 0

    def _take(item: Scored, budget: int) -> bool:
        nonlocal used
        cost = estimate_tokens(_for_prompt(item))
        if used + cost > budget:
            return False
        chosen[item.key] = item
        used += cost
        return True

    # 1. Analyst choices first, against the whole budget, highest-ranked first.
    #    Ordering matters only when the selection overflows — and then it is the
    #    difference between dropping the least interesting of their picks and
    #    dropping whichever happened to be iterated last.
    for item in sorted(
        (r for r in representatives if r.key in pinned_set),
        key=lambda s: (-s.score, abs(s.offset_seconds)),
    ):
        if item.key in chosen:
            continue
        if _take(item, budget_tokens):
            result.pinned.append(item.key)
        else:
            result.pinned_dropped.append(item.key)

    # 2. Lane by lane, so before/after are both represented.
    for lane, share in LANE_SHARES:
        lane_budget = used + int(budget_tokens * share)
        pool = [s for s in representatives if s.key not in chosen and (lane == "open" or s.lane == lane)]
        pool.sort(key=lambda s: (-s.score, abs(s.offset_seconds)))
        for item in pool:
            if used >= lane_budget:
                break
            _take(item, min(lane_budget, budget_tokens))

    # 3. A budget too small for any single lane's share must still send the best
    #    event it can afford, not nothing. Lane reservation is there to stop one
    #    burst monopolising a large budget; applied to a small one it can leave
    #    every lane unable to afford a single entry.
    if not chosen:
        for item in sorted(representatives, key=lambda s: (-s.score, abs(s.offset_seconds))):
            if not _take(item, budget_tokens):
                break

    ordered = sorted(chosen.values(), key=lambda s: (_parse_time(s.record.get("timestamp")) or alert_time))
    result.selected = [_for_prompt(s) for s in ordered]
    result.used_tokens = used
    result.relevant_refs = [s.get("ref") for s in result.selected if s.get("ref")]
    result.represented = sum(int(s.record.get("duplicate_count") or 1) for s in chosen.values())
    result.omitted = max(0, len(records) - result.represented)
    return result


def _for_prompt(item: Scored) -> dict[str, Any]:
    """The compact shape an event takes in the prompt.

    Carries `ref` — the OpenSearch `index:id` — so any statement the model makes
    can be traced to the document it came from, and `why` so an analyst can see
    what put it in front of the model.
    """
    record = item.record
    agent = record.get("agent") or {}
    rule = record.get("rule") or {}
    process = record.get("process") or {}
    network = record.get("network") or {}

    out: dict[str, Any] = {
        "ref": record.get("key"),
        "time": record.get("timestamp"),
        "offset_s": item.offset_seconds,
        "device": agent.get("name"),
        "user": (record.get("users") or [None])[0],
        "rule": rule.get("description"),
        "rule_id": rule.get("id"),
        "level": rule.get("level"),
        "event_id": record.get("event_id"),
        "why": item.reasons[:4],
    }
    if process.get("image") or process.get("command_line"):
        out["process"] = {
            "image": process.get("image"),
            "cmd": (str(process.get("command_line"))[:300] if process.get("command_line") else None),
        }
    if network.get("src_ip") or network.get("dst_ip"):
        out["network"] = {"src": network.get("src_ip"), "dst": network.get("dst_ip")}
    if record.get("full_log"):
        out["log"] = str(record["full_log"])[:400]
    if record.get("duplicate_count"):
        out["repeated"] = {
            "count": record["duplicate_count"],
            "span": record.get("duplicate_span"),
            "other_refs": record.get("duplicate_refs"),
        }
    return {k: v for k, v in out.items() if v not in (None, [], {})}


def explain(records: Sequence[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    """Every event with its score and reasons, for debugging a selection."""
    pivots = kwargs.pop("pivots")
    alert_time = kwargs.pop("alert_time")
    window_seconds = kwargs.pop("window_seconds", 600.0)
    scored = [
        score_record(r, pivots=pivots, alert_time=alert_time, window_seconds=window_seconds)
        for r in records
    ]
    scored.sort(key=lambda s: -s.score)
    return [
        {"ref": s.key, "score": s.score, "lane": s.lane, "offset_s": s.offset_seconds, "why": s.reasons}
        for s in scored
    ]
