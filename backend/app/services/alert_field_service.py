"""
The fields of an alert, for suppression and for correlation.

Two things need the same parse. An `alert` exclusion matches on what an alert
*is* — its rule, the agent it came from, its severity — rather than on an
indicator inside it. And correlation needs the entity, because a chain is
built from (entity, time, tactics) and nothing groups by device without one.

Deliberately format-tolerant rather than format-aware. This deployment receives
Wazuh header blocks, CEF key/value lines and embedded JSON in the same stream,
often all three in one body:

    Agent: exprevpxy002 | 1445
    Agent IP: 172.20.20.5
    ... CEF:0|Fortinet|...|dvchost=fw01 suser=jdoe ...
    ... {"eventSeverity": "Info", "eventPriority": "Low"}

So each field is looked for in every shape it is known to take and the first
hit wins. A field that is absent is absent — never guessed, because a
suppression rule built on a guessed value silences alerts nobody chose to
silence.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Header form: "Agent: name | id" or "Agent IP: 1.2.3.4". The pipe is captured
# rather than used as a terminator, because the id after it is what separates a
# real endpoint from the manager forwarding someone else's log.
_HEADER = r"^[ \t]*{label}[ \t]*:[ \t]*(?P<value>[^\n]{{1,200}})"
# CEF/key=value form: "dvchost=fw01" up to the next key or end. The leading
# boundary allows a quote or backslash because this deployment forwards CEF
# inside escaped JSON — \"destinationServiceName=Office 365 dproc=... — where
# the key is preceded by \" and a whitespace-only boundary never matches.
_KV = r"(?:^|[\s|\"\\]){key}=(?P<value>[^=\n]{{1,200}}?)(?=[\s\\\"]+[A-Za-z_][\w.]*=|[\\\"]|\s*$)"
# JSON form, including bodies where JSON is embedded mid-line.
_JSON = r'"{key}"\s*:\s*"?(?P<value>[^",}}{{\[\]\n]{{1,200}})"?'


def _first(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            value = (match.group("value") or "").strip().strip('"').strip()
            # A structural character is not a value. "client":{"userAgent":...}
            # is an Okta object, not an organisation called "{" — and a bogus
            # client name is worse than none, because correlation partitions on
            # it and would quietly file 87 alerts under a punctuation mark.
            if value and value not in ("{", "[", "}", "]", "null", "None", "-"):
                return value[:200]
    return None


def _field(label: str | None, keys: list[str], text: str) -> str | None:
    patterns: list[str] = []
    if label:
        patterns.append(_HEADER.format(label=re.escape(label)))
    for key in keys:
        patterns.append(_KV.format(key=re.escape(key)))
        patterns.append(_JSON.format(key=re.escape(key)))
    return _first(patterns, text)


def extract_alert_fields(alert_body: str, *, rule_id: str | None = None,
                         rule_name: str | None = None) -> dict[str, Any]:
    """
    Every field this platform can match an alert on, plus its entity.

    `rule_id` and `rule_name` are passed in rather than parsed: the ingest route
    already resolved them into columns, and re-deriving them from the text is a
    second answer to a settled question.
    """
    text = str(alert_body or "")[:200_000]

    agent = _field("Agent", ["agent", "dvchost", "shost", "computer", "hostname"], text)
    # "Agent: exprevpxy002 | 1445" — the id after the pipe is not the name, and
    # it is worth keeping: agent 000 is the Wazuh manager itself, so an alert
    # attributed to it was forwarded (a firewall log, say) rather than observed
    # on a device. Correlating those by "host" would group every forwarded log
    # in the estate under one machine that never saw any of it.
    agent_id = None
    if agent and "|" in agent:
        agent, _, agent_id = (part.strip() for part in agent.partition("|"))

    fields: dict[str, Any] = {
        "rule_id": (str(rule_id).strip() if rule_id else None) or _field("Rule", ["rule_id", "ruleid"], text),
        "rule_name": (str(rule_name).strip() if rule_name else None),
        "agent": agent,
        "agent_ip": _field("Agent IP", ["agent_ip", "dvc", "src"], text),
        "agent_id": agent_id,
        "manager": _field("Manager", ["manager"], text),
        # An incident names its own subject; trust that over a parsed header.
        "entity_id": _field("entity_id", ["entity_id"], text),
        "event_id": _field("Event ID", ["event_id", "eventid"], text),
        "event_name": _field(None, ["eventName", "event_name", "name"], text),
        "event_priority": _field(None, ["eventPriority", "event_priority", "priority"], text),
        "event_severity": _field(None, ["eventSeverity", "event_severity", "severity"], text),
        "event_log_level": _field(None, ["eventLogLevel", "event_log_level", "log_level", "level"], text),
        "user": _field(None, ["suser", "duser", "user", "userName", "srcuser"], text),
        # Both feeds carry alerts on behalf of other organisations. TraceCat
        # incidents name theirs outright ("client: LIN"); Wazuh alerts name none
        # at all, which is why the sender can declare it.
        "client": _field("client", ["client", "customer", "tenant", "organisation"], text),
        # A TraceCat incident is a whole user or asset session already — it
        # arrives with its own event_count and entity_type. That is a different
        # object from a single Wazuh alert, and correlating the two kinds
        # together would be comparing a case to one of its own members.
        "entity_type": _field("entity_type", ["entity_type"], text),
        "event_count": _field("event_count", ["event_count"], text),
        "service": _field(None, ["destinationServiceName", "service"], text),
    }
    return {key: value for key, value in fields.items() if value}


# Fields worth offering as suppression criteria, most identifying first. A
# suppression built from the top of this list is narrow; one built from the
# bottom alone is a blunt instrument, which is why the UI orders them this way.
SUPPRESSIBLE_FIELDS: tuple[str, ...] = (
    "rule_id",
    "rule_name",
    "agent",
    "agent_ip",
    "event_id",
    "event_name",
    "service",
    "manager",
    "user",
    "event_priority",
    "event_severity",
    "event_log_level",
)

# Severity is the sender's own opinion, and this deployment has alerts arriving
# High that resolve benign — so it is wrong in at least one direction and
# probably both. An exclusion keyed on severity alone would silence a real
# detection that happened to be mislabelled Low.
SEVERITY_ONLY_FIELDS = frozenset({"event_priority", "event_severity", "event_log_level"})



# Device categories that arrive where a hostname belongs. This feed's CEF puts
# "dvchost=Personal computer" and "dvchost=Smartphone" in the field the standard
# reserves for a device hostname, so the value is a class of machine rather than
# a machine. Correlation groups on the host, so accepting these would file every
# phone in the estate under one entity called "Smartphone" — 52 alerts were
# already grouped that way, which is precisely the fabricated chain the source
# and client partitions exist to prevent.
_DEVICE_CATEGORIES = frozenset({
    "unknown", "unknown device", "personal computer", "computer", "desktop",
    "laptop", "smartphone", "phone", "mobile", "mobile device", "tablet",
    "workstation", "server", "device", "iphone", "ipad", "android", "windows",
    "macintosh", "mac", "linux", "n/a", "none", "null",
})


def looks_like_host(value: Any) -> bool:
    """
    Whether this could be a machine's name rather than a description of one.

    Two rules, both cheap and both decisive here. A hostname has no whitespace —
    DNS and NetBIOS names cannot contain it, so "Personal computer" is a
    sentence about a device, not its name. And a bare category word is a class,
    however well it is spelled.
    """
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 255:
        return False
    if any(character.isspace() for character in candidate):
        return False
    return candidate.casefold() not in _DEVICE_CATEGORIES


# Wazuh's own id for the manager. An alert bearing it was forwarded, not
# observed on an endpoint.
MANAGER_AGENT_ID = "000"


# When the sender says nothing about where an alert came from.
UNKNOWN_SOURCE = "unknown"


def source_of(fields: dict[str, Any], *, declared: str | None = None) -> str:
    """
    Which platform this alert came from.

    Correlation must never join alerts across senders. Two platforms watching
    the same estate name hosts their own way, and a "chain" assembled from a
    Siembiot endpoint alert and an unrelated session alert about a similarly
    named host is a fabrication — the most damaging kind, because it looks
    exactly like the thing the feature exists to find.

    The sender's own declaration wins; otherwise the manager that forwarded it
    identifies the platform. Nothing is inferred beyond that: an unknown source
    stays unknown and correlates only with other unknowns from the same feed.
    """
    if str(declared or "").strip():
        return str(declared).strip()[:120]
    manager = str(fields.get("manager") or "").strip()
    return manager[:120] if manager else UNKNOWN_SOURCE


# Alerts arriving without one. Correlation treats it as its own partition
# rather than a wildcard: pooling every unlabelled client into one bucket is
# exactly the cross-tenant mixing this is meant to prevent.
UNKNOWN_CLIENT = "unknown"


def client_of(fields: dict[str, Any], *, declared: str | None = None) -> str:
    """
    Which organisation this alert is about.

    Both feeds carry other people's alerts, so two customers can each own a host
    called DC01. Grouping those together would build a chain across companies —
    wrong, and a confidentiality problem as well as a correctness one.
    """
    if str(declared or "").strip():
        return str(declared).strip()[:120]
    value = str(fields.get("client") or "").strip()
    return value[:120] if value else UNKNOWN_CLIENT


def is_pre_correlated(fields: dict[str, Any]) -> bool:
    """
    True when the payload is already a session rather than a single alert.

    A TraceCat incident arrives carrying fifty events and their triggered rules.
    It is a case, not a member of one.
    """
    return bool(fields.get("entity_type") and fields.get("event_count"))


def entity_of(fields: dict[str, Any]) -> tuple[str | None, str | None]:
    """
    The (host, user) this alert is about — the key correlation groups on.

    Returns no host for a manager-forwarded alert. Grouping those by "host"
    would file every forwarded firewall log in the estate under one machine
    that never saw any of them, and a chain built on that is fiction.
    """
    # In preference order, taking the first that names a machine rather than
    # describing one. An address is a worse identifier than a name but a real
    # one; a category is not an identifier at all.
    host = next(
        (
            candidate
            for candidate in (fields.get("entity_id"), fields.get("agent"), fields.get("agent_ip"))
            if looks_like_host(candidate)
        ),
        None,
    )
    if str(fields.get("agent_id") or "").strip() == MANAGER_AGENT_ID:
        host = fields.get("agent_ip") if looks_like_host(fields.get("agent_ip")) else None
    user = fields.get("user")
    return (str(host)[:255] if host else None, str(user)[:255] if user else None)

# ── Event time ────────────────────────────────────────────────────────────────
#
# When the thing happened on the host, as distinct from when this platform was
# told about it. They are not close: this deployment receives alerts replayed
# days after the fact, so ingest order is the order a sender chose to send in
# and says nothing about the order events occurred. Any sequence reasoning built
# on created_at measures the pipeline rather than the attack.
#
# Sources in descending order of authority. The first two are the host's own
# clock; the rest are progressively further from it.
_EVENT_TIME_PATTERNS: tuple[str, ...] = (
    # Wazuh Windows eventlog, flattened or nested.
    r"data\.win\.system\.systemTime\s*[:=]\s*\"?([0-9T:\-\.\+Z]{19,40})",
    r'"systemTime"\s*:\s*"([^"]{19,40})"',
    # Wazuh FIM.
    r"syscheck\.mtime\s*[:=]\s*\"?([0-9T:\-\.\+Z ]{19,40})",
    r'"mtime"\s*:\s*"([^"]{19,40})"',
    # The alert's own header. Two stamps appear here separated by a pipe; both
    # are collected and the earliest wins — see _parse_header_times.
    r"(?:^|\n)[ \t]*Time:[ \t]*([^\n]{19,90})",
    # Source-provided event time inside a JSON payload.
    r'"eventTime"\s*:\s*"([^"]{19,40})"',
    r'"timestamp"\s*:\s*"([^"]{19,40})"',
)

_TIMESTAMP_IN_TEXT = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
)


# ── Telemetry for the two heuristics above ────────────────────────────────────
#
# Both are defensible on today's data and neither is a law. These counters exist
# so drift announces itself instead of being reconstructed from wrong answers
# months later.
#
# Measured over 2,961 stored runs when this was written: the two header stamps
# disagree on 89.6% of bodies, but by min 0.0s / p50 27.6s / p95 51.4s / max
# 57.5s — one tight mode bounded under a minute, which is what systematic
# manager-processing lag looks like. A flipped field order or a
# corrected-earlier/observed-later pair would instead show a second cluster or
# an unbounded tail, so the shape is the signal, not the rate.
#
# Naive stamps were 0% of chosen values: the offset-bearing header outranks the
# naive eventTime on every body that carries both. The UTC assumption is
# therefore inert today, and this counter is what will say when it stops being.
STAMP_DISAGREEMENT_NOTABLE_SECONDS = 5.0
STAMP_DISAGREEMENT_IMPLAUSIBLE_SECONDS = 600.0

_STAMP_STATS: dict[str, float] = {
    "headers_with_multiple_stamps": 0,
    "disagreed_notably": 0,
    "disagreed_implausibly": 0,
    "max_delta_seconds": 0.0,
    "naive_stamps_chosen": 0,
}


def stamp_heuristic_stats() -> dict[str, float]:
    """A snapshot of how the timestamp heuristics are behaving in this process."""
    return dict(_STAMP_STATS)


def reset_stamp_heuristic_stats() -> None:
    for key in _STAMP_STATS:
        _STAMP_STATS[key] = 0 if key != "max_delta_seconds" else 0.0


_NAIVE_LITERAL = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$")


def _parse_timestamp(raw: str) -> datetime | None:
    """
    One timestamp, or nothing. Never raises.

    Normalises the two shapes Python will not take as they arrive: a trailing Z,
    and the sub-microsecond precision Windows emits (systemTime carries seven
    fractional digits, which is 100-nanosecond FILETIME resolution).
    """
    text = str(raw or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00").replace(" ", "T", 1) if text.endswith("Z") else text
    text = text.replace(" UTC", "").strip()

    fraction = re.search(r"\.(\d{7,9})", text)
    if fraction:
        text = text.replace(f".{fraction.group(1)}", f".{fraction.group(1)[:6]}")

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A naive stamp is the source's local clock with no offset given. Treating
    # it as UTC is a documented assumption, not a discovery — but it keeps every
    # stored value on one scale, which ordering needs more than it needs to be
    # right about a timezone nobody declared.
    if parsed.tzinfo:
        return parsed
    # Counted, not just assumed. A naive stamp from a UTC+9 host read as UTC
    # lands nine hours out, which ordering tolerates and tempo does not.
    _STAMP_STATS["naive_stamps_chosen"] += 1
    return parsed.replace(tzinfo=timezone.utc)


def _parse_header_times(raw: str) -> datetime | None:
    """
    The earliest timestamp in one header line.

    Wazuh's header carries two — "2026-08-16T07:29:13.311+0000 |
    2026-08-16T07:28:30.948Z UTC" — without saying which is which. Taking the
    earlier one is a rule rather than a guess about field order: an event on a
    host cannot postdate the processing of that event, so whichever position
    they occupy, the earlier value is the one nearer the host.
    """
    candidates = [
        parsed
        for match in _TIMESTAMP_IN_TEXT.findall(str(raw or ""))
        if (parsed := _parse_timestamp(match)) is not None
    ]
    if not candidates:
        return None

    chosen = min(candidates)
    if len(candidates) > 1:
        delta = (max(candidates) - chosen).total_seconds()
        _STAMP_STATS["headers_with_multiple_stamps"] += 1
        _STAMP_STATS["max_delta_seconds"] = max(_STAMP_STATS["max_delta_seconds"], delta)
        if delta > STAMP_DISAGREEMENT_NOTABLE_SECONDS:
            _STAMP_STATS["disagreed_notably"] += 1
        if delta > STAMP_DISAGREEMENT_IMPLAUSIBLE_SECONDS:
            # Beyond processing lag. Either the field order flipped or these are
            # not an event and its processing at all, and picking the earlier is
            # then picking arbitrarily.
            _STAMP_STATS["disagreed_implausibly"] += 1
            logger.warning(
                "Alert header stamps disagree by %.0fs, far beyond processing lag — "
                "the earliest-wins rule may be choosing arbitrarily", delta
            )
    return chosen


def event_time_of(alert_body: str, *, fallback: datetime | None = None) -> datetime | None:
    """
    When this happened on the host, falling back to when we were told.

    Returns `fallback` (the run's created_at) only when the body carries nothing
    parseable, so a caller can always order by the result. A value in the far
    future is refused: a clock-skewed endpoint stamping 2031 would otherwise
    sort itself to the end of every case it appears in, permanently.
    """
    text = str(alert_body or "")[:200_000]

    for pattern in _EVENT_TIME_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        found = _parse_header_times(match.group(1))
        if found is None:
            continue
        if found > datetime.now(timezone.utc) + timedelta(days=2):
            logger.debug("Ignoring implausible event time %s", found)
            continue
        return found

    return fallback
