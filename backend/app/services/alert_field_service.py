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
import re
from typing import Any

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
