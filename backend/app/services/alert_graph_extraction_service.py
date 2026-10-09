"""Entities and relationships, read out of one alert body.

The case graph used to draw the case *record*: a case hub, one box per alert,
and an account. That shape cannot show an attack, because the thing an analyst
needs to see — the same binary reached by persistence and by credential
access, the same address serving a stager and later answering a beacon — only
appears when two observations collapse onto one node. So alerts stop being
nodes here. Entities are nodes; an alert is a witness attached to the nodes
and edges it saw.

Everything below comes out of fields already stored on the alert. Measured
over all 15,203 stored bodies before this was written:

    shape                       bodies
    key/value text lines        14,430   <- the real corpus
    freeform (CEF, syslog)         712
    JSON                            61

So the dotted Wazuh form (`data.win.eventdata.image: C:\\...`) is the normal
case and JSON is the exception, not the other way round. Both are read.

What each node type is actually worth, as a share of those 15,203 runs:

    Host         94.3%      Technique      87.3%
    Process      48.6%      Account        27.1%
    File          7.0%      RegistryValue   0.2%
    IP/Domain      0.0%     Service/Control  ~one case

The four at the top are what make the graph work across the estate. The rest
are present in a handful of incidents, and this module says so rather than
quietly drawing an empty canvas.

Claimed versus corroborated
---------------------------
Every entity and every edge carries a status, and the rule is about *basis*,
not about confidence:

    OBSERVED   a sensor field on the machine the event came from. The alert
               says `targetImage: lsass.exe`, so the handle open happened.
    PARSED     pulled out of a free-text string such as a command line. The
               string is real; the structure read out of it is ours.
    INFERRED   neither — it follows from two other facts, or from a rule's
               own opinion.

OBSERVED is corroborated. PARSED and INFERRED are claims, and anything whose
basis is unrecognised is a claim too, because a graph is far more persuasive
than a table: of the 30,834 ATT&CK mappings in this estate 40 are confirmed,
so an unmarked inference is more dangerous here, not less.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Any, Iterable

from app.services.alert_field_service import is_machine_account
from app.services import panos_field_map
from app.services.source_severity_service import _loudest_of, normalise

#: What `graph_source_type` reads for Palo Alto syslog. Named like a field map
#: rather than like a transport, because `unstructured syslog` — what these 224
#: runs read today — describes how it arrived, not what it is.
PANOS_SOURCE = "palo_alto_panos"

# --- basis, and the status it earns ----------------------------------------

OBSERVED = "observed"
PARSED = "parsed"
INFERRED = "inferred"

CORROBORATED = "corroborated"
CLAIMED = "claimed"


def status_for(basis: str | None) -> str:
    """Only a sensor field corroborates. Everything else, including a basis
    nobody anticipated, is a claim."""
    return CORROBORATED if basis == OBSERVED else CLAIMED


# --- node and edge vocabulary ----------------------------------------------

KINDS = (
    "host", "account", "process", "file", "registry_value",
    "service", "security_control", "domain", "ip", "url", "technique",
    # Identifiers that failed their type's shape check. Drawn, not dropped.
    "unparsed",
)

#: Edge verb -> the basis it is created with when nothing narrows it further.
#: Declared in one table so a reader can see, in one place, which relationships
#: this platform claims to have observed and which it worked out.
EDGE_BASIS = {
    "spawned": OBSERVED,            # parentProcessId/parentImage, same event
    "opened_handle": OBSERVED,      # Sysmon EID 10 names both ends
    "created_value": OBSERVED,      # EID 13 names the writing process
    "points_to": OBSERVED,          # the registry value's data *is* the path
    "disabled": OBSERVED,           # Defender's own event names the feature
    "connected_to": OBSERVED,       # EID 3 names image and destination
    "resolves_to": OBSERVED,        # one event carries hostname and address
    "ran_as": OBSERVED,             # the event names the principal
    "opened_file": OBSERVED,
    "executed_as": INFERRED,        # this path is also running as a process
    "downloaded": PARSED,           # a URL inside a command line
    "hosted_on": PARSED,            # that URL's host part
    "remote_exec_via": PARSED,      # \\HOST\share in a command line
    "created_service": PARSED,      # sc create ... in a command line
    "service_binary": PARSED,       # binpath= ... in a command line
    "evidenced_by": OBSERVED,       # an alert witnessed this node
    "requested": OBSERVED,          # a firewall saw this address ask for this
    "attributed_to": OBSERVED,      # PAN-OS User-ID bound an address to a user
}


@dataclass
class Entity:
    kind: str
    merge_key: str
    label: str
    basis: str
    attrs: dict[str, Any] = dc_field(default_factory=dict)

    @property
    def status(self) -> str:
        return status_for(self.basis)


@dataclass
class Edge:
    kind: str
    source: str
    target: str
    basis: str
    attrs: dict[str, Any] = dc_field(default_factory=dict)

    @property
    def status(self) -> str:
        return status_for(self.basis)


#: Decoders this extractor has a field map for. Everything else yields
#: nothing, and says so by name rather than drawing an empty canvas — a blank
#: graph reads as "no attack here", which is a different and much worse claim
#: than "this platform cannot read this source yet".
#:
#: Measured share of the 15,212 stored alerts, by `decoder.name`:
#:     windows_eventchannel     9,055   59.5%   mapped
#:     appsec-agent             2,685   17.7%   not mapped
#:     fortigate-firewall-v5    2,533   16.6%   not mapped (carries data.srcip,
#:                                              data.dstip, data.dstport — the
#:                                              IP and Domain node types that
#:                                              currently measure 0.0%)
#:     (none: PAN-OS, syslog)     865    5.7%   not mapped
#:     syscheck_*, macOS, json     76    0.5%   not mapped
MAPPED_DECODERS = frozenset({"windows_eventchannel", PANOS_SOURCE})

#: How many stored SIEM events one alert contributes. Measured: 40 sampled log
#: contexts hold 14,674 events, so roughly 370 each, and the 1,858 runs that
#: have context would otherwise dominate the extraction entirely. Entities are
#: deduplicated inside a run, so a higher number buys little beyond this.
MAX_LOG_EVENTS = 400


def source_type_of(fields: dict[str, Any]) -> str:
    """What kind of alert this is, named as the field map would be named."""
    decoder = fields.get("decoder.name") or fields.get("decoder")
    if decoder:
        return str(decoder)
    channel = fields.get("data.win.system.channel")
    if channel:
        return str(channel)
    if any(str(k).startswith("data.") for k in fields):
        return "unrecognised structured alert"
    return "unstructured syslog"


@dataclass
class Extracted:
    entities: list[Entity] = dc_field(default_factory=list)
    edges: list[Edge] = dc_field(default_factory=list)
    #: The source this came from, so an empty result can name it.
    source_type: str = "unknown"
    #: Whether this platform has a field map for that source at all.
    mapped: bool = False
    #: Whether log events were left unread because there were too many.
    truncated_logs: bool = False
    #: The alert's own severity, normalised 0-100, or None when its source
    #: states none. Never 0 for an absent value.
    source_severity: int | None = None
    source_severity_raw: str | None = None
    #: Identifiers that failed a shape check, with the reason. Counted so a
    #: new source landing with an unanticipated encoding shows up as a rising
    #: number rather than as silence.
    quarantined: list[dict[str, Any]] = dc_field(default_factory=list)
    #: Field names present in the body that no node type claimed. Reported so a
    #: missing node type shows up as an unread field rather than as silence.
    unread: list[str] = dc_field(default_factory=list)


# --- reading the body ------------------------------------------------------

# A key/value line. The key may be a friendly label ("Computer") or a flattened
# path ("data.win.eventdata.image"); both are kept at their full spelling.
#
# Deliberately NOT the suffix match used by alert_field_service._DOTTED. That
# pattern matches `[\w.]*\.{key}`, and switched on for every field at once it
# gave 11,374 alerts an `event_name` of "Account Manipulation, Valid Accounts"
# — a technique list read as an event name because some dotted path ends in
# `.name`. Keying on the whole path cannot do that.
_LINE = re.compile(r"^[ \t]*([A-Za-z][\w.\- ]{0,64}?)[ \t]*:[ \t]*(.*)$", re.MULTILINE)

#: Friendly label -> flattened path, so the rest of this module reads one
#: namespace. Both spellings occur, often in the same body.
_ALIASES = {
    "Agent": "agent.name",
    "Agent IP": "agent.ip",
    "Computer": "data.win.system.computer",
    "Channel": "data.win.system.channel",
    "Event ID": "data.win.system.eventID",
    "Rule": "rule.id",
    "Rule level": "rule.level",
    "Image": "data.win.eventdata.image",
    "CommandLine": "data.win.eventdata.commandLine",
    "ParentImage": "data.win.eventdata.parentImage",
    "ParentCommandLine": "data.win.eventdata.parentCommandLine",
    "ParentProcessId": "data.win.eventdata.parentProcessId",
    "ProcessId": "data.win.eventdata.processId",
    "ProcessGuid": "data.win.eventdata.processGuid",
    "SourceImage": "data.win.eventdata.sourceImage",
    "SourceProcessId": "data.win.eventdata.sourceProcessId",
    "SourceProcessGUID": "data.win.eventdata.sourceProcessGuid",
    "TargetImage": "data.win.eventdata.targetImage",
    "TargetProcessId": "data.win.eventdata.targetProcessId",
    "GrantedAccess": "data.win.eventdata.grantedAccess",
    "CallTrace": "data.win.eventdata.callTrace",
    "User": "data.win.eventdata.user",
    "TargetObject": "data.win.eventdata.targetObject",
    "Details": "data.win.eventdata.details",
    "Hashes": "data.win.eventdata.hashes",
    "TargetFilename": "data.win.eventdata.targetFilename",
    "DestinationIp": "data.win.eventdata.destinationIp",
    "DestinationHostname": "data.win.eventdata.destinationHostname",
    "DestinationPort": "data.win.eventdata.destinationPort",
    "ScriptBlockText": "data.win.eventdata.scriptBlockText",
}

ED = "data.win.eventdata."

# One alert can aggregate several events, and the text form joins their values
# with " | ": `Agent: EXP-4LWK334 | 1634`, `Rule level: 15 | 3`,
# `Event ID: 10 | ThreatHunting`. Reading the whole string as one value gives a
# host called "EXP-4LWK334 | 1634", which is a different host from every other
# mention of the same machine — the entity-splitting failure this file exists
# to avoid.
def _first_value(raw: str) -> str:
    return raw.split("|")[0].strip().strip('"').strip()


# The text form encodes lists as `{0=T1055.001, 1=T1106}`, and MITRE packs
# three of them: ids, then names, then tactics. Splitting the whole value on
# commas yields "Dynamic-link Library Injection" as a technique id.
_INDEXED = re.compile(r"\d+\s*=\s*([^,}]+)")


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        out[prefix.rstrip(".")] = obj
    else:
        out[prefix.rstrip(".")] = obj
    return out


def read_fields(alert_body: str | None) -> dict[str, Any]:
    """Every field the body carries, keyed by its full flattened path.

    One pass, rather than one regex per field: this runs over every stored
    alert during the backfill, and it is also what makes the materialised
    tables a join instead of a re-parse.
    """
    body = alert_body or ""
    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            flat = _flatten(parsed)
            return {k: v for k, v in flat.items() if v not in (None, "", [], {})}

    fields: dict[str, Any] = {}
    for match in _LINE.finditer(body):
        label = match.group(1).strip()
        raw = match.group(2)
        key = _ALIASES.get(label, label)
        if key in fields:
            continue  # first occurrence wins, as the corpus survey assumed
        if label == "MITRE":
            ids = _INDEXED.findall(raw.split("|")[0])
            if ids:
                fields["rule.mitre.id"] = [i.strip() for i in ids]
            continue
        if label == "Mitre.Sub_technique.ID":
            fields.setdefault(
                "rule.mitre.id",
                [p.strip() for p in _first_value(raw).split(",") if p.strip()],
            )
            continue
        value = _first_value(raw)
        if value and value not in ("{", "[", "}", "]", "null", "None", "-"):
            fields[key] = value
    return fields


# --- normalising the things that become merge keys -------------------------

#: Names Windows itself defines, which appear in UNC position but are never
#: machines: `\\BUILTIN\Administrators` is a well-known group, not a server.
#: This is a short list of identifiers Microsoft fixes, not a guess about how
#: this customer names hosts — the latter is exactly what the explicit
#: criticality table exists to avoid.
_NOT_A_MACHINE = frozenset({
    "builtin", "nt authority", "nt service", "local service", "network service",
    "everyone", "creator owner", "authenticated users", "localhost", "127",
    "iis apppool", "window manager", "font driver host",
})


def host_key(value: Any) -> str | None:
    """The short machine label, lowercased.

    NOT the FQDN the brief asked for. The same alert carries
    `Agent: EXP-FIN-034` and `Computer: EXP-FIN-034.corp.local`, so keying on
    the FQDN splits one machine into two nodes; and `EXP-DC-01`, which only
    ever appears inside `\\\\EXP-DC-01\\ADMIN$`, has no FQDN anywhere in the
    estate. The label is the one form every mention shares. The FQDN is kept
    as an attribute, so nothing is lost.
    """
    text = str(value or "").strip().strip('"')
    if not text:
        return None
    text = re.sub(r"^\\\\", "", text)        # \\EXP-DC-01\ADMIN$
    text = text.split("\\")[0]               # drop the share
    text = text.split("/")[0]
    label = text.split(".")[0].strip().lower()
    # A bare number is an agent id, not a machine; `Agent: EXP-4LWK334 | 1634`
    # already lost its second half to _first_value, but JSON bodies carry
    # agent.id separately and it must never become a host.
    if not label or label.isdigit():
        return None
    if label in _NOT_A_MACHINE:
        return None
    return label


_PATH_TAIL = re.compile(r"[\\/]([^\\/]+)$")


def path_label(value: Any) -> str:
    """`C:\\Windows\\System32\\lsass.exe` -> `lsass.exe`.

    A node has to fit on screen, and a full path in a 140-pixel box is
    unreadable. The whole path stays in the attributes.
    """
    text = str(value or "").strip().strip('"')
    match = _PATH_TAIL.search(text)
    return (match.group(1) if match else text) or text


def norm_path(value: Any) -> str | None:
    text = str(value or "").strip().strip('"')
    return text.replace("/", "\\").lower() or None


_SHA256 = re.compile(r"SHA256\s*=\s*([0-9a-fA-F]{64})")


def sha256_of(hashes: Any) -> str | None:
    match = _SHA256.search(str(hashes or ""))
    return match.group(1).lower() if match else None


_URL = re.compile(r"https?://[^\s'\"<>)\]]+", re.IGNORECASE)
_URL_HOST = re.compile(r"https?://([^/:\s]+)", re.IGNORECASE)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# `\\HOST\share` or a bare `\\HOST`. Both occur: targetServer carries the
# share, a PsExec command line usually does not.
#
# The leading boundary is load-bearing, and it is the seventh delimiter bug of
# this shape in this codebase. Without it, any doubled backslash inside a
# Windows path matches: `"C:\\Program Files\\Git\\bin\\bash.exe"` yielded a host
# called `program`, and across the estate the host list gained `windows`,
# `system`, `users`, `python312`, `secpol`, `sysmon`, `microsoft` and
# `localhost` — fourteen path fragments drawn as machines, one of which the
# criticality seeder then proposed as a crown jewel. A real UNC prefix starts
# a token; a path separator never does.
_UNC = re.compile(
    r"(?:^|[\s\"\',=;(])\\\\([A-Za-z0-9][A-Za-z0-9._-]{0,62})(?:\\([^\\\s\"]+))?"
)

# `sc create updsvc binpath= C:\Windows\odsvc.exe`
#
# The space after `=` is real and it is load-bearing: `binpath=(\S+)` against
# the stored string returns None, so the naive pattern finds no service binary
# at all and the chain stops at the service node.
_SC_CREATE = re.compile(r"\bsc(?:\.exe)?\s+create\s+(\"[^\"]+\"|\S+)", re.IGNORECASE)
_BINPATH = re.compile(r"binpath\s*=\s*\"?([^\"\n]+?)\"?\s*(?:$|\")", re.IGNORECASE)


# --- shape guards: quarantine, never drop -----------------------------------
#
# An identifier that fails its type's shape check becomes an `unparsed` entity
# carrying its raw value, and is counted. Dropping it would hide the parser bug
# that produced it, which is how this class of failure keeps recurring — six
# delimiter bugs before the `_UNC` one, and that one was only found because a
# seeding helper printed a host called `program`.
#
# The traced example: Sysmon Event ID 15 (FileCreateStreamHash) carries the
# alternate data stream's bytes in `Contents`. Where those bytes are UTF-16,
# Wazuh mis-decodes them — `'湁桡楥'` appears 567 times, which is UTF-16LE read
# as CJK (U+6E41 -> bytes 41 6E -> "An") — and the adjacent `user` field
# catches a one-character fragment. Measured: 107 of 299,087 user fields in
# stored log context are 1-2 characters and 100% of them are EID 15, values
# `_` (78) and `P` (29). `targetFilename` and `image` on those same 107 events
# are intact, so the damage is confined to `user`.

UNPARSED = "unparsed"

#: A drive-letter path or a UNC prefix. Either means the value is a location,
#: not a principal.
_PATH_SHAPED = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")

#: Event IDs whose `user` field is known-unreliable at the source. Suppressed
#: rather than shape-checked per value: quarantining `P` and `_` individually
#: treats the symptom, while the field itself is untrustworthy for this event
#: type whatever it happens to contain.
_NO_ACCOUNT_FROM_EVENT = {"15"}


def account_shape_problem(value: str) -> str | None:
    """Why this is not a usable account identifier, if it isn't."""
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) < 2:
        return (
            "An account name of one character is not an identifier. On Sysmon "
            "Event ID 15 this is field-boundary debris from the alternate data "
            "stream payload in `Contents`."
        )
    # `DOMAIN\\user` is the normal form and must pass. What must not pass is a
    # path: a drive letter, a UNC prefix, a forward slash, or more than one
    # backslash. The first version of this check rejected a single backslash
    # and would have quarantined almost every real account in the estate.
    if _PATH_SHAPED.search(text) or text.count("\\") > 1 or "/" in text:
        return "This is shaped like a path, not an account."
    return None


def host_shape_problem(value: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if _NOT_A_MACHINE and text.lower() in _NOT_A_MACHINE:
        return "This is a name Windows defines, not a machine."
    return None


# --- the extractor ---------------------------------------------------------

#: Fields read by some node type below. Anything else present in a body is
#: reported as unread, so a node type that silently never fires is visible.
_CLAIMED_FIELDS = {
    "agent.name", "agent.ip", "agent.id", "data.win.system.computer",
    "rule.mitre.id", "rule.level", "rule.id",
    f"{ED}user", f"{ED}targetUserName", f"{ED}targetUserSid",
    f"{ED}subjectUserName", f"{ED}subjectUserSid", f"{ED}targetDomainName",
    f"{ED}subjectDomainName",
    f"{ED}image", f"{ED}processId", f"{ED}processGuid",
    f"{ED}parentImage", f"{ED}parentProcessId", f"{ED}parentProcessGuid",
    f"{ED}parentCommandLine", f"{ED}commandLine",
    f"{ED}sourceImage", f"{ED}sourceProcessId", f"{ED}sourceProcessGuid",
    f"{ED}targetImage", f"{ED}targetProcessId", f"{ED}grantedAccess",
    f"{ED}hashes", f"{ED}targetFilename", f"{ED}details",
    f"{ED}targetObject", f"{ED}eventType",
    f"{ED}product", f"{ED}feature", f"{ED}state",
    f"{ED}destinationIp", f"{ED}destinationHostname", f"{ED}destinationPort",
    f"{ED}domainAgeDays", f"{ED}callTrace", f"{ED}integrityLevel",
    f"{ED}targetServer", f"{ED}scriptBlockText", f"{ED}recentCommands",
    f"{ED}path",
}


class _Builder:
    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self.unread: set[str] = set()
        self.truncated_logs: bool = False
        #: Identifiers that failed their type's shape check. Kept, counted and
        #: rendered as `unparsed` — never dropped.
        self.quarantined: list[dict[str, Any]] = []

    def quarantine(self, *, kind: str, field: str, value: Any, why: str) -> str:
        key = f"unparsed:{kind}:{str(value)[:80]}"
        self.quarantined.append(
            {"kind": kind, "field": field, "value": str(value)[:120], "why": why}
        )
        self.node(
            UNPARSED, key, str(value)[:40] or "(empty)", PARSED,
            unparsed_kind=kind, source_field=field, why=why, raw=str(value)[:200],
        )
        return key

    def node(
        self, kind: str, merge_key: str, label: str, basis: str, **attrs: Any
    ) -> str:
        """Add or merge. The whole point of this module is that the second
        observation of a thing does not create a second node."""
        existing = self.entities.get(merge_key)
        if existing is None:
            self.entities[merge_key] = Entity(
                kind=kind, merge_key=merge_key, label=label, basis=basis,
                attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            )
            return merge_key
        # An observation outranks a parse: a host first seen named inside
        # someone else's command line, then seen reporting its own telemetry,
        # is corroborated from then on.
        if existing.basis != OBSERVED and basis == OBSERVED:
            existing.basis = OBSERVED
        if label and len(label) < len(existing.label or ""):
            existing.label = label
        for k, v in attrs.items():
            if v not in (None, "") and k not in existing.attrs:
                existing.attrs[k] = v
        return merge_key

    def edge(
        self, kind: str, source: str | None, target: str | None,
        basis: str | None = None, **attrs: Any
    ) -> None:
        if not source or not target or source == target:
            return
        basis = basis or EDGE_BASIS.get(kind, INFERRED)
        key = (kind, source, target)
        existing = self.edges.get(key)
        if existing is None:
            self.edges[key] = Edge(
                kind=kind, source=source, target=target, basis=basis,
                attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            )
            return
        if existing.basis != OBSERVED and basis == OBSERVED:
            existing.basis = OBSERVED
        for k, v in attrs.items():
            if v not in (None, "") and k not in existing.attrs:
                existing.attrs[k] = v


def _populate(
    b: "_Builder",
    f: dict[str, Any],
    *,
    risk_score: int | None = None,
    confirmed_techniques: Iterable[str] = (),
) -> None:
    """Read one set of fields into a builder.

    Separated from `extract` so a run's alert body and the SIEM log events
    retrieved around it can share one builder. They use the same dotted
    field names, and sharing the builder is what makes a process seen in
    both of them one node instead of two.

    `confirmed_techniques` are the ATT&CK ids the investigation actually
    corroborated. Everything a *rule* asserts is a claim: a rule's
    `mitre.id` is its author's mapping, not a finding, and 30,863 of the
    30,903 mappings in this estate have never been corroborated.
    """
    get = f.get

    def val(key: str) -> str | None:
        v = get(key)
        if isinstance(v, list):
            v = v[0] if v else None
        text = str(v).strip() if v not in (None, "") else None
        return text or None

    # ---- Host. The machine that reported, plus any machine it named. ------
    agent_name = val("agent.name")
    computer = val("data.win.system.computer")
    local = host_key(computer) or host_key(agent_name)
    if local:
        b.node(
            "host", f"host:{local}", local, OBSERVED,
            fqdn=computer if computer and "." in str(computer) else None,
            agent_ip=val("agent.ip"),
        )

    # ---- Account ---------------------------------------------------------
    sid = val(f"{ED}targetUserSid") or val(f"{ED}subjectUserSid")
    user = val(f"{ED}user") or val(f"{ED}targetUserName") or val(f"{ED}subjectUserName")
    event_id = val("data.win.system.eventID") or val("event_id")
    account = None
    if user and str(event_id or "") in _NO_ACCOUNT_FROM_EVENT:
        # The field is untrustworthy for this event type whatever it contains,
        # so it does not become an account at all — and the raw value is kept
        # visible rather than silently discarded.
        b.quarantine(
            kind="account", field=f"{ED}user", value=user,
            why=(
                f"Sysmon Event ID {event_id} carries the alternate data stream's "
                "bytes in `Contents`, and Wazuh's decoding of those bytes leaks "
                "into the adjacent `user` field. Every 1-2 character account "
                "name in this estate's stored log context — 107 of 299,087 — "
                "comes from this event ID. The field is not read as an account."
            ),
        )
        user = None
    elif user:
        problem = account_shape_problem(user)
        if problem:
            b.quarantine(kind="account", field=f"{ED}user", value=user, why=problem)
            user = None
    if sid or user:
        key = f"account:sid:{sid.lower()}" if sid else f"account:{str(user).lower()}"
        account = b.node(
            "account", key, str(user or sid), OBSERVED,
            sid=sid, user=user,
            machine_account=is_machine_account(user) if user else None,
        )
        if local:
            b.edge("ran_as", f"host:{local}", account)

    # ---- Processes -------------------------------------------------------
    def process(
        image: str | None, pid: str | None, guid: str | None,
        *, host: str | None = None, basis: str = OBSERVED, **attrs: Any
    ) -> str | None:
        """Identity, in the order the data actually supports it.

        A GUID is Sysmon's own identity for a process and is unambiguous, but
        it is absent from whole families of alerts — none of case #1440's eight
        carry one — so host+PID+image is the working key. When the PID is
        absent too (an alert that names only `parentImage`), the key falls
        back to host+image. That fallback is what lets one binary named three
        different ways in one case stay one node; it can also merge two
        genuine runs of the same binary, so the node it creates is a claim
        until an observation with a PID confirms it.
        """
        if not image and not guid:
            return None
        h = host or local
        if guid:
            key = f"process:guid:{str(guid).strip('{}').lower()}"
        elif pid and h:
            key = f"process:{h}:{pid}:{path_label(image).lower()}"
        elif h:
            key = f"process:{h}:{norm_path(image)}"
            basis = basis if basis != OBSERVED else INFERRED
        else:
            return None
        return b.node(
            "process", key, path_label(image), basis,
            image=image, pid=pid, guid=guid, host=h, **attrs,
        )

    subject = process(
        val(f"{ED}image") or val(f"{ED}path"),
        val(f"{ED}processId"),
        val(f"{ED}processGuid"),
        command_line=val(f"{ED}commandLine"),
        integrity=val(f"{ED}integrityLevel"),
    )
    parent = process(
        val(f"{ED}parentImage"),
        val(f"{ED}parentProcessId"),
        val(f"{ED}parentProcessGuid"),
        command_line=val(f"{ED}parentCommandLine"),
    )
    b.edge("spawned", parent, subject)
    # Whether the *sensor* said anything about this process's parent. An alert
    # that named one has been answered; an alert that named none left a gap the
    # assembler may close with a claim. Without this they are indistinguishable
    # and the assembler would second-guess the telemetry.
    if subject and (val(f"{ED}parentImage") or val(f"{ED}parentProcessId")):
        b.entities[subject].attrs["parent_reported"] = True
    # Which process this alert was actually *about*. A node minted from
    # `parentImage` is a thing we know one fact about — that it started
    # something — and inferring a parent for it is how the assembler came to
    # draw `reg.exe spawned explorer.exe`, inverting the very relationship the
    # sensor had just reported.
    if subject:
        b.entities[subject].attrs["observed_as_subject"] = True
    if account:
        for proc in (p for p in (subject, parent) if p):
            b.edge("ran_as", proc, account)

    # Process access: Sysmon names both ends and the access mask.
    source_proc = process(
        val(f"{ED}sourceImage"), val(f"{ED}sourceProcessId"),
        val(f"{ED}sourceProcessGuid"),
    )
    target_proc = process(
        val(f"{ED}targetImage"), val(f"{ED}targetProcessId"), None,
    )
    if source_proc and target_proc:
        b.edge(
            "opened_handle", source_proc, target_proc,
            granted_access=val(f"{ED}grantedAccess"),
            call_trace=(val(f"{ED}callTrace") or "")[:200] or None,
        )
    # Only the source. The alert's principal is whoever opened the handle; the
    # process on the other end of it runs as something else entirely, and
    # `lsass.exe ran_as CORP\jdoe` is a false statement about a real event.
    if account and source_proc:
        b.edge("ran_as", source_proc, account)

    # ---- Files -----------------------------------------------------------
    def file_node(path: Any, *, basis: str = OBSERVED, sha: str | None = None) -> str | None:
        """A file, unless a process is already running from that same path.

        When it is, the two are one object: the Run key points at
        `odsync.exe` and the thing that opens LSASS *is* `odsync.exe`.
        Splitting them into a File and a Process puts persistence and
        credential access on two separate leaves and hides that they are the
        same binary — the single most important merge in the model.
        """
        normalised = norm_path(path)
        if not normalised:
            return None
        if local:
            for candidate in (
                f"process:{local}:{normalised}",
                *[
                    k for k, e in b.entities.items()
                    if e.kind == "process" and norm_path(e.attrs.get("image")) == normalised
                ],
            ):
                if candidate in b.entities:
                    if sha:
                        b.entities[candidate].attrs.setdefault("sha256", sha)
                    return candidate
        key = f"file:sha256:{sha}" if sha else f"file:{local or '?'}:{normalised}"
        return b.node(
            "file", key, path_label(path), basis,
            path=str(path), sha256=sha, host=local,
        )

    sha = sha256_of(get(f"{ED}hashes"))
    if sha and subject:
        b.entities[subject].attrs.setdefault("sha256", sha)
    for raw_path in (val(f"{ED}targetFilename"),):
        written = file_node(raw_path, sha=sha)
        b.edge("opened_file", subject, written)

    # The document a command line opened, which is how a maldoc chain starts.
    parent_cmd = val(f"{ED}parentCommandLine") or ""
    for doc in re.findall(r'"([A-Za-z]:\\[^"]+\.(?:docm|docx|doc|xlsm|xls|pdf|rtf|zip|js|vbs|lnk|hta))"', parent_cmd, re.I):
        opened = file_node(doc, basis=PARSED)
        b.edge("opened_file", parent, opened, basis=PARSED)

    # A burst rule reports one alert for several commands and lists them in a
    # single field: `whoami /all; net group "Domain Admins" /domain; nltest
    # /dclist:corp.local; ipconfig /all`. Each is a sibling of the others under
    # the same parent, and they are given a shared group so the renderer can
    # draw "Discovery burst ×4" instead of four leaves nobody reads. Parsed out
    # of a text field, so claims.
    recent = val(f"{ED}recentCommands")
    if recent:
        commands = [c.strip() for c in str(recent).split(";") if c.strip()]
        group = f"burst:{local}:{path_label(val(f'{ED}parentImage') or '')}".lower()
        own = path_label(val(f"{ED}image") or "")
        for command_text in commands:
            binary = command_text.split()[0] if command_text.split() else None
            if not binary:
                continue
            stem = lambda v: path_label(v).lower().removesuffix(".exe")
            if own and stem(binary) == stem(own) and subject:
                # This is the command the alert itself fired on. It already has
                # a node, with its real image path, so the sibling group claims
                # that node rather than minting a bare-token twin of it.
                b.entities[subject].attrs.setdefault("sibling_group", group)
                b.entities[subject].attrs.setdefault("command_line", command_text)
                continue
            sibling = b.node(
                "process", f"process:{local}:{binary.lower()}", binary, PARSED,
                command_line=command_text, sibling_group=group,
                host=local, image=binary,
            )
            b.edge("spawned", parent, sibling, basis=PARSED)
            if account:
                b.edge("ran_as", sibling, account, basis=PARSED)

    # ---- Registry --------------------------------------------------------
    target_object = val(f"{ED}targetObject")
    if target_object:
        reg = b.node(
            "registry_value", f"registry:{local}:{str(target_object).lower()}",
            str(target_object).rsplit("\\", 1)[-1], OBSERVED,
            path=target_object, event_type=val(f"{ED}eventType"),
            data=val(f"{ED}details"),
        )
        b.edge("created_value", subject, reg)
        details = val(f"{ED}details")
        if details and re.match(r"^[A-Za-z]:\\", str(details)):
            b.edge("points_to", reg, file_node(details))

    # ---- Security control ------------------------------------------------
    # Keyed on feature+state, never on `product` alone: `ed.product` occurs on
    # 294 runs as PE version metadata (company/description/product/fileVersion
    # of a signed binary), so keying on it would mint a "security control" for
    # every signed executable in the estate — a node true of everything, which
    # can neither link nor rank.
    feature, state = val(f"{ED}feature"), val(f"{ED}state")
    if feature and state:
        product = val(f"{ED}product") or "security product"
        control = b.node(
            "security_control", f"control:{local}:{str(product).lower()}:{str(feature).lower()}",
            f"{product} · {feature}", OBSERVED, product=product, feature=feature, state=state,
        )
        if str(state).lower() in ("disabled", "off", "stopped"):
            b.edge("disabled", subject, control)

    # ---- Network ---------------------------------------------------------
    dest_ip = val(f"{ED}destinationIp")
    dest_host = val(f"{ED}destinationHostname")
    ip_node = domain_node = None
    if dest_ip:
        ip_node = b.node("ip", f"ip:{dest_ip}", str(dest_ip), OBSERVED, address=dest_ip)
        b.edge("connected_to", subject, ip_node, port=val(f"{ED}destinationPort"))
    if dest_host:
        domain_node = b.node(
            "domain", f"domain:{str(dest_host).lower()}", str(dest_host), OBSERVED,
            age_days=val(f"{ED}domainAgeDays"),
        )
        b.edge("connected_to", subject, domain_node, port=val(f"{ED}destinationPort"))
        b.edge("resolves_to", domain_node, ip_node)

    # ---- URLs, and the addresses inside them -----------------------------
    haystack = " ".join(
        str(x) for x in (
            val(f"{ED}commandLine"), parent_cmd,
            val(f"{ED}scriptBlockText"), val(f"{ED}recentCommands"),
        ) if x
    )
    for url in dict.fromkeys(_URL.findall(haystack)):
        url_node = b.node("url", f"url:{url.lower()}", url[:72], PARSED, url=url)
        b.edge("downloaded", subject, url_node, basis=PARSED)
        host_part = _URL_HOST.match(url)
        if host_part:
            value = host_part.group(1)
            if _IPV4.match(value):
                hosted = b.node("ip", f"ip:{value}", value, PARSED, address=value)
            else:
                hosted = b.node("domain", f"domain:{value.lower()}", value, PARSED)
            b.edge("hosted_on", url_node, hosted, basis=PARSED)

    # ---- Remote execution, services --------------------------------------
    command = val(f"{ED}commandLine") or ""
    remote_host = None
    for raw_unc in (val(f"{ED}targetServer"), command):
        if not raw_unc:
            continue
        match = _UNC.search(str(raw_unc))
        if not match:
            continue
        label = host_key(match.group(1))
        if not label or label == local:
            continue
        remote_host = b.node("host", f"host:{label}", label, PARSED)
        b.edge(
            "remote_exec_via", subject, remote_host, basis=PARSED,
            share=match.group(2),
        )
        break

    service_match = _SC_CREATE.search(command)
    if service_match:
        name = service_match.group(1).strip('"')
        # The service is created on whichever machine the command reached, not
        # on the machine that typed it. Keying it on the local host would file
        # a domain controller's new service under the workstation.
        owner = remote_host or (f"host:{local}" if local else None)
        owner_label = owner.split(":", 1)[1] if owner else "?"
        service = b.node(
            "service", f"service:{owner_label}:{name.lower()}", name, PARSED,
            name=name, host=owner_label,
        )
        b.edge("created_service", subject, service, basis=PARSED)
        b.edge("hosted_on", service, owner, basis=PARSED)
        binpath = _BINPATH.search(command)
        if binpath:
            binary = b.node(
                "file", f"file:{owner_label}:{norm_path(binpath.group(1))}",
                path_label(binpath.group(1)), PARSED,
                path=binpath.group(1).strip(), host=owner_label,
            )
            b.edge("service_binary", service, binary, basis=PARSED)

    # ---- Techniques ------------------------------------------------------
    confirmed = {str(t).upper() for t in confirmed_techniques}
    raw_ids = get("rule.mitre.id")
    ids = raw_ids if isinstance(raw_ids, list) else ([raw_ids] if raw_ids else [])
    for tid in dict.fromkeys(str(i).strip().upper() for i in ids if str(i).strip()):
        technique = b.node(
            "technique", f"technique:{tid}", tid,
            OBSERVED if tid in confirmed else INFERRED, id=tid,
        )
        # Attached to the thing the alert was about, so a technique hangs off
        # the process or host it touched rather than off the case hub.
        anchor = subject or source_proc or (f"host:{local}" if local else None)
        b.edge(
            "evidenced_by", anchor, technique,
            basis=OBSERVED if tid in confirmed else INFERRED,
        )

    # ---- Risk, carried on every node this alert touched ------------------
    # Two different numbers, kept apart. `indicator_risk_score` is the
    # aggregator's sum over this alert's indicators and is not a severity;
    # `source_severity` is what the alert's own source says. Conflating them
    # put a 0-100 score behind thresholds written for Wazuh's 1-16 scale.
    if risk_score:
        for entity in b.entities.values():
            prior = entity.attrs.get("indicator_risk_score")
            if prior is None or int(risk_score) > int(prior):
                entity.attrs["indicator_risk_score"] = int(risk_score)
    severity, severity_raw = normalise(f)
    if severity is not None:
        for entity in b.entities.values():
            prior = entity.attrs.get("source_severity")
            if prior is None or severity > int(prior):
                entity.attrs["source_severity"] = severity
                # Every grading the source gave, not only the winning one.
                # `data.level=alert (also crlevel=low)` is more informative
                # than 86, and a firewall disagreeing with itself is something
                # an analyst should see.
                entity.attrs["source_severity_raw"] = severity_raw

    unread = sorted(
        k for k in f
        if k not in _CLAIMED_FIELDS
        and k.startswith(ED)
    )
    unread = sorted(
        k for k in f
        if k not in _CLAIMED_FIELDS
        and k.startswith(ED)
    )
    b.unread.update(unread)


def _populate_panos(b: "_Builder", records: list[Any]) -> None:
    """Read PAN-OS records into a builder.

    The model is deliberately not the Windows one. PAN-OS witnesses a session
    between two addresses, so the subject is an address and not a process, and
    nothing here claims to have seen a parent, a hash or a command line.

    The firewall itself does not become a node. It reported 718 of the 734
    records in the store, so it would join every node in every PAN-OS case to
    one hub — the host-wide bucket shape — while telling an analyst nothing
    they did not already know from the case's source. It is kept as the
    `reported_by` attribute of the session instead.
    """
    for record in records:
        if not record.readable:
            b.quarantine(
                kind="panos_record", field="alert_body",
                value=record.raw, why=record.problem or "unreadable",
            )
            continue

        src = record.get("src_ip")
        dst = record.get("dst_ip")
        subject = (
            b.node("ip", f"ip:{src}", src, OBSERVED, address=src,
                   zone=record.get("src_zone"))
            if src else None
        )
        target = (
            b.node("ip", f"ip:{dst}", dst, OBSERVED, address=dst,
                   zone=record.get("dst_zone"))
            if dst else None
        )

        name, signature = panos_field_map.threat_id(record)
        if subject and target:
            b.edge(
                "connected_to", subject, target,
                port=record.get("dst_port"), protocol=record.get("protocol"),
                application=record.get("application"),
                # The firewall's verdict on the session, which is not the
                # platform's: `alert` means it was allowed and logged.
                firewall_action=record.get("action"),
                threat=name or None, threat_id=signature,
                # A URL-filtering record states a category and no signature.
                # Kept apart so an analyst is not shown `content-delivery-
                # networks` where a detection name belongs.
                url_category=record.get("category") or None,
                severity=record.get("severity") or None,
                rule=record.get("rule"), reported_by=record.get("device_name"),
                subtype=record.get("subtype"),
            )

        # User-ID: the firewall states which principal held the address.
        user = record.get("src_user")
        if user and subject:
            problem = account_shape_problem(user)
            if problem:
                b.quarantine(
                    kind="account", field="panos.src_user", value=user, why=problem
                )
            else:
                account = b.node(
                    "account", f"account:{user.lower()}", user, OBSERVED, user=user,
                    machine_account=is_machine_account(user),
                )
                b.edge("attributed_to", subject, account)

        # What was asked for. One position, three meanings, keyed on subtype.
        kind = panos_field_map.misc_kind(record)
        value = panos_field_map.misc_value(record)
        asked = None
        if kind == "domain":
            bare = value.split("/", 1)[0].lower()
            asked = b.node("domain", f"domain:{bare}", bare, OBSERVED)
        elif kind == "url":
            # A vulnerability record names the resource without its host, so
            # the server is part of the identity: the same page on two servers
            # is two resources.
            full = value if "/" in value.rstrip("/") else f"{dst or '?'}/{value}"
            asked = b.node("url", f"url:{full.lower()}", full[:72], OBSERVED, url=full)
        elif kind == "file":
            asked = b.node(
                "file", f"file:{(dst or '?')}:{value.lower()}", value, OBSERVED,
                served_by=dst or None,
            )
        if asked and subject:
            b.edge(
                "requested", subject, asked,
                application=record.get("application"),
                firewall_action=record.get("action"),
                threat=name or None,
                url_category=record.get("category") or None,
            )
        if asked and target and kind in ("url", "file"):
            b.edge("hosted_on", asked, target)


def extract(
    alert_body: str | None,
    *,
    risk_score: int | None = None,
    confirmed_techniques: Iterable[str] = (),
    log_events: Iterable[dict[str, Any]] = (),
    max_log_events: int = MAX_LOG_EVENTS,
) -> Extracted:
    """The entities and relationships one alert witnesses.

    `log_events` are the SIEM events retrieved around the alert, which
    carry the same dotted field names. Reading them through the same
    builder matters: `targetObject` appears 5,805 times across stored log
    context and only 25 times across alert bodies, so the registry layer
    exists almost entirely here — and a process named by both the alert
    and its log context has to be one node, not two.
    """
    b = _Builder()

    # PAN-OS arrives outside Wazuh as a positional record, so it is detected
    # from the body and not from `decoder.name`, which it does not carry.
    panos = panos_field_map.records_of(alert_body)
    if panos:
        _populate_panos(b, panos)
        loudest = _loudest_of(panos_field_map.severity_signals(panos))
        return Extracted(
            entities=list(b.entities.values()),
            edges=list(b.edges.values()),
            unread=sorted(b.unread),
            source_type=PANOS_SOURCE,
            mapped=True,
            source_severity=loudest[0] if loudest else None,
            source_severity_raw=loudest[1] if loudest else None,
            quarantined=b.quarantined,
        )

    fields = read_fields(alert_body)
    _populate(b, fields, risk_score=risk_score,
              confirmed_techniques=confirmed_techniques)
    for index, event in enumerate(log_events or ()):
        if index >= max_log_events:
            b.truncated_logs = True
            break
        _populate(b, fields_of_log_event(event), risk_score=risk_score,
                  confirmed_techniques=confirmed_techniques)
    source_type = source_type_of(fields)
    severity, severity_raw = normalise(fields)
    return Extracted(
        entities=list(b.entities.values()),
        edges=list(b.edges.values()),
        unread=sorted(b.unread),
        source_type=source_type,
        mapped=source_type in MAPPED_DECODERS,
        truncated_logs=b.truncated_logs,
        source_severity=severity,
        source_severity_raw=severity_raw,
        quarantined=b.quarantined,
    )


def fields_of_log_event(event: dict[str, Any]) -> dict[str, Any]:
    """One stored SIEM event, as a field dict the extractor can read.

    The events keep Wazuh's flattened names verbatim, so no translation is
    needed for `data.win.eventdata.*`. The envelope keys sit beside them
    and have to be lifted in by hand.
    """
    out: dict[str, Any] = {}
    for field in (event.get("fields") or ()):
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "").strip()
        value = field.get("value")
        if name and value not in (None, "") and name not in out:
            out[name] = value
    agent = event.get("agent")
    if isinstance(agent, dict):
        if agent.get("name"):
            out.setdefault("agent.name", agent["name"])
        if agent.get("ip"):
            out.setdefault("agent.ip", agent["ip"])
    elif isinstance(agent, str) and agent:
        out.setdefault("agent.name", agent)
    decoder = event.get("decoder")
    if isinstance(decoder, dict) and decoder.get("name"):
        out.setdefault("decoder.name", decoder["name"])
    elif isinstance(decoder, str) and decoder:
        out.setdefault("decoder.name", decoder)
    rule = event.get("rule")
    if isinstance(rule, dict):
        mitre = rule.get("mitre")
        if isinstance(mitre, dict) and mitre.get("id"):
            out.setdefault("rule.mitre.id", mitre["id"])
        if rule.get("level") is not None:
            out.setdefault("rule.level", rule["level"])
    return out