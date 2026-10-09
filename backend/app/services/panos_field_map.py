"""Reading Palo Alto PAN-OS syslog, which arrives outside Wazuh.

Why this source rather than the larger ones
-------------------------------------------
Measured on `alert_body_investigation_runs`, the only table holding the raw
line — `alert_graph_entity` has no rows for this source at all, which is the
defect:

    224 runs carry a PAN-OS record      1.5% of the 15,357 stored alerts
    734 records inside them             a run holds 1 to 14, median 2
    168 of 224 have entity_host = NULL  three quarters cannot be keyed to a
                                        machine, and 48 of the rest are keyed
                                        to the firewall itself

So the field map is not only about drawing nodes. It is the only way these
alerts acquire a subject at all.

And it contains case #1106, one of four `true_positive` cases in
`alert_case_spine`, whose graph draws nothing today: two alerts, both PAN-OS,
a DNS sinkhole on a spyware domain.

The record is positional, and three things about it bite
--------------------------------------------------------
**Commas inside quoted fields.** 197 of the first 199 records sampled carry a
quoted field containing a comma — `"used-by-malware,has-known-vulnerability"`,
`"Microsoft Windows 11 Enterprise , 64-bit"`. `split(",")` is wrong on 99% of
real lines, so the parse goes through `csv.reader`, which is what the quoting
is for. This would have been the ninth delimiter-boundary bug in this
codebase.

**The BSD timestamp has a variable-width day.** `Sep 17` has one space,
`Sep  8` has two, so `line.split(" ", 4)` puts the relay address *inside*
field 1. It happens to be harmless here, because the whole header precedes the
first comma and so lands inside FUTURE_USE either way — but only by luck, and
a header containing a comma would shift every position. The header is stripped
by pattern, not by counting spaces.

**One alert body holds several records, and sometimes a JSON envelope.** 733 of
734 records sit in the body as plain text, one per line; one run carries its
record inside `{"rawLogs": ["..."]}` with the quotes backslash-escaped, where
`csv.reader` would read `\\"www.darmika.be\\"` as part of the value. Records
are therefore found by pattern anywhere in the body and unescaped when they
need it, rather than by iterating lines.

What is mapped, and what is not
-------------------------------
    THREAT          718 records   mapped positionally (131 fields)
    GLOBALPROTECT    15 records   51 fields, a different layout, no map
    CEF key=value    52 records   mapped by key

`THREAT` subtypes present: vulnerability 619, spyware 62, wildfire-virus 34,
virus 3. GLOBALPROTECT is quarantined by name rather than guessed at: its
positions are not the THREAT positions, and reading field 35 as a severity
there would invent one.

Severity, which this source does state
--------------------------------------
Field 35 of a THREAT record. Measured over all 718: high 455, low 167,
medium 96, and **nothing unreadable** — against 224 of 224 runs currently
holding `source_severity = NULL`. Normalised onto the same 1-100 scale as
FortiGuard IPS so the two firewalls rank together, and resolved by the same
LOUDEST WINS rule, which matters here because one body holds up to 14 records
and they disagree.

13 of 224 runs still end up unrated: every one is GLOBALPROTECT-only.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Iterator

#: The syslog header in front of the positional record: an optional priority,
#: a BSD timestamp whose day is one or two digits, and the relay address.
#: Matched rather than counted, because the day's width varies.
_HEADER = r"(?:<\d+>)?[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d \S+ "

#: A PAN-OS record: the header, then FUTURE_USE, then the receive time. Two
#: anchored timestamps is what keeps this from matching arbitrary CSV.
_RECORD = re.compile(_HEADER + r"\d+,\d{4}/\d{2}/\d{2} \d\d:\d\d:\d\d,")

#: A PAN-OS CEF record. The vendor and product are fixed by Palo Alto, so this
#: is their spelling, not a guess at the customer's.
_CEF = re.compile(r"CEF:0\|Palo Alto Networks\|PAN-OS\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|")

#: CEF extensions are `key=value` separated by spaces, and values contain
#: spaces: `rt=Sep 17 2026 11:36:21 GMT`, `cs1=LEO to UNTRUST - WEB`. So a
#: value runs up to the next key, never to the next space.
_CEF_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=")

#: Field counts PAN-OS writes for the record types in this estate. A record
#: with any other width is quarantined rather than read at the positions it
#: happens to have, because a positional map against the wrong layout does not
#: fail — it returns the wrong field.
_WIDTHS = {"THREAT": 131, "GLOBALPROTECT": 51}

#: Zero-based positions of the THREAT record, read off the data rather than a
#: manual. Verified against a known line in `docs/problems/`.
THREAT = {
    "receive_time": 1, "serial": 2, "type": 3, "subtype": 4,
    "generated_time": 6, "src_ip": 7, "dst_ip": 8,
    "nat_src_ip": 9, "nat_dst_ip": 10,
    "rule": 11, "src_user": 12, "dst_user": 13, "application": 14,
    "vsys": 15, "src_zone": 16, "dst_zone": 17,
    "inbound_if": 18, "outbound_if": 19,
    "session_id": 22, "repeat_count": 23, "src_port": 24, "dst_port": 25,
    "protocol": 29, "action": 30, "misc": 31, "threat_name": 32,
    "category": 33, "severity": 34, "direction": 35,
    "vsys_name": 58, "device_name": 59,
}

#: PAN-OS's five named severities onto 1-100. The same shape as
#: `_FORTIOS_IPS` in `source_severity_service`, deliberately: both are a
#: firewall's own grading of an attack signature, and giving them different
#: scales would make the two incomparable for no reason. Never 0 — an absent
#: severity is an absence, not a low grade.
SEVERITIES = {
    "critical": 100, "high": 86, "medium": 57, "low": 29,
    "informational": 14, "info": 14,
}

#: CEF severity is 0-10 by the CEF specification.
_CEF_MAX = 10

#: PAN-OS writes `cat=9999(9999)` on a URL-filtering record, which is the
#: absence of a threat id rather than one. All 91 cef:url records in the store
#: carry exactly this.
_URL_FILTERING = re.compile(r"^\s*(?:9999(?:\(9999\))?|from-policy)?\s*$")

#: What position 32 means, keyed on the subtype PAN-OS itself writes beside
#: it. The field is documented as "URL/Filename" and holds a different kind of
#: thing per subtype, so the subtype is the only non-guessing way to read it:
#:
#:     spyware          a hostname          "www.darmika.be"
#:     vulnerability    a URI on the server showPresenceWSW.cfm
#:     wildfire-virus   a filename          the sample's name
#:     cef:url          a full request      "qvdt3feo.com/"
#:
#: Sniffing the suffix instead reads `showPresenceWSW.cfm` as a file, which
#: would put a web page on the graph as something on an endpoint's disk. The
#: extension says what served the page, not where it lives.
_MISC_BY_SUBTYPE = {
    "spyware": "host-or-url", "dns": "host-or-url", "dns-malware": "host-or-url",
    "url": "host-or-url",
    "vulnerability": "url",
    "virus": "file", "wildfire-virus": "file", "wildfire": "file", "file": "file",
}

#: A bare hostname. Deliberately strict: it must have a dot, a TLD of letters,
#: and no path separator, so `showPresenceWSW.cfm` does not become a domain.
_HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,24}$")


@dataclass
class PanosRecord:
    """One PAN-OS event, named by field rather than by position."""

    kind: str                       # THREAT, GLOBALPROTECT, or cef:<class>
    fields: dict[str, str] = dc_field(default_factory=dict)
    #: Why this record could not be read, if it couldn't. Quarantined, never
    #: dropped: a record this platform cannot parse has to be visible as one.
    problem: str | None = None
    raw: str = ""

    @property
    def readable(self) -> bool:
        return self.problem is None

    def get(self, name: str) -> str:
        return (self.fields.get(name) or "").strip()


def _unescape(text: str) -> str:
    """Undo JSON string escaping on a record lifted out of an envelope.

    One run in the corpus carries its record inside `{"rawLogs": ["..."]}`,
    where the record's own quoting arrives as `\\"`. Left alone, `csv.reader`
    reads the backslash as part of the value and the quoted commas split the
    field. Applied only when the escaping is actually present, so a plain
    record — 733 of 734 — is untouched.

    Unescaped until it stops changing, because that envelope is a JSON object
    serialised *into* a JSON string, so its contents are escaped twice. One
    pass left `povgrp\\\\did24`, which the account shape guard then quarantined
    as a path — the guard was right and the parse was wrong.
    """
    for _ in range(4):
        if '\\"' not in text and "\\\\" not in text:
            return text
        text = text.replace('\\\\"', '"').replace('\\"', '"').replace("\\\\", "\\")
    return text


def _split(record: str) -> list[str]:
    """The positional fields, with quoting respected."""
    return next(csv.reader(io.StringIO(record)), [])


def records_of(body: str | None) -> list[PanosRecord]:
    """Every PAN-OS record in one alert body, readable or quarantined.

    Found by pattern anywhere in the body rather than per line: a body holds
    1 to 14 of them, and one wraps them in a JSON envelope on a single line.
    """
    text = body or ""
    out: list[PanosRecord] = []
    starts = [m.start() for m in _RECORD.finditer(text)]
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        segment = text[start:end]
        # A record ends at a newline or at the envelope's closing quote,
        # whichever comes first; everything after is another log's business.
        for terminator in ("\n", '\\"]', '"]'):
            cut = segment.find(terminator)
            if cut > 0:
                segment = segment[:cut]
        out.append(_read_positional(_unescape(segment.strip())))
    for match in _CEF.finditer(text):
        out.append(_read_cef(text, match))
    return out


def _read_positional(segment: str) -> PanosRecord:
    record = re.sub("^" + _HEADER, "", segment)
    values = _split(record)
    kind = (values[THREAT["type"]] if len(values) > THREAT["type"] else "") or "?"
    if kind not in _WIDTHS:
        return PanosRecord(
            kind=kind, raw=segment[:400],
            problem=(
                f"PAN-OS writes a different field layout per record type, and "
                f"{kind!r} is not one this platform has a map for. Reading it "
                "at the THREAT positions would return the wrong field rather "
                "than fail."
            ),
        )
    if len(values) != _WIDTHS[kind]:
        return PanosRecord(
            kind=kind, raw=segment[:400],
            problem=(
                f"A {kind} record has {_WIDTHS[kind]} fields and this one has "
                f"{len(values)}, so the positions cannot be trusted. Either "
                "the firmware writes a different width or the record was "
                "truncated in transit."
            ),
        )
    if kind != "THREAT":
        return PanosRecord(
            kind=kind, raw=segment[:400],
            problem=(
                f"{kind} records are not mapped yet. There are 15 of them in "
                "the store against 718 THREAT records, and their 51 positions "
                "are a different layout — subtype, then an authentication "
                "event, not a source and destination."
            ),
        )
    return PanosRecord(
        kind=kind, raw=segment[:400],
        fields={name: values[at] for name, at in THREAT.items() if at < len(values)},
    )


def _read_cef(text: str, match: re.Match[str]) -> PanosRecord:
    """A CEF record, read by key. 25 runs carry only this form."""
    tail = text[match.end():]
    for terminator in ("\n", '\\"]', '"]'):
        cut = tail.find(terminator)
        if cut > 0:
            tail = tail[:cut]
    keys = [(m.group(1), m.start(1), m.end()) for m in _CEF_KEY.finditer(tail)]
    pairs: dict[str, str] = {}
    for index, (name, _at, after) in enumerate(keys):
        stop = keys[index + 1][1] if index + 1 < len(keys) else len(tail)
        if name not in pairs:
            pairs[name] = _unescape(tail[after:stop].strip()).strip('"').strip()
    fields = {
        "type": "THREAT", "subtype": match.group(2),
        "src_ip": pairs.get("src", ""), "dst_ip": pairs.get("dst", ""),
        "src_user": pairs.get("suser", ""), "dst_user": pairs.get("duser", ""),
        "application": pairs.get("app", ""), "action": pairs.get("act", ""),
        "protocol": pairs.get("proto", ""), "src_port": pairs.get("spt", ""),
        "dst_port": pairs.get("dpt", ""), "misc": pairs.get("request", ""),
        # `cs2` is the URL *category* and `cat` is `9999(9999)` on all 91 of
        # these records — the URL-filtering placeholder, with
        # `PanOSThreatCategory=N/A` beside it. So a CEF url record states no
        # signature, and putting the category in `threat_name` presented
        # `computer-and-internet-info` and `URLCAT-WHITELIST` to an analyst as
        # detections. The category is kept as a category.
        "category": pairs.get("cs2", ""),
        "threat_name": (
            pairs.get("cat", "") if not _URL_FILTERING.match(pairs.get("cat", "")) else ""
        ),
        "rule": pairs.get("cs1", ""), "src_zone": pairs.get("cs4", ""),
        "dst_zone": pairs.get("cs5", ""), "device_name": pairs.get("dvchost", ""),
        "session_id": pairs.get("cn1", ""), "generated_time": pairs.get("rt", ""),
        # CEF states severity in the header, 0-10, not as a named grade.
        "cef_severity": match.group(4),
    }
    return PanosRecord(
        kind=f"cef:{match.group(2) or 'unknown'}",
        fields={k: v for k, v in fields.items() if v},
        raw=("CEF:0|Palo Alto Networks|PAN-OS|" + match.group(1))[:400],
    )


def severity_signals(records: list[PanosRecord]) -> list[tuple[int, str]]:
    """Every severity these records state, for LOUDEST WINS to resolve.

    One body holds up to 14 records and they disagree — a `low` brute-force
    attempt beside a `high` one. Taking the first would make the alert's
    severity depend on syslog ordering; averaging would invent a grade no
    record states. The loudest is the only answer the data supports.

    Deduplicated by wording. Ten records stating `medium` is one grading, and
    `source_severity_raw` is a sentence an analyst reads — undeduplicated it
    reached 252 characters of the same clause repeated against a column of 96,
    which is an insert failure selected for by how much a firewall logged.
    """
    found: list[tuple[int, str]] = []
    seen: set[str] = set()

    def record_signal(score: int, label: str) -> None:
        if label in seen:
            return
        seen.add(label)
        found.append((score, label))

    for record in records:
        if not record.readable:
            continue
        named = record.get("severity").lower()
        if named in SEVERITIES:
            record_signal(SEVERITIES[named], f"panos.severity={named}")
            continue
        cef = record.get("cef_severity")
        if cef.isdigit():
            level = min(int(cef), _CEF_MAX)
            record_signal(
                max(1, round(level / _CEF_MAX * 100)), f"cef.severity={cef}/10"
            )
    return found


def misc_value(record: PanosRecord) -> str:
    """Position 32's value, with the quoting PAN-OS and CEF each add removed."""
    return record.get("misc").strip().strip('"').strip()


def misc_kind(record: PanosRecord) -> str | None:
    """What the `misc` field holds on this record: a domain, a url, or a file.

    Returns None when the subtype is one whose meaning for this position is
    not established — an absence, so the field shows up as unread rather than
    as a node of the wrong type.
    """
    value = misc_value(record)
    if not value:
        return None
    meaning = _MISC_BY_SUBTYPE.get(record.get("subtype").lower())
    if meaning is None:
        return None
    if meaning == "host-or-url":
        # A bare hostname is a domain; a hostname with a path is a request for
        # something on it, and both occur under these subtypes.
        bare = value.split("/", 1)[0]
        if "/" in value.rstrip("/") or value.startswith("http"):
            return "url"
        return "domain" if _HOSTNAME.match(bare) else "url"
    return meaning


def threat_id(record: PanosRecord) -> tuple[str, str | None]:
    """The signature's name and its Palo Alto id, split.

    The field reads `HTTP Unauthorized Brute Force Attack(40031)` or
    `generic:umbernarthex.org(784699157)`. The id is stable across firmware
    and the wording is not, so the id is what identifies the signature and the
    wording is what an analyst reads.
    """
    raw = record.get("threat_name")
    match = re.match(r"^(.*?)\((\d+)\)\s*$", raw)
    if match:
        return match.group(1).strip(), match.group(2)
    return raw, None


def census(bodies: Iterator[str | None]) -> dict[str, Any]:
    """What a corpus of bodies holds, for the backfill to report."""
    counts: dict[str, int] = {}
    problems: dict[str, int] = {}
    for body in bodies:
        for record in records_of(body):
            counts[record.kind] = counts.get(record.kind, 0) + 1
            if record.problem:
                problems[record.kind] = problems.get(record.kind, 0) + 1
    return {"records": counts, "quarantined": problems}
