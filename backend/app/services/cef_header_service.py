"""Parse a CEF header into its named fields, respecting escapes.

Why this exists at all
----------------------
`6.0.4.27` was stored as an `ip` observable in 97 alert bodies, and in all 97
it sits in **field 4 of a CEF header** — which the format defines as *Device
Version*. So "is this a valid address that is not an observable" stops being
a judgement and becomes a lookup: a value from Device Version is not an
indicator, one from a destination-address extension is.

Definitional rather than statistical, which is why it generalises to the next
CEF source rather than to this corpus.

The escape, which is why this is a module and not a `split("|")`
-----------------------------------------------------------------
CEF escapes a literal pipe inside a header field as `\\|`. A naive
`split("|")` on a body whose Device Product contains one **silently shifts
every later field by one position** — and then reads Device Event Class ID as
the Device Version. No exception, no empty value, just the wrong field under
the right name.

That is the eleventh instance of this codebase's delimiter-boundary family,
and it would have been **latent inside the parser written to fix the tenth**.
Measured on the current corpus: 0 of 257 CEF bodies contain an escaped pipe,
so it is not live today — which is precisely why it needed catching now
rather than after a new CEF source arrived with a product name like
`Firewall \\| Edge`.

Per the CEF specification, inside the **header** a backslash escapes `\\` and
`|`; inside the **extension** it also escapes `=`. Newlines are escaped as
`\\n`/`\\r`. This module handles the header only, because the header is where
positions carry meaning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: The header's seven fields, in order, as the specification names them.
#: Position *is* the meaning, which is the whole reason this is reliable.
HEADER_FIELDS = (
    "cef_version",
    "device_vendor",
    "device_product",
    "device_version",
    "device_event_class_id",
    "name",
    "severity",
)

#: Header fields that can never carry an observable, by what the format says
#: they are. Not a list of bad values — a list of field *meanings*, which is
#: fixed by the specification and identical for every CEF source.
NON_OBSERVABLE_FIELDS = frozenset({
    "cef_version", "device_vendor", "device_product", "device_version",
    "device_event_class_id", "severity",
})

_CEF_START = re.compile(r"CEF:(\d+)\|")


@dataclass(frozen=True)
class CefHeader:
    fields: dict[str, str]
    #: Where the extension begins in the original string, so a caller can
    #: parse it without re-finding the boundary.
    extension_offset: int
    #: Character ranges of each field in the ORIGINAL string, so an
    #: indicator found at an offset can be attributed to a field without
    #: re-matching anything.
    spans: dict[str, tuple[int, int]]

    def field_at(self, position: int) -> str | None:
        """Which header field contains this offset, if any."""
        for name, (start, end) in self.spans.items():
            if start <= position < end:
                return name
        return None

    def is_observable_position(self, position: int) -> bool | None:
        """Whether a value at this offset could be an observable.

        `None` means the offset is outside the header — the extension, or
        another part of the body — so this module has no opinion. An
        unknown position must not read as permission; the caller decides.
        """
        field = self.field_at(position)
        if field is None:
            return None
        return field not in NON_OBSERVABLE_FIELDS


def split_header(body: str) -> list[tuple[str, int, int]]:
    """The header's raw segments as (text, start, end), honouring `\\|`.

    Hand-scanned rather than regex-split: a pipe preceded by an odd number
    of backslashes is escaped and belongs to the field, and that is not
    something `split` can express.
    """
    match = _CEF_START.search(body)
    if match is None:
        return []

    # Field 0 is the CEF version, which the prefix already captured.
    segments: list[tuple[str, int, int]] = [
        (match.group(1), match.start(1), match.end(1))
    ]
    i = match.end()          # just past the first `|`
    start = i
    while i < len(body) and len(segments) < len(HEADER_FIELDS):
        ch = body[i]
        if ch == "\\":
            # Skip the escaped character, whatever it is. This is what makes
            # `\|` part of the field instead of a separator.
            i += 2
            continue
        if ch == "|":
            segments.append((body[start:i], start, i))
            i += 1
            start = i
            continue
        i += 1
    if len(segments) < len(HEADER_FIELDS):
        segments.append((body[start:i], start, i))
    return segments


def unescape(value: str) -> str:
    """Resolve header escapes: `\\|` → `|`, `\\\\` → `\\`, `\\n` → newline."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def parse(body: str) -> CefHeader | None:
    """The CEF header of `body`, or None if there is not one."""
    segments = split_header(str(body or ""))
    if not segments:
        return None

    fields: dict[str, str] = {}
    spans: dict[str, tuple[int, int]] = {}
    for name, (raw, start, end) in zip(HEADER_FIELDS, segments):
        fields[name] = unescape(raw)
        spans[name] = (start, end)

    last_end = segments[len(fields) - 1][2] if fields else 0
    return CefHeader(fields=fields, extension_offset=last_end + 1, spans=spans)


def provenance(body: str, position: int) -> dict[str, Any] | None:
    """What field a value at `position` came from, for the provenance record.

    Returns None when the offset is not inside a CEF header, so a caller
    cannot mistake "no opinion" for "it is fine".
    """
    header = parse(body)
    if header is None:
        return None
    field = header.field_at(position)
    if field is None:
        return None
    return {
        "format": "cef",
        "field": field,
        "could_be_observable": field not in NON_OBSERVABLE_FIELDS,
        "device_vendor": header.fields.get("device_vendor"),
        "device_product": header.fields.get("device_product"),
    }
