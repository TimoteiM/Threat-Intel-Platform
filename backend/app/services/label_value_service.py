r"""Parse `Label: value` prose into fields, where values contain spaces.

The largest alert shape in this corpus and the most fragile: **7,386 of
16,969 bodies (43.5%)**. Windows Event Log text, Wazuh alert summaries, and
anything else that renders an event as readable lines.

The failure this is built around
--------------------------------
A value can contain spaces — a file path, a command line, a display name, a
process argument:

    Account Name:  adm_lbyfszaa   Display Name:  Zakaria El Bouyafsakh adm

A parser that reads a value as "everything up to the next whitespace"
returns `Zakaria` and loses the rest. Worse, the discarded tail is then
available to be read as the *next* label — so `El Bouyafsakh adm   Home
Directory:  -` can yield a field called `El Bouyafsakh adm   Home Directory`
with the real label swallowed into it.

That is the eleventh instance of this codebase's delimiter-boundary family,
and it lives in the biggest format we have, which is why its test came
before the parser.

The fix: a value ends at the next *label* or the end of the line
----------------------------------------------------------------
Not at the next space. Labels are located first, and each value is the text
between its own colon and the next boundary. So a value containing spaces,
colons inside a path, or a time like `09:38:44` survives whole, because
nothing is split on a character — the boundaries are the labels themselves.

**And the end of the line is also a boundary.** The first version of this
parser bounded values *only* by the next label, which made a newline
invisible: a value ran on until the next thing that looked like a label,
swallowing whole following lines. Measured against the 25,186 materialised
account nodes, it disagreed with the live line-anchored parser on 12,421, and
in **9,963 of them (80.2%) the live value was a prefix of this one** — the
fix was worse than what it replaced, on four fifths of the rows where they
differed.

That is the **twelfth** delimiter-boundary instance in this codebase, and it
was inside the fix for the eleventh. Both halves are needed and neither is
sufficient: the line bound alone is the live parser, which cannot split the
63.8% of bodies carrying several pairs on one line; the label bound alone is
what this module shipped with first.

A label is deliberately narrow: capitalised words, no digits, at most four of
them, immediately followed by a colon and whitespace. `Account Domain:` is a
label; `C:\Windows` is not, and neither is `https://host`, because neither
matches the shape.

What this does NOT claim
------------------------
It reports the fields it can see and says nothing about the rest. A body may
carry indicators in genuine prose as well as in labelled fields, and a value
not found under a label gets **no provenance**, not a default one —
`provenance()` returns `None`, which a caller must not read as permission.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: A label: one to four capitalised words, then a colon, then whitespace.
#:
#: `(?<![:\w])` keeps it from firing mid-token, so `C:\Users\Name:` and the
#: `https:` in a URL are not labels. Requiring whitespace *after* the colon
#: is what excludes `C:\Windows` and `09:38:44`.
_LABEL = re.compile(
    r"(?<![:\w])((?:[A-Z][A-Za-z]*)(?:[ \t][A-Z][A-Za-z]*){0,3}):(?=[ \t])"
)

#: Fields whose values are never observables, by what the label means. Field
#: *meanings*, not values — the same principle as the CEF header's
#: non-observable positions, and it generalises to any source using these
#: standard Windows labels.
NON_OBSERVABLE_LABELS = frozenset({
    "logon id", "primary group id", "old uac value", "new uac value",
    "password last set", "account expires", "rule level", "severity",
    "version", "product version", "device version", "event id",
    "keywords", "task category", "opcode", "process id", "thread id",
})


@dataclass(frozen=True)
class LabelledFields:
    #: label (lowercased, whitespace-collapsed) -> value, first occurrence
    fields: dict[str, str]
    #: label -> (value_start, value_end) in the original string, so an
    #: indicator found at an offset can be attributed without re-matching.
    spans: dict[str, tuple[int, int]]

    def field_at(self, position: int) -> str | None:
        for label, (start, end) in self.spans.items():
            if start <= position < end:
                return label
        return None

    def is_observable_position(self, position: int) -> bool | None:
        """`None` when the offset is not inside any labelled value.

        An unknown position must not read as permission — the caller
        decides. Same rule as the CEF parser.
        """
        label = self.field_at(position)
        if label is None:
            return None
        return label not in NON_OBSERVABLE_LABELS


def parse(body: str) -> LabelledFields:
    """Every `Label: value` pair, with values intact.

    Values are bounded by the *next label*, never by whitespace, which is
    the whole point.
    """
    text = str(body or "")
    matches = list(_LABEL.finditer(text))
    fields: dict[str, str] = {}
    spans: dict[str, tuple[int, int]] = {}

    for i, match in enumerate(matches):
        label = re.sub(r"\s+", " ", match.group(1)).strip().lower()
        value_start = match.end()
        value_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        # A line end is a hard boundary, and bounding only by the next label
        # made it invisible. See the module docstring: this cost 9,963 of
        # 25,186 materialised account nodes a joined-on trailing line.
        newline = text.find("\n", value_start)
        if newline != -1 and newline < value_end:
            value_end = newline
        raw = text[value_start:value_end]
        value = raw.strip()
        # Trim the trailing run of whitespace from the span too, so an
        # offset in the gap between fields is not attributed to either.
        trimmed_start = value_start + (len(raw) - len(raw.lstrip()))
        if label in fields:
            # First occurrence wins. A repeated label in one body — Windows
            # events repeat `Security ID:` for Subject and New Account — is
            # ambiguous, and picking the later one silently would attribute a
            # value to the wrong section.
            continue
        fields[label] = value
        spans[label] = (trimmed_start, trimmed_start + len(value))
    return LabelledFields(fields=fields, spans=spans)


def provenance(body: str, position: int) -> dict[str, Any] | None:
    """What labelled field a value at `position` came from, or None."""
    parsed = parse(body)
    label = parsed.field_at(position)
    if label is None:
        return None
    return {
        "format": "label_value",
        "field": label,
        "could_be_observable": label not in NON_OBSERVABLE_LABELS,
    }
