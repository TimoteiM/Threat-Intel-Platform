"""Read a named Windows field out of a normalised log event.

**This is the facility, not a pair of one-offs.** `normalise_hit` keeps the
event's own fields as a `fields` list of `{"name", "value"}` pairs — up to 40
per event, present on **92.7%** of stored events, **323 distinct names**. Every
Windows-shaped template that wants something outside the fixed keys needs to
read that list, so it is read in one place with one set of rules.

Two measured hazards, both of which would silently halve a result:

**1. Casing is inconsistent in the data itself.** Measured across 107,668
events: `sourceProcessGUID` appears **10,806** times and `sourceProcessGuid`
**14** — the same logical field, two spellings, a 99.9/0.1 split. Same for
`targetProcessGUID` / `targetProcessGuid`. A case-sensitive lookup on either
spelling loses the other and the loss is invisible, because what comes back
is a shorter list rather than an error. So names match **case-insensitively**
on the last path segment.

**2. One concept has several vendor names.** Sysmon says `image`, Security
channel 4688 says `newProcessName`, other events say `processName`. Measured:
46,422 / 18,042 / 8,768. A template asking for "the process image" means all
three. So the logical names below are **alias groups**, resolved in order of
how well each spelling actually identifies the thing.

Both hazards are the delimiter-and-spelling family this codebase has twelve
recorded instances of, and the reason this module exists rather than a
`next(f for f in fields if f["name"] == …)` at each call site.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

#: Logical field -> vendor spellings, most identifying first.
#:
#: Counts are occurrences across 107,668 stored events, 2026-10-22, and they
#: are here so a reader can see which spelling actually carries the data
#: rather than trusting the order.
ALIASES: dict[str, tuple[str, ...]] = {
    # 46,422 / 18,042 / 8,768 / 23
    "image": ("image", "newProcessName", "processName", "imagePath"),
    # 699 / 18,042
    "parent_image": ("parentImage", "parentProcessName"),
    # 46,422. `sourceProcessGUID` and `targetProcessGUID` are the *other*
    # process in a cross-process event, not this one's identity, so they are
    # deliberately not aliases for it.
    "process_guid": ("processGuid",),
    # 699
    "parent_process_guid": ("parentProcessGuid",),
    # 74,562 / 18,042 / 8,768
    "process_id": ("processId", "newProcessId", "clientProcessId"),
    # 741
    "parent_process_id": ("parentProcessId",),
    # 1,351 / 699
    "command_line": ("commandLine",),
    "parent_command_line": ("parentCommandLine",),
    # 1,005 — the only spelling seen
    "pipe_name": ("pipeName",),
    # 10,820 each: the far side of a cross-process access (Sysmon 10)
    "source_image": ("sourceImage",),
    "target_image": ("targetImage",),
    "source_process_guid": ("sourceProcessGUID", "sourceProcessGuid"),
    "target_process_guid": ("targetProcessGUID", "targetProcessGuid"),
    # 337
    "image_loaded": ("imageLoaded",),
    # 207 / 2 / 1 — small populations, included because a caller asking is
    # better served by "present on 207 events" than by a missing alias.
    "service_name": ("serviceName",),
    "share_name": ("shareName",),
    "share_local_path": ("shareLocalPath",),
    # 7,420 / 10,862 / 1,354
    "logon_type": ("logonType",),
    "target_user_name": ("targetUserName",),
    "ip_address": ("ipAddress",),
}


def pairs(event: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The event's own fields as `(last path segment, value)`, unchanged.

    The full name is `data.win.eventdata.image`; callers want `image`. The
    section is dropped rather than matched on, because the same logical field
    appears under `eventdata` for Sysmon and occasionally elsewhere, and a
    caller asking for the pipe name does not care which block held it.
    """
    out: list[tuple[str, str]] = []
    for item in (event or {}).get("fields") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        value = item.get("value")
        if not name or value in (None, ""):
            continue
        out.append((name.rsplit(".", 1)[-1], str(value)))
    return out


def raw(event: Mapping[str, Any], *spellings: str) -> str | None:
    """The first of these exact spellings present, matched case-insensitively.

    Case-insensitive because the data is inconsistent — see the module
    docstring's `sourceProcessGUID` / `sourceProcessGuid` split.
    """
    wanted = [s.casefold() for s in spellings]
    available = {name.casefold(): value for name, value in pairs(event)}
    for key in wanted:
        if available.get(key):
            return available[key]
    return None


def field(event: Mapping[str, Any], logical: str) -> str | None:
    """A logical field, resolved through its alias group.

    An unknown logical name **raises**, rather than returning None: a
    template asking for a field nobody declared is a programming error, and
    returning None would make it look like an event that lacked the value.
    That distinction is the whole point of this codebase's absence
    convention.
    """
    if logical not in ALIASES:
        raise KeyError(
            f"no alias group for {logical!r}; known: {sorted(ALIASES)}. "
            f"Add one with its measured occurrence count rather than "
            f"matching a spelling inline."
        )
    return raw(event, *ALIASES[logical])


def _norm_path(path: str) -> str:
    r"""A path in one form, for comparison only — never for display.

    **The two sides of the comparison are encoded differently.** Measured
    2026-10-22: the stored normalised events carry doubled backslashes on
    **1,905 of 1,929** image values (98.8%), while the selector read from the
    alert body carries single ones on **250 of 293** (85.3%). So a literal
    equality test between a body-derived selector and a stored event value
    fails on the dominant case, and the comparison falls through to the
    basename rule — which conflates a masquerade. The template would have
    looked like it worked.

    Collapsing runs of backslashes is safe here because a Windows path has no
    meaningful empty segment; a UNC prefix (`\\host\share`) collapses to
    `\host\share` on both sides, so it still compares equal.
    """
    return re.sub(r"\\+", r"\\", str(path or "")).casefold()


def _basename(path: str) -> str:
    """The last segment of a Windows or POSIX path, casefolded."""
    return _norm_path(path).replace("\\", "/").rsplit("/", 1)[-1]


def having(events: Iterable[Mapping[str, Any]], logical: str,
           value: str, *, exact: bool = False) -> list[dict[str, Any]]:
    """Events whose `logical` field matches `value`.

    **Full path first, basename only as a fallback, never a substring.** The
    first version of this matched bidirectionally on substrings, which
    over-matches badly: a two-character field value matches every selector
    containing it, and `...\\svchost.exe` matches a selector naming
    `...\\notsvchost.exe`. So:

    1. exact match on the whole value, casefolded — the normal case, since
       the selector and the events come from the same vendor's paths;
    2. failing that, match on the **basename**, which spans a bare
       `processName` against a fully-qualified `image`.

    Step 2 **conflates a masquerade**: `C:\\Windows\\System32\\cmd.exe` and
    `C:\\temp\\cmd.exe` have one basename and are not one binary. It runs
    only when nothing matched exactly, and for a process *tree* seeded from
    the same alert that is the useful direction — but a caller that needs the
    distinction must pass `exact=True` rather than trust this.

    `exact=True` for identity fields — a GUID, a pipe name — where anything
    looser is a different object.
    """
    raw_needle = str(value or "")
    if not raw_needle:
        return []
    present = [(e, got) for e in (events or [])
               if (got := field(e, logical))]
    # Compared through `_norm_path`, so a single-backslash selector from an
    # alert body matches a doubled-backslash value from a stored event. For a
    # non-path field (a pipe name, a GUID) this is just a casefold.
    needle = _norm_path(raw_needle)
    hits = [dict(e) for e, got in present if _norm_path(got) == needle]
    if hits or exact:
        return hits
    base = _basename(raw_needle)
    return [dict(e) for e, got in present if _basename(got) == base]


#: How a key is written in an **alert body**, as opposed to a stored event.
#:
#: Measured over the 800 most recent `c00` bodies: the `image` key appears as
#: `image: C:\…` on **632 (79.0%)** and in **no other encoding** — `"image":`,
#: `\"image\":` and `image=` are each 0. That is the colon-space form the
#: shipped identifier detectors are known to miss, so a `key="value"` pattern
#: here would have matched nothing and reported the field absent. The other
#: forms are still accepted because one shipper's format is not a contract.
_TEXT_ENCODINGS = (
    r'\\"{key}\\"\s*:\s*\\"(?P<value>[^"\\\n]{{1,400}})',   # json, escaped
    r'"{key}"\s*:\s*"(?P<value>[^"\n]{{1,400}})',            # json, plain
    r'(?<![\\"\w]){key}\s*=\s*"?(?P<value>[^"\n,}}]{{1,400}})',   # key=value
    r'(?<![\\"\w]){key}\s*:\s+(?P<value>[^"\n,}}]{{1,400}})',     # key: value
)


def from_text(body: str, logical: str) -> str | None:
    """A logical field read out of raw alert text, same alias group as `field`.

    **Why this lives beside `field` and not in its own module.** A Wazuh alert
    body is the serialised event: it uses the *same* key names the stored
    `fields` list uses, in a different encoding. Two spelling lists would
    drift, and the one that drifted would be the one nobody was reading — so
    there is one `ALIASES` and two readers over it.

    Returns the first spelling that matches, in alias order, trying each
    encoding. Values are right-stripped of trailing punctuation the
    serialisation adds, never of path characters.
    """
    text = str(body or "")
    if not text:
        return None
    if logical not in ALIASES:
        raise KeyError(f"no alias group for {logical!r}; known: {sorted(ALIASES)}")
    for spelling in ALIASES[logical]:
        for encoding in _TEXT_ENCODINGS:
            pattern = encoding.format(key=re.escape(spelling))
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = (match.group("value") or "").strip().rstrip(',;"\'')
                if value:
                    return value
    return None


def link_parents(events: Sequence[Mapping[str, Any]],
                 seeds: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """`seeds` plus their parents and children, linked by process GUID.

    One hop each way, not a transitive walk: the loop's whole premise is a
    bounded amount of gathering, and a full ancestry chase on a busy host is
    the runaway the budget exists to stop.

    Linked on GUID rather than on process id, because a pid is reused within
    minutes on a busy host and a GUID is not — joining on pid would attach a
    stranger's process to the tree and present it as lineage.
    """
    seed_guids = {g for e in seeds if (g := field(e, "process_guid"))}
    parent_guids = {g for e in seeds if (g := field(e, "parent_process_guid"))}
    out: list[dict[str, Any]] = [dict(e) for e in seeds]
    seen = {e.get("key") for e in out}
    for event in events or []:
        if event.get("key") in seen:
            continue
        guid = field(event, "process_guid")
        parent = field(event, "parent_process_guid")
        # a parent of a seed, or a child of a seed
        if (guid and guid in parent_guids) or (parent and parent in seed_guids):
            out.append(dict(event))
            seen.add(event.get("key"))
    return out
