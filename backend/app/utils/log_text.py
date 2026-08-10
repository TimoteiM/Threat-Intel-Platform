"""
Telling values from labels in log text.

Alerts arrive as key/value text — `data.win.eventdata.hashes: MD5=…`, or a
Sysmon block, or a SIEM document flattened to dotted keys. Both the indicator
extractor and the AI sanitiser have to decide whether a dotted token is a
hostname or just the name of a field, and they were each getting it wrong in
their own way, so the rules live here once.

A dotted token in an alert is a hostname only if it survives all of these: not a
field name, not a file, not a code identifier, and ending in a suffix that is
either public or one of the private ones every network uses.
"""

from __future__ import annotations

import re

# Trailing labels that mean "file", never "top-level domain", when they appear in
# endpoint telemetry. Deliberately excludes suffixes that are genuinely common as
# TLDs in alerts (com, io, co, app, dev, me, tv, ai).
NON_HOST_SUFFIXES = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "jse", "jar",
        "msi", "scr", "efi", "bak", "tmp", "log", "txt", "csv", "json", "xml", "yml",
        "yaml", "ini", "conf", "cfg", "reg", "dat", "bin", "img", "iso", "cab", "lnk",
        "url", "eml", "msg", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
        "ppt", "pptx", "rtf", "zip", "rar", "gz", "tar", "7z", "png", "jpg", "jpeg",
        "gif", "bmp", "svg", "ico", "mp3", "mp4", "avi", "html", "htm", "php", "asp",
        "aspx", "py", "pyc", "sh", "js", "sql", "db", "md", "shim", "old", "orig",
    }
)

_LABEL_SEPARATORS = (" ", "\t")


def is_field_name(text: str, match: re.Match[str]) -> bool:
    """
    True when this match is a key rather than a value.

    A flattened alert document turns into lines like `rule.id: 110145`, and
    several field names collide with real suffixes — `.id` is Indonesia, `.name`
    and `.category` merely look plausible. A key starts its line and is followed
    by a colon; a hostname inside a value never is.
    """
    line_start = text.rfind("\n", 0, match.start()) + 1
    prefix = text[line_start : match.start()]
    if prefix.strip(" \t-•*"):
        return False
    tail = text[match.end() : match.end() + 2]
    if tail[:1] != ":":
        return False
    # `key: value` separates with whitespace; `evil.com:8080/path` and
    # `host://…` do not — those are values that happen to start a line.
    return tail[1:2] in ("", " ", "\t", "\n", "\r")


def has_file_suffix(value: str) -> bool:
    """True when the value's last label names a file type (`BOOTX64.EFI.shim.bak`)."""
    candidate = str(value or "").strip().strip("\"'").rstrip(".").lower()
    if "." not in candidate:
        return False
    return candidate.rsplit(".", 1)[-1] in NON_HOST_SUFFIXES


# Suffixes no public list knows but every network uses. A host under one of
# these is still a host, and must still be redacted before anything leaves.
INTERNAL_HOST_SUFFIXES = frozenset(
    {
        "local", "localdomain", "lan", "corp", "corporate", "internal", "intranet",
        "intra", "priv", "private", "home", "ad", "domain", "dmz", "localhost",
    }
)

_MIXED_CASE_LABEL = re.compile(r"(?=.*[a-z])(?=.*[A-Z])")


def has_internal_suffix(value: str) -> bool:
    """True when the value ends in a private-network suffix (`db.corp.local`)."""
    candidate = str(value or "").strip().strip("\"'").rstrip(".").lower()
    if "." not in candidate:
        return False
    return candidate.rsplit(".", 1)[-1] in INTERNAL_HOST_SUFFIXES


def looks_like_code_identifier(value: str) -> bool:
    """
    True when a dotted token is a namespace or type reference, not a host.

    A .NET or Java stack trace is a wall of dotted tokens — `System.Net.Security`,
    `StreamJsonRpc.Protocol.JsonRpcMessage` — and enough of their trailing labels
    are real gTLDs (`.security`, `.stream`, `.dell`, `.services`) that asking the
    public suffix list is not enough on its own: one crash report had the
    platform look up `net.security` and `io.stream` at VirusTotal.

    Case is what separates them. DNS is case-insensitive, so hosts are written
    lowercase or shouted (`EXP-C7VD864.INT.EXPERTWARE.NET`); Title case and
    camelCase are how code is written and effectively never how a hostname is.
    Two independent readings of that, either sufficient:

        the last label is Title/camelCase   `…​.Task`, `…​.Security`
        two or more labels are              `System.Net.…`, `Dell.UnifiedAgent.…`

    One mixed-case label alone is not enough: `Server01.corp.local` is a host an
    admin typed with a capital, and dropping it would leak a real machine name.
    """
    candidate = str(value or "").strip().strip("\"'").rstrip(".")
    if "." not in candidate:
        return False
    labels = candidate.split(".")
    mixed = [label for label in labels if _MIXED_CASE_LABEL.match(label)]
    return bool(_MIXED_CASE_LABEL.match(labels[-1])) or len(mixed) >= 2
