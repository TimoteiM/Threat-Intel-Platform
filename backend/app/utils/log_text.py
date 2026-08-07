"""
Telling values from labels in log text.

Alerts arrive as key/value text — `data.win.eventdata.hashes: MD5=…`, or a
Sysmon block, or a SIEM document flattened to dotted keys. Both the indicator
extractor and the AI sanitiser have to decide whether a dotted token is a
hostname or just the name of a field, and they were each getting it wrong in
their own way, so the rules live here once.
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
