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
    several field names collide with real suffixes — `.id` is Indonesia, and
    `.name`, `.channel` and `.computer` are all real gTLDs, so no public-suffix
    check can refuse them. A key is recognised by its position, not its spelling.

    Two shapes, because SIEMs ship both:

        rule.id: 60104              bare key at the start of a line
        "agent.name": "exprdsh002"  quoted key in a JSON object

    The quoted form is the one that matters in practice. A Wazuh alert arrives
    as escaped JSON — `\\"agent.id\\": \\"1174\\"` — where the token is preceded
    by a quote rather than starting the line, so the bare-key rule alone let
    seven field names through as domains on one real alert, each of them then
    investigated against live collectors.
    """
    if _is_quoted_key(text, match):
        return True

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


# A quoted key in an object: `"agent.id":`, `\"agent.id\":`, `'rule.id' :`.
# The closing quote and the colon are both required, so a *value* that merely
# sits next to a colon is never matched.
_STRUCTURED_KEY_RE = re.compile(r"""(\\?["'])([^"'\\\n]{1,200}?)\1(\s*:)""")


def mask_structured_keys(text: str) -> str:
    """
    Blank out object keys, leaving everything else at the same offset.

    A key is a field name. It can never be an indicator, so the reliable way to
    stop one being read as a domain is not to guess from its spelling — it is to
    remove keys from what the matcher sees.

    Masking rather than parsing, for two reasons. Alert bodies are usually prose
    wrapped around a JSON blob, often escaped into a string and sometimes
    truncated, so `json.loads` fails on the majority of real deliveries. And
    every position the extractor reports — `first_seen_at`, the field-name and
    defanging checks — is an offset into the original text, so the masked copy
    has to stay byte-for-byte the same length.

    Values are untouched: `"host": "evil.com"` keeps `evil.com`, because only
    the token followed by a colon is blanked.
    """
    def blank(match: re.Match[str]) -> str:
        return f"{match.group(1)}{' ' * len(match.group(2))}{match.group(1)}{match.group(3)}"

    return _STRUCTURED_KEY_RE.sub(blank, str(text or ""))


def _is_quoted_key(text: str, match: re.Match[str]) -> bool:
    """
    True for `"token":` — a JSON object key, escaped or not.

    Deliberately requires the closing quote *and* the colon. A quoted value such
    as `"host": "evil.com"` must stay a value: `evil.com` is followed by a quote
    and then a comma or brace, never a colon.
    """
    before = text[max(0, match.start() - 2) : match.start()]
    if not before.endswith('"') and not before.endswith("'"):
        return False

    after = text[match.end() : match.end() + 4]
    # `":` directly, or `\":` when the JSON itself has been escaped into a string.
    return bool(re.match(r'\\?["\']\s*:', after))


# Field namespaces used by the SIEMs that feed this platform. These appear as
# bare dotted paths in text/plain deliveries, where there is no quoting or
# line position to give them away — `data.win.eventdata.image` in the middle of
# a sentence is still a field path, never a hostname.
_SIEM_FIELD_ROOTS = frozenset(
    {
        # Wazuh
        "agent", "manager", "decoder", "rule", "predecoder", "syscheck",
        "rootcheck", "sca", "syscollector", "data", "location", "cluster",
        "previous_output", "full_log", "input", "gl2", "wazuh",
        # Elastic Common Schema / Filebeat / Winlogbeat
        "winlog", "event", "host", "log", "ecs", "fileset", "observer",
        "process", "source", "destination", "user", "url", "http", "tls",
        "network", "related", "threat", "registry", "dll", "file", "dns",
        # Splunk / QRadar / misc
        "sourcetype", "index", "splunk", "qradar", "sysmon",
    }
)


def is_siem_field_path(value: str) -> bool:
    """
    True for a dotted path from a SIEM document rather than a hostname.

    The bar is deliberately high: the first label must be a known field root and
    the last must not look like a public suffix a real host would end on. This
    is a fallback for unquoted occurrences — the positional checks in
    `is_field_name` handle the common case.
    """
    candidate = str(value or "").strip().strip("\"'").rstrip(".").lower()
    if "." not in candidate:
        return False
    labels = candidate.split(".")
    if labels[0] not in _SIEM_FIELD_ROOTS:
        return False
    # `agent.ip` is a field; `data.gov.uk` would be a real host. Requiring the
    # last label to be non-geographic keeps the rule from swallowing hostnames
    # that happen to start with one of these words.
    return labels[-1] not in {"com", "net", "org", "io", "gov", "edu", "uk", "de", "fr", "eu", "ro"}


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
