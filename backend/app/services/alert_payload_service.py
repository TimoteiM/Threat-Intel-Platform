"""
Accept an alert the way a SIEM actually emits it.

Senders do not wrap their alert in our schema — Wazuh/OpenSearch posts its alert
document, flattened (`data.win.system.message`) or nested (`data: {win: {…}}`),
with metadata around it. This module turns any such document into the three
things the pipeline needs:

    alert_body   readable text: a header of the fields that identify the alert,
                 then the raw Sysmon/EDR message verbatim so the endpoint-event
                 parser sees a real event block, then the remaining fields
    title        the alert's own title, or its rule description
    external_ref the sender's document id, so their ticket and our run line up

Nothing is invented: every line in the body comes from the payload, and the
message field is passed through untouched rather than re-encoded, because that
is what the Sysmon parser and the AI both read best.
"""

from __future__ import annotations

import json
from typing import Any

# Fields carrying the raw event text, in order of preference.
MESSAGE_KEYS = (
    "data.win.system.message",
    "message",
    "full_log",
    "data.message",
    "event.original",
)

# Whole-document duplicates and transport noise — including them would double
# the AI's input and every extracted indicator.
NOISE_PREFIXES = ("_source", "@metadata", "_index", "_type", "_score", "input.")

# Header lines, in the order an analyst reads them: what fired, on which host,
# when, and how the rule classified it.
HEADER_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Alert", ("title", "rule.description", "trigger")),
    ("Rule", ("rule.id",)),
    ("Rule level", ("rule.level", "severity")),
    ("Groups", ("rule.groups",)),
    ("MITRE", ("rule.mitre.id", "rule.mitre.technique", "rule.mitre.tactic")),
    ("Agent", ("agent.name", "agent.id")),
    ("Agent IP", ("agent.ip",)),
    ("Computer", ("data.win.system.computer", "host.name", "computer")),
    ("Channel", ("data.win.system.channel",)),
    ("Event ID", ("data.win.system.eventID", "alert.type")),
    ("Manager", ("manager.name",)),
    ("Time", ("timestamp", "@timestamp", "period_start")),
)

MAX_EXTRA_FIELDS = 120
MAX_FIELD_CHARS = 600
ID_KEYS = ("_id", "id", "alert_id", "event.id")

# The *rule*, not the alert. ID_KEYS identify one delivery; these identify the
# detection that keeps producing them — what detection-quality reporting needs.
RULE_ID_KEYS = ("rule.id", "rule_id", "signal.rule.id", "detection.rule.id", "sigma_id")
RULE_NAME_KEYS = ("rule.description", "rule.name", "title", "trigger", "alert.name")


def normalize_alert_payload(payload: Any) -> dict[str, Any]:
    """
    Turn a SIEM alert document into `{alert_body, title, external_ref, fields}`.

    A plain string is already an alert body. A document that carries our own
    `alert_body` field is left alone — this only rescues payloads shaped like the
    sender's own alert.
    """
    empty = {
        "alert_body": "",
        "title": None,
        "external_ref": None,
        "detection_rule_id": None,
        "detection_rule_name": None,
        "fields": {},
    }
    if isinstance(payload, str):
        return {**empty, "alert_body": payload}
    if not isinstance(payload, dict):
        return {**empty, "alert_body": str(payload or "")}

    fields = _flatten(payload)
    message = _first_value(fields, MESSAGE_KEYS)
    header = _header_lines(fields)
    extras = _extra_lines(fields, skip_keys={key for key in MESSAGE_KEYS})

    sections: list[str] = []
    if header:
        sections.append("\n".join(header))
    if message:
        sections.append(_clean_message(message))
    if extras:
        sections.append("\n".join(extras))

    return {
        "alert_body": "\n\n".join(sections).strip(),
        "title": _first_value(fields, ("title", "rule.description", "trigger")),
        "external_ref": _first_value(fields, ID_KEYS),
        "detection_rule_id": _first_value(fields, RULE_ID_KEYS),
        "detection_rule_name": _first_value(fields, RULE_NAME_KEYS),
        "fields": fields,
    }


def looks_like_siem_alert(payload: Any) -> bool:
    """True when this is somebody's alert document rather than our own request."""
    if not isinstance(payload, dict):
        return False
    if "alert_body" in payload:
        return False
    return bool(_flatten(payload))


# ── Internals ─────────────────────────────────────────────────────────────────


def _flatten(payload: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """
    Flatten to dotted keys, so nested and pre-flattened documents look the same.

    Wazuh sends `data.win.eventdata.image` as a literal key through one shipper
    and as nested objects through another; both must produce the same result.
    """
    flat: dict[str, str] = {}
    for key, value in payload.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, prefix=f"{path}."))
        elif isinstance(value, (list, tuple)):
            flat[path] = ", ".join(str(item) for item in value)
        elif value is None:
            continue
        else:
            flat[path] = str(value)
    return flat


def _first_value(fields: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = (fields.get(key) or "").strip()
        if value and value != "-":
            return value
    return None


def _header_lines(fields: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for label, keys in HEADER_FIELDS:
        values = [
            (fields.get(key) or "").strip()
            for key in keys
            if (fields.get(key) or "").strip() not in ("", "-")
        ]
        if not values:
            continue
        # Same-label values (MITRE id/technique/tactic) read better joined.
        lines.append(f"{label}: {' | '.join(dict.fromkeys(values))}")
    return lines


def _extra_lines(fields: dict[str, str], *, skip_keys: set[str]) -> list[str]:
    """Everything not already in the header or the message, bounded and stable."""
    header_keys = {key for _label, keys in HEADER_FIELDS for key in keys}
    lines: list[str] = []
    for key in sorted(fields):
        if key in header_keys or key in skip_keys:
            continue
        if any(key.startswith(prefix) for prefix in NOISE_PREFIXES):
            continue
        value = (fields.get(key) or "").strip()
        if not value or value == "-":
            continue
        lines.append(f"{key}: {value[:MAX_FIELD_CHARS]}")
        if len(lines) >= MAX_EXTRA_FIELDS:
            lines.append(f"… {len(fields) - len(lines)} further field(s) omitted")
            break
    return lines


def _clean_message(message: str) -> str:
    """
    The raw event text as the agent recorded it.

    Shippers hand us the message JSON-quoted (`"Process Create:\\r\\n…"`) often
    enough that unwrapping it is worth doing: the Sysmon parser reads real line
    breaks far better than the two characters `\\` and `n`.
    """
    text = str(message or "").strip()
    if len(text) > 1 and text[0] == '"' and text[-1] == '"':
        try:
            decoded = json.loads(text)
            if isinstance(decoded, str):
                text = decoded
        except (ValueError, TypeError):
            text = text[1:-1]
    return text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n")
