from __future__ import annotations

from dataclasses import dataclass
import re
from collections import defaultdict


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SID_RE = re.compile(r"\bS-\d-(?:\d+-){1,14}\d+\b", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\b(?:user(?:name)?|account|admin|operator)\b", re.IGNORECASE)
KEYED_HOST_RE = re.compile(
    r"(?P<prefix>\b(?:hostname|computer|host|server|device|workstation)\s*[=:]\s*)(?P<value>[A-Z0-9._-]+)",
    re.IGNORECASE,
)
FREEFORM_HOST_RE = re.compile(
    r"(?P<prefix>\b(?:host|server|device|workstation)\s+)(?P<value>[A-Z0-9][A-Z0-9._-]{1,253})",
    re.IGNORECASE,
)


@dataclass
class SanitizedEntry:
    raw_text: str
    sanitized_text: str
    token_map: dict[str, str]
    summary: dict[str, int]


@dataclass
class SanitizationBatchResult:
    entries: list[SanitizedEntry]
    summary: dict[str, int]


def sanitize_entry(text: str, existing_token_map: dict[str, str] | None = None) -> SanitizedEntry:
    batch = sanitize_entries([text], existing_token_map=existing_token_map or {})
    return batch.entries[0]


def sanitize_entries(
    entries: list[str], existing_token_map: dict[str, str] | None = None
) -> SanitizationBatchResult:
    reverse_token_map = {
        original: token for token, original in (existing_token_map or {}).items()
    }
    shared_token_map = dict(existing_token_map or {})
    token_counters: dict[str, int] = _seed_counters(shared_token_map)
    batch_summary: dict[str, int] = defaultdict(int)
    sanitized_entries: list[SanitizedEntry] = []

    for entry in entries:
        try:
            sanitized_text = entry.replace("\r\n", "\n")
            entry_summary: dict[str, int] = defaultdict(int)
            sanitized_text = _replace_keyed_host_pattern(
                sanitized_text,
                KEYED_HOST_RE,
                "HOST",
                shared_token_map,
                reverse_token_map,
                token_counters,
                entry_summary,
                batch_summary,
            )
            sanitized_text = _replace_keyed_host_pattern(
                sanitized_text,
                FREEFORM_HOST_RE,
                "HOST",
                shared_token_map,
                reverse_token_map,
                token_counters,
                entry_summary,
                batch_summary,
            )
            for label, pattern in (
                ("emails", EMAIL_RE),
                ("ips", IP_RE),
                ("sids", SID_RE),
                ("accounts", ACCOUNT_RE),
            ):
                sanitized_text = _replace_pattern(
                    sanitized_text,
                    pattern,
                    label[:-1].upper(),
                    shared_token_map,
                    reverse_token_map,
                    token_counters,
                    entry_summary,
                    batch_summary,
                )
            sanitized_entries.append(
                SanitizedEntry(
                    raw_text=str(entry),
                    sanitized_text=sanitized_text,
                    token_map=dict(shared_token_map),
                    summary=dict(entry_summary),
                )
            )
        except Exception:
            batch_summary["errors"] += 1
            sanitized_entries.append(
                SanitizedEntry(
                    raw_text=str(entry),
                    sanitized_text="[SANITIZATION_ERROR]",
                    token_map={},
                    summary={"errors": 1},
                )
            )

    return SanitizationBatchResult(entries=sanitized_entries, summary=dict(batch_summary))


def _replace_pattern(
    text: str,
    pattern: re.Pattern[str],
    token_prefix: str,
    shared_token_map: dict[str, str],
    reverse_token_map: dict[str, str],
    token_counters: dict[str, int],
    entry_summary: dict[str, int],
    batch_summary: dict[str, int],
) -> str:
    label_key = token_prefix.lower() + "s"

    def repl(match: re.Match[str]) -> str:
        original = match.group(0)
        token = reverse_token_map.get(original)
        if token is None:
            token_counters[token_prefix] += 1
            token = f"[{token_prefix}_{token_counters[token_prefix]}]"
            reverse_token_map[original] = token
            shared_token_map[token] = original
            batch_summary[label_key] += 1
        if entry_summary.get(label_key, 0) == 0 or token not in text:
            entry_summary[label_key] += 1
        return token

    return pattern.sub(repl, text)


def _replace_keyed_host_pattern(
    text: str,
    pattern: re.Pattern[str],
    token_prefix: str,
    shared_token_map: dict[str, str],
    reverse_token_map: dict[str, str],
    token_counters: dict[str, int],
    entry_summary: dict[str, int],
    batch_summary: dict[str, int],
) -> str:
    label_key = "hosts"

    def repl(match: re.Match[str]) -> str:
        original = match.group("value")
        if EMAIL_RE.fullmatch(original) or IP_RE.fullmatch(original):
            return match.group(0)
        token = reverse_token_map.get(original)
        if token is None:
            token_counters[token_prefix] += 1
            token = f"[{token_prefix}_{token_counters[token_prefix]}]"
            reverse_token_map[original] = token
            shared_token_map[token] = original
            batch_summary[label_key] += 1
        entry_summary[label_key] += 1
        return f"{match.group('prefix')}{token}"

    return pattern.sub(repl, text)


def _seed_counters(shared_token_map: dict[str, str]) -> dict[str, int]:
    counters: dict[str, int] = defaultdict(int)
    token_re = re.compile(r"^\[(?P<prefix>[A-Z]+)_(?P<number>\d+)\]$")
    for token in shared_token_map:
        match = token_re.match(token)
        if not match:
            continue
        prefix = match.group("prefix")
        counters[prefix] = max(counters[prefix], int(match.group("number")))
    return counters
