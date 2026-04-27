from __future__ import annotations

from dataclasses import dataclass
import re
from collections import defaultdict


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SID_RE = re.compile(r"\bS-\d-(?:\d+-){1,14}\d+\b", re.IGNORECASE)
# Captures the VALUE in key="VALUE" patterns for user/username/srcuser/dstuser fields.
# Uses a lookahead so the closing quote is not consumed and remains in the text.
KEYED_ACCOUNT_RE = re.compile(
    r'(?P<prefix>\b(?:(?:src|dst)?user(?:name)?)\s*=\s*"?)(?P<value>[A-Za-z0-9][A-Za-z0-9._@-]{0,252})(?="|\s|$)',
    re.IGNORECASE,
)
KEYED_HOST_RE = re.compile(
    r'(?P<prefix>\b(?:[A-Z0-9_]*?(?:hostname|computername|computer|host|server|device|workstation))(?:(?:\\?")?\s*:\s*(?:\\?")|\s*[=:]\s*))(?P<value>[A-Z0-9._-]+)',
    re.IGNORECASE,
)
FREEFORM_HOST_RE = re.compile(
    r"(?P<prefix>\b(?:host|server|device|workstation)\s+)(?P<value>[A-Z0-9][A-Z0-9._-]{1,253})",
    re.IGNORECASE,
)
SIMPLE_HOST_RE = re.compile(r"^[A-Z0-9](?:[A-Z0-9-]{0,251}[A-Z0-9])?$", re.IGNORECASE)
FQDN_LABEL_RE = re.compile(r"^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?$", re.IGNORECASE)
# Bare FQDNs not preceded by a keyword (e.g. "onvmbp01.onenet.be" appearing inline).
# Requires at least 3 labels (2+ dots) to avoid matching .NET type references.
# Must not be preceded by @ (emails already handled) or letters/digits (mid-word match).
BARE_FQDN_RE = re.compile(
    r"(?<![/@\w])(?!(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,}(?![\w])",
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
                KEYED_ACCOUNT_RE,
                "ACCOUNT",
                shared_token_map,
                reverse_token_map,
                token_counters,
                entry_summary,
                batch_summary,
            )
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
            # Bare FQDNs not caught by keyed/freeform patterns — run after emails
            # and IPs are already tokenised so their placeholders don't re-match.
            sanitized_text = _replace_pattern(
                sanitized_text,
                BARE_FQDN_RE,
                "HOST",
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
        if EMAIL_RE.fullmatch(original) or IP_RE.fullmatch(original) or not _looks_like_host(original):
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


def _looks_like_host(value: str) -> bool:
    candidate = value.strip().strip("\"'")
    if not candidate or len(candidate) > 253:
        return False
    if EMAIL_RE.fullmatch(candidate) or IP_RE.fullmatch(candidate):
        return False
    if "." in candidate:
        labels = candidate.split(".")
        if len(labels) < 2:
            return False
        if any(not label or len(label) > 63 for label in labels):
            return False
        if any("_" in label or not FQDN_LABEL_RE.fullmatch(label) for label in labels):
            return False
        if not any(any(ch.isalpha() for ch in label) for label in labels):
            return False
        return any(ch.isalpha() for ch in labels[-1]) and len(labels[-1]) >= 2
    if "_" in candidate or not SIMPLE_HOST_RE.fullmatch(candidate):
        return False
    if candidate.isdigit():
        return False
    return any(ch.isalpha() for ch in candidate) and any(ch.isdigit() for ch in candidate)


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
