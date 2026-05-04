from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Iterable, TypedDict


class AIOutput(TypedDict):
    summary: str
    details: str
    reasonlist: list[str]


TokenMapping = dict[str, str]
LLMCallable = Callable[[str], str]


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![/@A-Z0-9_.-])"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}"
    r"(?![A-Z0-9_.-])",
    re.IGNORECASE,
)
URL_HOST_RE = re.compile(
    r"\b[A-Z][A-Z0-9+.-]*://(?P<value>[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)",
    re.IGNORECASE,
)
KEYED_USER_RE = re.compile(
    r"(?P<prefix>\b(?:src|dst)?user(?:name)?\s*[=:]\s*\"?)"
    r"(?P<value>[A-Z0-9][A-Z0-9._@\\-]{0,252})"
    r"(?P<suffix>\"?)",
    re.IGNORECASE,
)
WINDOWS_USER_PATH_RE = re.compile(
    r"(?P<prefix>\b[A-Z]:[/\\]+Users[/\\]+)"
    r"(?P<value>[A-Z0-9][A-Z0-9._-]{0,252})",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"\b(?P<prefix>IP|EMAIL|HOST|USER)\s*_\s*(?P<number>\d+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class _Match:
    start: int
    end: int
    kind: str
    value: str


def tokenize(text: str) -> tuple[str, TokenMapping]:
    """Replace sensitive SOC identifiers with deterministic per-entry tokens."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    matches = _collect_non_overlapping_matches(text)
    mapping: TokenMapping = {}
    reverse_mapping: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = defaultdict(int)

    chunks: list[str] = []
    cursor = 0
    for match in matches:
        chunks.append(text[cursor:match.start])
        key = (match.kind, match.value)
        token = reverse_mapping.get(key)
        if token is None:
            counters[match.kind] += 1
            token = f"{match.kind}_{counters[match.kind]}"
            reverse_mapping[key] = token
            mapping[token] = match.value
        chunks.append(token)
        cursor = match.end
    chunks.append(text[cursor:])

    return "".join(chunks), mapping


def reinject(text: str, mapping: TokenMapping) -> str:
    """Reinject token values using regex replacement, tolerant of minor token spacing/casing."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not mapping:
        return text

    normalized_mapping = {_normalize_token(token): value for token, value in mapping.items()}

    def replace_token(match: re.Match[str]) -> str:
        token = f"{match.group('prefix').upper()}_{match.group('number')}"
        return normalized_mapping.get(token, match.group(0))

    return TOKEN_RE.sub(replace_token, text)


def build_prompt(sanitized_log: str) -> str:
    """Build a strict prompt contract for JSON-only SOC analysis."""
    return (
        "You are a SOC log analysis assistant.\n"
        "Return valid JSON only. Do not include markdown, code fences, comments, or extra text.\n"
        "The JSON object must match this exact schema:\n"
        '{"summary": string, "details": string, "reasonlist": [string]}\n'
        "Tokens such as IP_1, EMAIL_1, HOST_1, and USER_1 are immutable identifiers.\n"
        "Do not modify token casing. Do not add spaces inside tokens. Do not add punctuation inside tokens.\n"
        "Copy every token exactly as it appears when referencing it.\n"
        "Correct example:\n"
        '{"summary":"HOST_1 contacted IP_1","details":"USER_1 accessed HOST_1.",'
        '"reasonlist":["HOST_1 and IP_1 appear in the same event."]}\n'
        "Incorrect examples: host_1, HOST _ 1, HOST-1, [HOST_1].\n"
        "Analyze this sanitized log:\n"
        f"{sanitized_log}"
    )


def validate_ai_output(response: str) -> AIOutput:
    """Parse and validate the AI JSON contract."""
    if not isinstance(response, str):
        raise TypeError("response must be a string")

    try:
        parsed = json.loads(response)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AI response is not valid JSON: {exc.msg}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("AI response must be a JSON object")

    expected_keys = {"summary", "details", "reasonlist"}
    missing = expected_keys - parsed.keys()
    if missing:
        raise ValueError(f"AI response missing required key(s): {', '.join(sorted(missing))}")

    if not isinstance(parsed["summary"], str):
        raise ValueError("AI response field 'summary' must be a string")
    if not isinstance(parsed["details"], str):
        raise ValueError("AI response field 'details' must be a string")
    if not isinstance(parsed["reasonlist"], list) or not all(
        isinstance(item, str) for item in parsed["reasonlist"]
    ):
        raise ValueError("AI response field 'reasonlist' must be a list of strings")

    return {
        "summary": parsed["summary"],
        "details": parsed["details"],
        "reasonlist": parsed["reasonlist"],
    }


def process_log(log: str, llm: LLMCallable | None = None) -> dict[str, Any]:
    """Run tokenize -> prompt -> LLM -> validate -> reinject as an end-to-end pipeline."""
    sanitized_log, mapping = tokenize(log)
    prompt = build_prompt(sanitized_log)
    response = (llm or mock_llm)(prompt)
    validated = validate_ai_output(response)

    reinjected: AIOutput = {
        "summary": reinject(validated["summary"], mapping),
        "details": reinject(validated["details"], mapping),
        "reasonlist": [reinject(reason, mapping) for reason in validated["reasonlist"]],
    }

    return {
        "sanitized_log": sanitized_log,
        "mapping": mapping,
        "prompt": prompt,
        "ai_response": validated,
        "result": reinjected,
    }


def mock_llm(prompt: str) -> str:
    """Deterministic mock LLM for tests and local pipeline demos."""
    tokens = TOKEN_RE.findall(prompt)
    rendered_tokens = [f"{prefix.upper()}_{number}" for prefix, number in tokens]
    unique_tokens = list(dict.fromkeys(rendered_tokens))
    subject = unique_tokens[0] if unique_tokens else "event"
    related = ", ".join(unique_tokens) if unique_tokens else "no immutable tokens"
    return json.dumps(
        {
            "summary": f"Suspicious activity involving {subject}.",
            "details": f"Observed SOC event references {related}.",
            "reasonlist": [
                f"{subject} appears in the sanitized log.",
                "The event should be reviewed by a SOC analyst.",
            ],
        },
        separators=(",", ":"),
    )


def _collect_non_overlapping_matches(text: str) -> list[_Match]:
    candidates: list[_Match] = []
    candidates.extend(_regex_matches(text, IP_RE, "IP"))
    candidates.extend(_regex_matches(text, EMAIL_RE, "EMAIL"))
    candidates.extend(_keyed_value_matches(text, URL_HOST_RE, "HOST"))
    candidates.extend(_regex_matches(text, DOMAIN_RE, "HOST"))
    candidates.extend(_keyed_value_matches(text, KEYED_USER_RE, "USER"))
    candidates.extend(_keyed_value_matches(text, WINDOWS_USER_PATH_RE, "USER"))

    candidates.sort(key=lambda item: (item.start, -(item.end - item.start), _priority(item.kind)))

    selected: list[_Match] = []
    occupied: list[range] = []
    for candidate in candidates:
        candidate_range = range(candidate.start, candidate.end)
        if any(_ranges_overlap(candidate_range, existing) for existing in occupied):
            continue
        selected.append(candidate)
        occupied.append(candidate_range)

    return sorted(selected, key=lambda item: item.start)


def _regex_matches(text: str, pattern: re.Pattern[str], kind: str) -> Iterable[_Match]:
    for match in pattern.finditer(text):
        value = match.group(0)
        if kind == "IP" and not _valid_ipv4(value):
            continue
        yield _Match(match.start(), match.end(), kind, value)


def _keyed_value_matches(text: str, pattern: re.Pattern[str], kind: str) -> Iterable[_Match]:
    for match in pattern.finditer(text):
        value = match.group("value")
        if EMAIL_RE.fullmatch(value) or IP_RE.fullmatch(value):
            continue
        yield _Match(match.start("value"), match.end("value"), kind, value)


def _priority(kind: str) -> int:
    return {"EMAIL": 0, "IP": 1, "USER": 2, "HOST": 3}.get(kind, 99)


def _ranges_overlap(left: range, right: range) -> bool:
    return left.start < right.stop and right.start < left.stop


def _valid_ipv4(value: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in value.split("."))
    except ValueError:
        return False


def _normalize_token(token: str) -> str:
    compact = re.sub(r"\s+", "", token)
    return compact.upper()


EXAMPLE_INPUT = (
    "srcip=10.10.10.5 dst=mail.company.com user=jdoe "
    "email=jdoe@company.com action=blocked"
)


EXAMPLE_OUTPUT = process_log(EXAMPLE_INPUT)


__all__ = [
    "AIOutput",
    "EXAMPLE_INPUT",
    "EXAMPLE_OUTPUT",
    "TokenMapping",
    "build_prompt",
    "mock_llm",
    "process_log",
    "reinject",
    "tokenize",
    "validate_ai_output",
]
