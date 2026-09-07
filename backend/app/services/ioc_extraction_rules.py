"""Shared machinery for indicator extraction: spans, rejections, and one boundary contract.

Three pieces of infrastructure that sit under the existing extraction passes
rather than replacing them. The pass order — URL, email, IP, hash, domain,
ioc-finder — is unchanged; what changes is that every pass now claims the text
it consumed, every rejection is recorded with the rule that caused it, and every
domain decision goes through one validator instead of four scattered guards.

All three are deterministic: no clocks, no randomness, no caching. The same
input produces the same output on every run, which the ingest dedupe, the
prior-investigation reuse and the re-verdict path all depend on.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.utils.domain_utils import has_public_suffix
from app.utils.log_text import is_siem_field_path, looks_like_code_identifier


# ─────────────────────────────────────────────────────────────────────────────
# 1. Consumed spans
# ─────────────────────────────────────────────────────────────────────────────


class ConsumedSpans:
    """Character ranges an earlier extraction pass has already claimed.

    Replaces the ad-hoc bookkeeping the extractor grew one case at a time — a
    `url_hosts` set so a URL's host was not re-reported as a bare domain, and a
    `consumed_hashes` set so a digest read out of `hashes=` was not re-read as a
    loose hash. Both solved the same problem in different currencies (values,
    not positions), so neither helped the third case: the domain half of an
    email address being extracted again as a domain.

    Positions are the honest unit. Two indicators that occupy the same
    characters are one thing seen twice, whatever their values look like.

    Earlier pass wins, which is why the order in the extractor is load-bearing:
    a URL claims its host before the domain pass runs, so the host is attributed
    to the URL that contained it rather than reported twice.

    Spans are kept sorted by start offset and searched with bisect. An alert
    body here can be eleven megabytes and a pass can test tens of thousands of
    candidates against a few hundred claims, so a linear scan per candidate is
    the difference between milliseconds and minutes.
    """

    __slots__ = ("_starts", "_spans")

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._spans: list[tuple[int, int, str, str]] = []

    def __len__(self) -> int:
        return len(self._spans)

    def claim(self, start: int, end: int, *, kind: str, value: str) -> bool:
        """Take ownership of `[start, end)`. False when it overlaps a claim.

        A refused claim is not an error — it is the mechanism. The caller drops
        the candidate and records why.
        """
        if end <= start:
            return False
        if self.overlapping(start, end) is not None:
            return False
        index = bisect.bisect_left(self._starts, start)
        self._starts.insert(index, start)
        self._spans.insert(index, (start, end, str(kind), str(value)))
        return True

    def overlapping(self, start: int, end: int) -> tuple[int, int, str, str] | None:
        """The claim covering any part of `[start, end)`, if there is one.

        Only the claim starting at or before `start` can reach into the range
        from the left, and claims do not overlap each other, so one step back
        from the insertion point is enough to check that side.
        """
        if end <= start or not self._spans:
            return None
        index = bisect.bisect_right(self._starts, start)
        if index:
            previous = self._spans[index - 1]
            if previous[1] > start:
                return previous
        if index < len(self._spans) and self._spans[index][0] < end:
            return self._spans[index]
        return None

    def is_consumed(self, start: int, end: int) -> bool:
        return self.overlapping(start, end) is not None

    def claimed_by(self, start: int, end: int) -> str | None:
        """The kind of indicator that owns this range, for the rejection record."""
        found = self.overlapping(start, end)
        return found[2] if found else None

    def spans(self) -> list[tuple[int, int, str, str]]:
        """Every claim, in text order. Returned as a copy so callers cannot edit."""
        return list(self._spans)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Rejection log
# ─────────────────────────────────────────────────────────────────────────────

# One word each, because a reason that needs a sentence is a reason nobody
# aggregates. These are the only values that may appear.
REJECTION_REASONS: frozenset[str] = frozenset(
    {
        "private_ip",           # RFC1918 / loopback / link-local — real, not investigable
        "field_path",           # user.email, source.ip — a SIEM key, not a host
        "file_extension",       # payload.exe, snapshot.sh — a filename
        "version_string",       # 10.0.17763.1 — a build number
        "url_host_duplicate",   # already reported as part of a URL
        "span_consumed",        # these characters belong to an earlier indicator
        "no_public_suffix",     # the last label is not a real suffix
        "purely_numeric_label", # every label before the suffix is digits
        "excluded",             # matched an exclusion the analyst configured
        "malformed_label",      # empty, over 63 chars, or an illegal character
        "too_few_labels",       # a bare word cannot be a domain
        "malformed_email",      # an @ with nothing usable either side
        "capped",               # real, but past the investigable-indicator limit
    }
)


@dataclass(frozen=True)
class Rejection:
    """One candidate that was tested and refused."""

    value: str
    reason: str
    offset: int
    # Which pass refused it. Two passes can reject the same string for different
    # rules — a host inside a URL is `url_host_duplicate` to the domain pass and
    # `span_consumed` to ioc-finder — and the answer to "why is this missing"
    # depends on knowing which one spoke.
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "reason": self.reason,
            "offset": self.offset,
            "pass": self.source,
        }


class DroppedLog:
    """Every candidate that was tested and rejected, and the rule that killed it.

    Rejections used to be silent: a candidate failed a guard, the loop moved on,
    and the only trace was an indicator that never appeared. That made every
    extraction complaint an archaeology exercise — `40lineas.net` was found by
    reading a screenshot, and `user.email` by grepping for values that looked
    like field names.

    Recording the reason turns "why is this not extracted" into a lookup.

    Bounded on purpose. An eleven-megabyte body can produce tens of thousands of
    rejections, and a report nobody can read is not a report; the full tally by
    reason is always kept, and the individual entries stop at `limit`.
    """

    __slots__ = ("_entries", "_counts", "_limit", "_seen")

    def __init__(self, limit: int = 200) -> None:
        self._entries: list[Rejection] = []
        self._counts: dict[str, int] = {}
        self._limit = max(0, int(limit))
        self._seen: set[tuple[str, str, int, str]] = set()

    def __len__(self) -> int:
        return sum(self._counts.values())

    def reject(self, value: Any, reason: str, offset: int = -1, *, source: str = "") -> None:
        """Record one rejection.

        An unknown reason raises rather than being stored. The vocabulary is the
        point — a free-text reason is how a list of nine becomes a list of forty
        that cannot be counted.
        """
        if reason not in REJECTION_REASONS:
            raise ValueError(
                f"unknown rejection reason {reason!r}; add it to REJECTION_REASONS "
                f"deliberately rather than inventing one at the call site"
            )
        text = str(value or "")
        self._counts[reason] = self._counts.get(reason, 0) + 1
        key = (text, reason, int(offset), source)
        if key in self._seen or len(self._entries) >= self._limit:
            return
        self._seen.add(key)
        self._entries.append(
            Rejection(value=text, reason=reason, offset=int(offset), source=str(source))
        )

    def counts(self) -> dict[str, int]:
        """How many candidates each rule refused, including beyond the entry cap."""
        return dict(sorted(self._counts.items()))

    def entries(self) -> list[dict[str, Any]]:
        """The recorded rejections, in the order they happened."""
        return [entry.as_dict() for entry in self._entries]

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": len(self),
            "by_reason": self.counts(),
            "entries": self.entries(),
            "truncated": len(self) > len(self._entries),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 3. One boundary contract
# ─────────────────────────────────────────────────────────────────────────────

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

# Suffixes that are also real TLDs. Not a blocklist deciding validity — the
# public suffix list does that — only a way to name the reason more precisely
# when a rejection is reported, so `payload.exe` reads as file_extension rather
# than as the vaguer no_public_suffix.
_FILE_EXTENSION_HINTS: frozenset[str] = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "jar", "msi", "scr", "bin",
        "dat", "tmp", "log", "txt", "csv", "json", "xml", "yml", "yaml", "pdf", "doc",
        "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "zip", "rar", "gz",
        "tar", "iso", "img", "cab", "lnk", "eml", "msg", "png", "jpg", "jpeg", "gif",
        "bmp", "svg", "ico", "mp3", "mp4", "avi", "conf", "ini", "reg", "sql",
    }
)

# Only the `v`-prefixed form. A bare dotted number like `185.220.101.45` is an
# address and `10.0.17763.1` is a build, and both are refused a line below by
# the all-numeric rule — which names them correctly. Matching them here first
# would have reported a CEF `src=` address as a version string.
# Suffixes that are simultaneously a real TLD and, in this corpus, always a
# file. `.zip` and `.cab` are both registrable gTLDs, so the public suffix list
# accepts `cache.zip` and `appconfigsettings.cab` as domains — and removing the
# old blocklist did exactly that, which is how this list earned its way back.
#
# It is a genuine exception to "the suffix list decides", and worth being honest
# about rather than hiding: for these suffixes the corpus outvotes the registry.
# Context would settle it where context exists, but the second extraction pass
# hands over bare values with no position, so a decision has to be possible
# without it. Kept deliberately short — every entry is a suffix this deployment
# has actually produced as a filename.
# `.run` is deliberately absent — ANY.RUN task links are real URLs here.
_FILE_SUFFIXES_THAT_ARE_ALSO_TLDS: frozenset[str] = frozenset(
    {"zip", "cab", "sh", "js", "py", "md", "bat", "cmd", "bar", "box", "download"}
)

_VERSION_RE = re.compile(r"^v\d+(?:\.\d+)+$", re.IGNORECASE)


@dataclass(frozen=True)
class DomainVerdict:
    """Whether a candidate is a domain, and if not, which rule said so."""

    ok: bool
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.ok


VALID = DomainVerdict(True)


class DomainValidator:
    """The single place that decides whether a string is a domain.

    Replaces four guards that each grew from a different incident and could
    disagree: `_looks_like_domain`, the `_NON_TLD_SUFFIXES` blocklist with its
    `_ALWAYS_TLD` rescue list (which contained `com` in both, one cancelling the
    other), `is_siem_field_path`, and a boundary lookahead buried in the domain
    regex. Four rules in four places is four opportunities for a candidate to be
    a domain to one of them and not to another.

    Two decisions shape everything here.

    **It runs on the masked text.** `mask_structured_keys` has already blanked
    field *names*, so what remains after `=` or `"` is a value. Judging a
    candidate by the character in front of it in the *raw* text would reject the
    values instead of the keys: measured on 1,728 real indicators, 36% sit
    immediately after `"` or `=`, because CEF and JSON put them there. The
    boundary checks below therefore look at label structure, not at punctuation.

    **The public suffix list decides validity, not a list of extensions.** A
    blocklist of file suffixes can never keep up with what a log line contains,
    and the one being replaced had already collapsed into contradiction. File
    extensions are still named in rejections, but only to label the reason.
    """

    __slots__ = ("_max_label", "_max_length")

    def __init__(self, *, max_label: int = 63, max_length: int = 253) -> None:
        self._max_label = max_label
        self._max_length = max_length

    # ── the contract ────────────────────────────────────────────────────────

    def check(
        self,
        candidate: str,
        *,
        masked_text: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> DomainVerdict:
        """Is `candidate` a domain? If not, which rule refused it?

        `masked_text`, `start` and `end` are optional; when given, the candidate
        is also checked against what surrounds it. They must refer to the masked
        copy — see the class docstring.
        """
        # Kept as written before lowering: one clause below can only tell a
        # namespace from a hostname by its capitalisation.
        raw = str(candidate or "").strip().strip("\"'").rstrip(".")
        value = raw.lower()

        if not value or "." not in value:
            # A bare word is not a domain. `localhost`, `SYSTEM`, a NetBIOS name.
            return DomainVerdict(False, "too_few_labels")

        if len(value) > self._max_length:
            # Longer than DNS permits; in practice a concatenated log line.
            return DomainVerdict(False, "malformed_label")

        labels = value.split(".")
        if len(labels) < 2:
            return DomainVerdict(False, "too_few_labels")

        for label in labels:
            if not label or len(label) > self._max_label or not _LABEL_RE.match(label):
                # Empty label (`a..b`), over-long, or an illegal character —
                # underscores in `message_sent`, spaces in `Personal computer`.
                return DomainVerdict(False, "malformed_label")

        if looks_like_code_identifier(raw):
            # A stack trace holds more namespaces than hostnames, and enough end
            # in a real gTLD to pass every other clause — `System.Net.Security`
            # was investigated as `net.security`. Capitalisation is what tells
            # them apart, which is why this runs on the value as written.
            return DomainVerdict(False, "field_path")

        if is_siem_field_path(value):
            # `agent.id`, `rule.id`, `system.channel` — `.id` is Indonesia and
            # `.channel` and `.computer` are real gTLDs, so the public suffix
            # list cannot refuse them. One Wazuh alert produced seven of these
            # as investigated hosts.
            return DomainVerdict(False, "field_path")

        if _VERSION_RE.match(value):
            # `v2.0.1` — a version someone wrote with its marker attached.
            return DomainVerdict(False, "version_string")

        tld = labels[-1]
        if not tld.isalpha() or len(tld) < 2:
            # An all-digit last label is an IP octet or a build number, never a
            # TLD. This is what declines `src=185.220.101.45` so the IP pass can
            # own it, and `10.0.17763.1` so nothing does.
            return DomainVerdict(False, "purely_numeric_label")

        if all(label.isdigit() for label in labels[:-1]):
            # Every label before the suffix is digits: `192.168.1.co` shapes.
            #
            # Deliberately "all", not "any". `1.off3.ru` is a real malicious
            # domain in this deployment — its first label is `1` — and a rule
            # that rejected any numeric label would throw it away. A digit in a
            # label is ordinary; a name made only of digits is not a name.
            return DomainVerdict(False, "purely_numeric_label")

        if tld in _FILE_SUFFIXES_THAT_ARE_ALSO_TLDS:
            # A real TLD that this estate only ever produces as a file suffix.
            # See the list's comment: the registry says domain, the corpus says
            # `cache.zip`, and the corpus is the one being extracted.
            return DomainVerdict(False, "file_extension")

        if not has_public_suffix(value):
            # The suffix must be a real one, per the public suffix list — the
            # same source the registrable-domain collapse uses, so validation
            # and collapse cannot disagree. `bootx64.efi`, `alert.category`,
            # `snapshot.sh` all look like domains until you ask it.
            reason = "file_extension" if tld in _FILE_EXTENSION_HINTS else "no_public_suffix"
            return DomainVerdict(False, reason)

        if masked_text is not None and start is not None and end is not None:
            surrounding = self._context(masked_text, start, end)
            if surrounding is not None:
                return surrounding

        return VALID

    # ── context, on the masked text ─────────────────────────────────────────

    def _context(self, masked_text: str, start: int, end: int) -> DomainVerdict | None:
        """Reject a candidate that is a fragment of something longer.

        This is the whole of the boundary contract. It replaces the lookahead
        that used to live in the domain regex and the `is_siem_field_path`
        root-name list, both of which were trying to answer the same question:
        is this the whole token, or the part of one that happens to end on a
        real suffix?
        """
        before = masked_text[max(0, start - 1):start]
        after = masked_text[end:end + 2]

        # Followed by a dot and another label: the match stopped early inside a
        # longer dotted identifier. Okta's
        # `core.user.email.message_sent.mfa_enroll_notification` matched as far
        # as `core.user.email`, which has a genuine `.email` suffix and
        # collapsed to `user.email`. A dot then a space is a sentence ending and
        # is left alone.
        if len(after) >= 2 and after[0] == "." and (after[1].isalnum() or after[1] == "_"):
            return DomainVerdict(False, "field_path")

        # Preceded by a dot and a label character: the match started late inside
        # the same kind of identifier.
        if before == "." :
            return DomainVerdict(False, "field_path")

        # Preceded by a path separator with no whitespace between: a filename,
        # not a host. Adjacency only — the proposed "within 20 characters" rule
        # rejects 16% of real domain and URL indicators here, because JSON and
        # URLs put slashes near everything.
        if before in ("/", "\\"):
            return DomainVerdict(False, "file_extension")

        # An address, not a domain in its own right. The email pass owns it and
        # will have claimed the span; this is the check for when it has not run.
        if before == "@":
            return DomainVerdict(False, "field_path")

        return None

    # ── convenience ─────────────────────────────────────────────────────────

    def is_valid(self, candidate: str, **kwargs: Any) -> bool:
        return bool(self.check(candidate, **kwargs))


# A module-level instance: the validator holds no state that varies per call, so
# one shared object keeps every pass on the same contract by construction.
DOMAIN_VALIDATOR = DomainValidator()
