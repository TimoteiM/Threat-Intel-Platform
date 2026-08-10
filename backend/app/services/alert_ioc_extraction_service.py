"""
Alert body IOC extraction.

Parses a raw alert body (SIEM/SOAR alert, ticket note, forwarded warning text)
and returns a deterministic indicator bundle that the alert-body investigation
pipeline can feed straight into the existing collectors.

Extracted indicator types map 1:1 onto the observable types the platform already
supports: url, domain, ip, hash. Email addresses are extracted for context and
their domain part is promoted to a domain indicator.

Hostnames are collapsed to their registered domain (eTLD+1) before becoming a
domain indicator — reputation, WHOIS and threat-feed data live at that level, so
investigating every host of the same site burns collector quota for one answer:

    exprdsh002.int.expertware.net  → expertware.net   (hostnames: [exprdsh002.int.expertware.net])
    mail.corp.example.co.uk        → example.co.uk

Defanged notation common in alert bodies is refanged before matching:
    hxxp://evil.com        → http://evil.com
    1[.]2[.]3[.]4          → 1.2.3.4
    evil(.)com             → evil.com
    user[at]evil[.]com     → user@evil.com
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from app.services.ip_context import is_ipv4_indicator_match
from app.utils.domain_utils import extract_registered_domain, has_public_suffix
from app.utils.log_text import (
    has_file_suffix,
    is_field_name,
    looks_like_code_identifier,
)

# ── Refang patterns ───────────────────────────────────────────────────────────

_REFANG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"h(?:xx|XX|\*\*)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bh(?:xx|XX)ps?\b(?!://)", re.IGNORECASE), "http"),
    (re.compile(r"\s*[\[\(\{]\s*\.\s*[\]\)\}]\s*"), "."),
    (re.compile(r"\s*[\[\(\{]\s*(?:dot|DOT)\s*[\]\)\}]\s*"), "."),
    (re.compile(r"\s*[\[\(\{]\s*:\s*[\]\)\}]\s*"), ":"),
    (re.compile(r"\s*[\[\(\{]\s*(?:at|AT)\s*[\]\)\}]\s*"), "@"),
    (re.compile(r"\s*[\[\(\{]\s*/\s*[\]\)\}]\s*"), "/"),
    (re.compile(r"[\[\(\{]\s*(https?)\s*[\]\)\}]", re.IGNORECASE), r"\1"),
)

# ── Indicator patterns (run against refanged text) ────────────────────────────

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\`]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,24}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{1,4}(?![\w:])", re.IGNORECASE)
HASH_RE = re.compile(r"(?<![A-F0-9])(?:[A-F0-9]{64}|[A-F0-9]{40}|[A-F0-9]{32})(?![A-F0-9])", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![\w.@/-])"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,24}"
    r"(?![\w-])",
    re.IGNORECASE,
)

HASH_TYPE_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}

# Sysmon / EDR digest field: "Hashes: MD5=…,SHA256=…,IMPHASH=…"
HASHES_FIELD_RE = re.compile(
    r"\bHashes\s*[:=]\s*((?:[A-Z0-9]+=[A-F0-9]+\s*,?\s*)+)",
    re.IGNORECASE,
)
_HASH_PAIR_RE = re.compile(r"([A-Z0-9]+)\s*=\s*([A-F0-9]+)", re.IGNORECASE)

# Digests that identify a file and can be looked up in VT/OpenCTI/threat feeds.
FILE_HASH_ALGOS = {"md5": 32, "sha1": 40, "sha256": 64}

# Trailing characters that are punctuation in prose but legal inside a URL.
_URL_TRAILING_TRIM = ").,;:!?]}>\"'*_"

# File extensions that look like TLDs in prose ("invoice.pdf", "setup.exe").
_NON_TLD_SUFFIXES = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "jar", "msi", "scr",
        "com", "bin", "dat", "tmp", "log", "txt", "csv", "json", "xml", "yml", "yaml",
        "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "one",
        "zip", "rar", "7z", "gz", "tar", "iso", "img", "cab", "lnk", "url", "eml", "msg",
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "mp3", "mp4", "avi", "html",
        "htm", "php", "asp", "aspx", "py", "sh", "conf", "ini", "reg", "db", "sql", "md",
    }
)
# Suffixes that are both a file extension and a real TLD, resolved in favour of
# the domain reading. `.sh` and `.js` are deliberately absent: in endpoint
# telemetry `snapshot-bash-123.sh` is a script every time, and a Saint Helena
# domain in an alert body is vanishingly rare.
_ALWAYS_TLD = frozenset({"com", "co", "io", "me", "tv", "ai", "app", "dev"})

_TYPE_ORDER = {"url": 0, "domain": 1, "ip": 2, "hash": 3, "cve": 4, "email": 5}

DEFAULT_MAX_INDICATORS = 30


def refang(text: str) -> str:
    """Return `text` with common defanging notation converted back to live form."""
    out = str(text or "")
    for pattern, replacement in _REFANG_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def extract_alert_indicators(
    alert_body: str,
    *,
    max_indicators: int = DEFAULT_MAX_INDICATORS,
) -> dict[str, Any]:
    """
    Extract deduplicated indicators from a raw alert body.

    Returns:
        {
          "indicators": [ {type, value, matched_text, occurrences, investigable, ...} ],
          "counts": {"url": 1, "domain": 2, ...},
          "total": int,
          "investigable_total": int,
          "truncated": bool,
          "dropped": int,
          "characters": int,
        }

    Indicators are ordered url → domain → ip → hash → email, and within a type by
    first appearance, so repeated runs over the same alert produce the same list.
    """
    raw_text = str(alert_body or "")
    raw_lower = raw_text.lower()
    text = refang(raw_text)

    found: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        kind: str,
        value: str,
        *,
        matched_text: str,
        position: int,
        investigable: bool = True,
        skip_reason: str | None = None,
        count_repeat: bool = True,
        **extra: Any,
    ) -> dict[str, Any]:
        key = (kind, value.lower())
        existing = found.get(key)
        if existing is not None:
            # The second pass re-reports matches the first pass already counted;
            # only a genuine repeat in the text is another occurrence.
            if count_repeat:
                existing["occurrences"] += 1
            return existing
        found[key] = {
            "type": kind,
            "value": value,
            "matched_text": matched_text,
            "occurrences": 1,
            "first_seen_at": position,
            "investigable": investigable,
            "skip_reason": skip_reason,
            # Refanging only rewrites defanged spellings, so a value that no
            # longer appears verbatim in the source was defanged in the alert.
            "defanged_in_source": value.lower() not in raw_lower,
            **extra,
        }
        return found[key]

    def add_domain(
        hostname: str, *, matched_text: str, position: int, count_repeat: bool = True, **extra: Any
    ) -> None:
        """Add a hostname as a domain indicator, collapsed to its eTLD+1."""
        registrable = extract_registered_domain(hostname) or hostname
        entry = add(
            "domain",
            registrable,
            matched_text=matched_text,
            position=position,
            count_repeat=count_repeat,
            **extra,
        )
        # Keep every FQDN that folded into this registered domain — the analyst
        # still needs to know which host the alert actually named.
        hostnames = entry.setdefault("hostnames", [])
        if hostname != registrable and hostname not in hostnames:
            hostnames.append(hostname)

    # ── URLs ──
    url_hosts: set[str] = set()
    for match in URL_RE.finditer(text):
        url = _trim_url(match.group(0))
        if not url:
            continue
        host = _url_host(url)
        if not host:
            continue
        if _is_ip_literal(host):
            add("url", url, matched_text=match.group(0), position=match.start(), host=host)
            url_hosts.add(host.lower())
            continue
        if not _looks_like_domain(host):
            continue
        # The URL's own collector chain already covers its site, so neither the
        # host nor its registered domain is re-investigated as a bare domain.
        url_hosts.add(host.lower())
        url_hosts.add(extract_registered_domain(host))
        add("url", url, matched_text=match.group(0), position=match.start(), host=host)

    # ── Emails (context only — the platform has no email observable type) ──
    email_domains: dict[str, int] = {}
    for match in EMAIL_RE.finditer(text):
        email = match.group(0).strip().strip(".").lower()
        if not email or "@" not in email:
            continue
        add(
            "email",
            email,
            matched_text=match.group(0),
            position=match.start(),
            investigable=False,
            skip_reason="email_addresses_are_reported_as_context",
        )
        domain = email.split("@", 1)[1]
        if _looks_like_domain(domain):
            email_domains.setdefault(domain, match.start())

    # ── IP addresses ──
    for pattern in (IPV4_RE, IPV6_RE):
        for match in pattern.finditer(text):
            # Four dotted integers are also how software versions are written —
            # `Chrome/131.0.0.0` in a user agent is not an address, and looking it
            # up spends an AbuseIPDB/ThreatFox call on a browser build number.
            if pattern is IPV4_RE and not is_ipv4_indicator_match(text, match):
                continue
            candidate = match.group(0).strip()
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            investigable = bool(getattr(parsed, "is_global", False))
            add(
                "ip",
                str(parsed),
                matched_text=match.group(0),
                position=match.start(),
                investigable=investigable,
                skip_reason=None if investigable else "private_or_reserved_address",
                ip_version=parsed.version,
            )

    # ── File hashes ──
    # Sysmon and EDR events list several digests of one file in a single field:
    #   Hashes: MD5=…,SHA256=…,IMPHASH=…
    # Treating those as three indicators means two lookups for one file plus one
    # for an import hash, which no file-reputation source can resolve at all.
    consumed_hashes: set[str] = set()
    for match in HASHES_FIELD_RE.finditer(text):
        digests = _parse_hash_field(match.group(1))
        if not digests:
            continue
        consumed_hashes.update(digests.values())
        primary_algo = next((algo for algo in ("sha256", "sha1", "md5") if algo in digests), None)
        if primary_algo is None:
            # Only non-file digests (imphash and friends) — nothing to investigate.
            continue
        extra = {algo: value for algo, value in digests.items() if algo != primary_algo}
        add(
            "hash",
            digests[primary_algo],
            matched_text=match.group(0)[:200],
            position=match.start(),
            hash_type=primary_algo,
            **({"other_digests": extra} if extra else {}),
        )

    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        if value in consumed_hashes:
            continue  # already reported as part of a file's digest set
        add(
            "hash",
            value,
            matched_text=match.group(0),
            position=match.start(),
            hash_type=HASH_TYPE_BY_LENGTH.get(len(value), "unknown"),
        )

    # ── Bare domains (skip hosts already covered by an extracted URL) ──
    for match in DOMAIN_RE.finditer(text):
        # Checked as written — `_looks_like_domain` needs the original case to
        # recognise a namespace — then lowercased for the identity comparisons.
        matched = match.group(0).strip(".")
        candidate = matched.lower()
        if is_field_name(text, match):
            continue
        if not _looks_like_domain(matched) or candidate in url_hosts:
            continue
        if extract_registered_domain(candidate) in url_hosts:
            continue
        add_domain(candidate, matched_text=match.group(0), position=match.start())

    # Sender/recipient domains carried by email addresses.
    for domain, position in email_domains.items():
        if domain in url_hosts or extract_registered_domain(domain) in url_hosts:
            continue
        add_domain(domain, matched_text=domain, position=position, derived_from="email")

    # ── Second pass: ioc-finder ──
    # A maintained pattern library catches what our own regexes miss — CVEs,
    # scheme-less URLs, defanging spellings we never wrote a rule for. It is a
    # candidate generator only: every value it returns goes through the same
    # validation as our own matches, because it has no notion of a flattened
    # field name, a Windows path, or a digest set belonging to one file.
    _merge_ioc_finder_candidates(
        raw_text,
        text,
        add=add,
        add_domain=add_domain,
        url_hosts=url_hosts,
        consumed_hashes=consumed_hashes,
        known=found,
    )

    ordered = sorted(
        found.values(),
        key=lambda item: (_TYPE_ORDER.get(item["type"], 99), item["first_seen_at"], item["value"]),
    )
    for item in ordered:
        item.pop("first_seen_at", None)
        if not item.get("hostnames"):
            item.pop("hostnames", None)

    limit = max(0, int(max_indicators))
    investigable = [item for item in ordered if item["investigable"]]
    dropped = 0
    if limit and len(investigable) > limit:
        keep = {id(item) for item in investigable[:limit]}
        trimmed: list[dict[str, Any]] = []
        for item in ordered:
            if item["investigable"] and id(item) not in keep:
                dropped += 1
                continue
            trimmed.append(item)
        ordered = trimmed

    counts: dict[str, int] = {}
    for item in ordered:
        counts[item["type"]] = counts.get(item["type"], 0) + 1

    return {
        "indicators": ordered,
        "by_type": group_by_type(ordered),
        "counts": counts,
        "total": len(ordered),
        "investigable_total": sum(1 for item in ordered if item["investigable"]),
        "truncated": dropped > 0,
        "dropped": dropped,
        "characters": len(raw_text),
    }


def group_by_type(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """
    The flat view of the same indicators, for consumers that just want values.

    Everything extracted appears here, including values the pipeline reports but
    does not investigate (private IPs, e-mail addresses, CVEs) — the rich list
    carries `investigable` and `skip_reason` for anyone who needs the distinction.
    """
    grouped: dict[str, Any] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {"md5": [], "sha1": [], "sha256": []},
        "emails": [],
        "cves": [],
    }
    for item in indicators:
        kind = item.get("type")
        value = item.get("value")
        if kind == "ip":
            grouped["ips"].append(value)
        elif kind == "domain":
            grouped["domains"].append(value)
        elif kind == "url":
            grouped["urls"].append(value)
        elif kind == "email":
            grouped["emails"].append(value)
        elif kind == "cve":
            grouped["cves"].append(value)
        elif kind == "hash":
            bucket = str(item.get("hash_type") or "")
            if bucket in grouped["hashes"]:
                grouped["hashes"][bucket].append(value)
            # Digests of the same file travel with it; surface them here too.
            for algo, digest in (item.get("other_digests") or {}).items():
                if algo in grouped["hashes"] and digest not in grouped["hashes"][algo]:
                    grouped["hashes"][algo].append(digest)
    return grouped


def observable_type_for(indicator: dict[str, Any]) -> str:
    """Map an extracted indicator onto the platform's observable_type vocabulary."""
    return str(indicator.get("type") or "domain")


# ── ioc-finder integration ────────────────────────────────────────────────────


def find_iocs_in(text: str) -> dict[str, Any]:
    """
    Raw ioc-finder output for `text`, or an empty result if the library is absent.

    `parse_domain_from_url=False` because a URL's host is already covered by the
    URL indicator — extracting both means investigating one site twice.
    """
    try:
        from ioc_finder import find_iocs
    except ImportError:  # pragma: no cover - dependency is declared in requirements
        return {}
    try:
        return find_iocs(text, parse_domain_from_url=False, parse_from_url_path=False)
    except Exception:
        return {}


def _merge_ioc_finder_candidates(
    raw_text: str,
    refanged: str,
    *,
    add: Any,
    add_domain: Any,
    url_hosts: set[str],
    consumed_hashes: set[str],
    known: dict[tuple[str, str], dict[str, Any]],
) -> None:
    """Fold ioc-finder's candidates in, applying the same rules as our own pass."""
    # The library fangs the text itself, so it sees the original spellings.
    iocs = find_iocs_in(raw_text)
    if not iocs:
        return

    def position_of(value: str) -> int:
        found_at = refanged.lower().find(value.lower())
        return found_at if found_at >= 0 else len(refanged)

    for url in iocs.get("urls") or []:
        normalized = _with_scheme(_trim_url(str(url)))
        host = _url_host(normalized)
        if not normalized or not host:
            continue
        if not (_is_ip_literal(host) or _looks_like_domain(host)):
            continue
        if ("url", normalized.lower()) in known:
            continue
        url_hosts.add(host.lower())
        if not _is_ip_literal(host):
            url_hosts.add(extract_registered_domain(host))
        add("url", normalized, matched_text=str(url), position=position_of(str(url)), host=host,
            count_repeat=False)

    for address in (iocs.get("ipv4s") or []) + (iocs.get("ipv6s") or []):
        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError:
            continue
        if ("ip", str(parsed).lower()) in known:
            continue
        # ioc-finder is context-free: apply the same version-string guard.
        if parsed.version == 4 and not _appears_as_address(refanged, str(parsed)):
            continue
        investigable = bool(getattr(parsed, "is_global", False))
        add(
            "ip",
            str(parsed),
            matched_text=str(address),
            position=position_of(str(address)),
            investigable=investigable,
            skip_reason=None if investigable else "private_or_reserved_address",
            ip_version=parsed.version,
            count_repeat=False,
        )

    for algo, key in (("md5", "md5s"), ("sha1", "sha1s"), ("sha256", "sha256s")):
        for digest in iocs.get(key) or []:
            value = str(digest).lower()
            if value in consumed_hashes or ("hash", value) in known:
                continue
            add("hash", value, matched_text=str(digest), position=position_of(value), hash_type=algo,
                count_repeat=False)

    for address in iocs.get("email_addresses") or []:
        value = str(address).strip().lower()
        if ("email", value) in known:
            continue
        add(
            "email",
            value,
            matched_text=str(address),
            position=position_of(value),
            investigable=False,
            skip_reason="email_addresses_are_reported_as_context",
            count_repeat=False,
        )
        domain = value.split("@", 1)[-1]
        if _looks_like_domain(domain) and domain not in url_hosts:
            if extract_registered_domain(domain) not in url_hosts:
                add_domain(domain, matched_text=domain, position=position_of(domain), derived_from="email",
                           count_repeat=False)

    for domain in iocs.get("domains") or []:
        candidate = str(domain).strip(".").lower()
        if not _is_usable_hostname(refanged, candidate):
            continue
        if candidate in url_hosts or extract_registered_domain(candidate) in url_hosts:
            continue
        add_domain(candidate, matched_text=str(domain), position=position_of(candidate), count_repeat=False)

    for cve in iocs.get("cves") or []:
        value = str(cve).strip().upper()
        if ("cve", value.lower()) in known:
            continue
        add(
            "cve",
            value,
            matched_text=str(cve),
            position=position_of(value),
            investigable=False,
            # Report-only: no collector resolves a CVE today, and an unenriched
            # id in the report is still the fact an analyst needs.
            skip_reason="cve_reported_as_context",
            count_repeat=False,
        )


def _appears_as_address(text: str, value: str) -> bool:
    """Whether this dotted quad reads as an address somewhere in the text."""
    matches = list(re.finditer(rf"(?<![\w.]){re.escape(value)}(?![\w.])", text))
    if not matches:
        return True  # only present in its defanged spelling
    return any(is_ipv4_indicator_match(text, match) for match in matches)


def _is_usable_hostname(text: str, candidate: str) -> bool:
    """
    Whether a candidate hostname is a value in this text rather than a label.

    ioc-finder hands back values without their position, so every occurrence is
    checked: a token that only ever appears as `key: …` at the start of a line is
    a field name (`data.win`, `decoder.name`), not a host.
    """
    if not _looks_like_domain(candidate) or has_file_suffix(candidate):
        return False

    # Standalone occurrences only: ioc-finder also returns the leading part of a
    # longer dotted token, so `data.win.eventdata.commandLine` yields `data.win`.
    standalone = re.compile(rf"(?<![\w.@/-]){re.escape(candidate)}(?![\w.-])", re.IGNORECASE)
    matches = list(standalone.finditer(text))
    if matches:
        # ioc-finder lowercases what it returns, so the namespace check has to be
        # made against the text as it was written.
        if all(looks_like_code_identifier(match.group(0)) for match in matches):
            return False
        return any(not is_field_name(text, match) for match in matches)
    if re.search(re.escape(candidate), text, re.IGNORECASE):
        return False  # only ever a fragment of something longer
    # Nowhere in the text as written. That used to be read as "defanged", but
    # this text is already refanged, so the far likelier explanation is that the
    # finder assembled the token across punctuation it ignores: a .NET assembly
    # line yielded `7cec85d7bea7798e.system.net.security` by joining a public
    # key token to the namespace after it, which then went to a collector as a
    # domain. Accept it only if the labels really are there in order, separated
    # by nothing but a defanged dot.
    return _appears_defanged(text, candidate)


# A dot as an alert might spell it: `.`, `[.]`, `(dot)`, ` dot `.
_DEFANGED_DOT = r"\s*(?:[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]|\.|\sdot\s)\s*"


def _appears_defanged(text: str, candidate: str) -> bool:
    """True when every label of the candidate is present, in order, dot-separated."""
    labels = [re.escape(label) for label in candidate.split(".") if label]
    if len(labels) < 2:
        return False
    return bool(re.search(_DEFANGED_DOT.join(labels), text, re.IGNORECASE))


def _with_scheme(url: str) -> str:
    """ioc-finder also returns scheme-less URLs; collectors need one."""
    value = str(url or "").strip()
    if not value or "://" in value:
        return value
    return f"http://{value}"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_hash_field(field: str) -> dict[str, str]:
    """
    Digests from one Sysmon-style `Hashes:` field, keyed by algorithm.

    Import hashes (IMPHASH) and other non-file digests are kept — they belong in
    the report as file attributes — but only md5/sha1/sha256 identify the file
    itself, and a digest whose length contradicts its label is dropped rather
    than investigated as something it is not.
    """
    digests: dict[str, str] = {}
    for algo, value in _HASH_PAIR_RE.findall(field or ""):
        name = algo.strip().lower()
        digest = value.strip().lower()
        expected = FILE_HASH_ALGOS.get(name)
        if expected is not None and len(digest) != expected:
            continue
        digests.setdefault(name, digest)
    return digests


def _trim_url(value: str) -> str:
    url = str(value or "").strip()
    while url and url[-1] in _URL_TRAILING_TRIM:
        # Keep a closing bracket that has a matching opener inside the URL.
        if url[-1] == ")" and url.count("(") > url.count(")"):
            break
        if url[-1] == "]" and url.count("[") > url.count("]"):
            break
        url = url[:-1]
    return url


def _url_host(url: str) -> str:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return ""
    return (host or "").strip().strip(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _looks_like_domain(value: str) -> bool:
    raw = str(value or "").strip().strip(".")
    candidate = raw.lower()
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return False
    if _is_ip_literal(candidate):
        return False
    # A stack trace's namespaces outnumber its hostnames, and enough of them end
    # in a real gTLD to pass every check below — `System.Net.Security` was being
    # looked up as `net.security`. Case tells them apart, so this has to run on
    # the value as written, before the lowercasing above is relied on.
    if looks_like_code_identifier(raw):
        return False
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    if any(not label or len(label) > 63 for label in labels):
        return False
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return False
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    if tld in _NON_TLD_SUFFIXES and tld not in _ALWAYS_TLD:
        return False
    # The suffix must be a real one. A blacklist of file extensions can never
    # keep up with what a log line contains — `bootx64.efi`, `snapshot.sh`,
    # `alert.category` all look like domains until you ask the public suffix
    # list, which is the same source the registrable-domain collapse uses.
    return has_public_suffix(candidate)
