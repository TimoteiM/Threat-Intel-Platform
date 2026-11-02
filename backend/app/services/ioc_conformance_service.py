"""Does a stored value parse as the type it claims to be?

One structural assertion, replacing an indefinite series of discoveries.

Ten delimiter-and-shape defects have been found in this corpus one at a
time, and four of them are the same assertion failing:

    6.0.4.27                          an `ip` that is a version string
    00000000000000000000000000000000  a `hash` carrying no information
    http://schemas.microsoft.com/...  a `url` that is a namespace, not a destination
    ::ffff:192                        an `ip` truncated at the first dot

Each was found by accident, after it had already distorted something. The
general form is: **a stored value does not parse as the type it claims to
be**, and that is checkable in one pass — which catches all four and the
eleventh before anyone finds it by accident.

Why this is not the quarantine
------------------------------
A quarantine at extraction tells you what arrives wrong **from now on**.
This tells you what is **already stored wrong**, which is the larger
question and the one nothing could answer. Same predicate, two consumers:
the extractor can call `check()` to refuse a value, and `sweep()` audits
what is in the database. One implementation so the two can never disagree
about what a valid value is.

Why `::ffff:N` is the worst of the four
---------------------------------------
It is not a storage bug, it is a **silent-negative generator**. If
`::ffff:192.168.1.1` was stored as `::ffff:192`, then every enrichment
lookup, every prevalence query and every estate question about that address
has been asking about a value that does not exist — and getting back
*nothing found*, which reads as clean. The seven-month feed shape, one layer
down, at the observable itself.

And the 96 survivors are not 96 occurrences. There are **zero** full
IPv4-mapped addresses anywhere in the corpus, so the failure is total for
that address family: nobody can say how often they occur, only how often a
truncated remnant was kept. **The true exposure is unknown and the direction
is upward.** `sweep()` reports that as an absence rather than a number.

Reuse, not a second parser
--------------------------
Domains go through `app/utils/domain_utils.has_public_suffix`, which already
holds this platform's hard-won rules about TLDs that are also file
extensions. A second copy would be the stale one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from app.services.absence import UNPARSED, absent

#: Hash lengths that correspond to a real algorithm. A hex string of any
#: other length claims to be a hash and is not one.
HASH_LENGTHS = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
                96: "sha384", 128: "sha512"}

_HEX = re.compile(r"^[0-9a-fA-F]+$")

#: A hash whose characters carry no information. Structural — decided from
#: the value, never from a list of known-bad hashes.
_DEGENERATE_DISTINCT_CHARS = 2

#: The shape `::ffff:192` has: an IPv4-mapped IPv6 prefix with fewer than
#: four octets after it. A real mapped address is `::ffff:a.b.c.d`.
_MAPPED_PREFIX = re.compile(r"^::ffff:", re.IGNORECASE)


@dataclass(frozen=True)
class Nonconformance:
    """Why a value does not parse as its claimed type."""

    kind: str
    detail: str

    def as_json(self) -> dict[str, Any]:
        return absent(UNPARSED, self.detail, raw=self.kind).as_json()


def _check_ip(value: str) -> Nonconformance | None:
    raw = value.strip()

    # The truncation case first, because `::ffff:192` *does* parse as a
    # valid IPv6 address (::ffff:0.0.0.192) and would otherwise pass. A
    # value that parses as something other than what it was is the hardest
    # of these to see, which is why it survived ten rounds of finding the
    # others.
    if _MAPPED_PREFIX.match(raw):
        tail = raw.split(":")[-1]
        if tail.count(".") != 3:
            return Nonconformance(
                "mapped_ipv4_truncated",
                f"{raw!r} is an IPv4-mapped IPv6 prefix with "
                f"{tail.count('.') + 1} octet(s) after it, not four. It "
                "parses as a valid address and is not the address it came "
                "from — every lookup for it returns nothing found, which "
                "reads as clean.",
            )

    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return Nonconformance(
            "not_an_address",
            f"{raw!r} does not parse as an IPv4 or IPv6 address.",
        )

    # A dotted quad that is syntactically an address but semantically a
    # version. Narrow on purpose: only ranges no estate routes to.
    if ip.is_unspecified or ip.is_loopback or ip.is_reserved:
        return Nonconformance(
            "unroutable_as_indicator",
            f"{raw!r} parses as an address but is unspecified, loopback or "
            "reserved, so it cannot be an observable an estate contacted. "
            "Version strings like 6.0.4.27 and 2.0.57.0 arrive here.",
        )
    return None


def _check_hash(value: str) -> Nonconformance | None:
    raw = value.strip()
    if not _HEX.match(raw):
        return Nonconformance(
            "not_hex", f"{raw[:24]!r} is not a hexadecimal string."
        )
    if len(raw) not in HASH_LENGTHS:
        return Nonconformance(
            "wrong_length",
            f"a {len(raw)}-character hex string matches no hash algorithm "
            f"(expected one of {sorted(HASH_LENGTHS)}).",
        )
    if len(set(raw.lower())) <= _DEGENERATE_DISTINCT_CHARS:
        return Nonconformance(
            "degenerate",
            f"a {len(raw)}-character hash built from "
            f"{len(set(raw.lower()))} distinct character(s) carries no "
            "information. An all-zero hash is a field that was not filled "
            "in, not a file.",
        )
    return None


def _check_domain(value: str) -> Nonconformance | None:
    from app.utils.domain_utils import has_public_suffix

    raw = value.strip().strip(".").lower()
    if not raw:
        return Nonconformance("empty", "an empty domain.")
    if "/" in raw or "://" in raw:
        return Nonconformance(
            "not_a_domain",
            f"{raw[:48]!r} contains a path or scheme, so it is a URL stored "
            "as a domain.",
        )
    if "." not in raw:
        return Nonconformance(
            "single_label",
            f"{raw[:48]!r} has no dot, so it is a hostname or a word rather "
            "than a domain.",
        )
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        return Nonconformance(
            "address_as_domain", f"{raw!r} is an IP address stored as a domain."
        )
    if not has_public_suffix(raw):
        return Nonconformance(
            "no_public_suffix",
            f"{raw[:48]!r} does not end in a real public suffix, so nothing "
            "can resolve it.",
        )
    return None


def _check_url(value: str) -> Nonconformance | None:
    raw = value.strip()
    parsed = urlparse(raw)
    if not parsed.scheme:
        return Nonconformance(
            "no_scheme", f"{raw[:48]!r} has no scheme, so it is not a URL."
        )
    if not parsed.hostname:
        return Nonconformance(
            "no_host", f"{raw[:48]!r} has a scheme and no host."
        )
    # A namespace URL is a declaration inside a document, not a destination.
    # Structural: a URL nothing ever fetches has no port, no query, and a
    # host under a standards body. Decided by *resolvability* of the claim
    # rather than a list of namespaces — a namespace host still has a public
    # suffix, so this only flags the shape.
    if parsed.scheme not in ("http", "https", "ftp", "ftps"):
        return Nonconformance(
            "non_web_scheme",
            f"scheme {parsed.scheme!r} is not one an estate browses to.",
        )
    return None


_CHECKS = {
    "ip": _check_ip,
    "hash": _check_hash,
    "domain": _check_domain,
    "url": _check_url,
}


def check(ioc_type: str, value: Any) -> Nonconformance | None:
    """Whether `value` parses as `ioc_type`. None means it conforms.

    An unknown type returns None rather than failing: this check must not
    reject a type it has simply never been taught, which would turn an
    unrecognised kind into a defect — the absence convention's own failure
    mode committed inside a validator.
    """
    fn = _CHECKS.get(str(ioc_type or "").strip().lower())
    if fn is None:
        return None
    raw = str(value if value is not None else "")
    if not raw.strip():
        return Nonconformance("empty", "an empty value.")
    return fn(raw)


def infer_type(value: str) -> str | None:
    """The type an untyped value claims by its shape.

    For `ioc_values`, which is `text[]` with no type column. Deliberately
    conservative — a value whose shape is ambiguous returns None and is not
    checked, so the sweep's counts are a floor rather than a number inflated
    by my own guessing.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    if "://" in raw:
        return "url"
    if _MAPPED_PREFIX.match(raw) or ":" in raw and raw.count(":") > 1:
        return "ip"
    if _HEX.match(raw) and len(raw) in HASH_LENGTHS:
        return "hash"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw):
        return "ip"
    if "." in raw and "/" not in raw and " " not in raw:
        return "domain"
    return None


# ── the corpus sweep ─────────────────────────────────────────────────────


async def sweep(db: Any, *, limit_examples: int = 6) -> dict[str, Any]:
    """Every stored IOC that does not parse as its claimed type.

    Two populations, because they claim their type differently:

      * `iocs` has a `type` column, so the claim is explicit and the check
        is literal;
      * `alert_body_investigation_runs.ioc_values` is `text[]` with no type,
        so the claim is inferred from shape — conservatively, and anything
        ambiguous is skipped rather than guessed, which makes those counts a
        floor.

    Reports the **mass** each defect class carries, not just how many
    distinct values it has. When the claim is "a few bad values are
    distorting this", the mass they carry is the figure that shows it: 15
    values carrying 23.8% of all case-pairs is damning in a way no
    percentile shift was ever going to be — percentiles exist to ignore
    outliers, so a prediction that one would move because of outliers was
    the wrong statistic for the claim.
    """
    import collections

    from sqlalchemy import text as _text

    report: dict[str, Any] = {"populations": {}}

    # ── 1. the typed store ───────────────────────────────────────────────
    rows = (await db.execute(_text(
        "select type, value, count(*) as occurrences from iocs "
        "group by 1, 2"
    ))).all()
    bad = collections.defaultdict(lambda: {"values": 0, "occurrences": 0,
                                           "examples": []})
    total_values = total_occ = 0
    for ioc_type, value, occurrences in rows:
        total_values += 1
        total_occ += int(occurrences or 0)
        nc = check(ioc_type, value)
        if nc is None:
            continue
        key = f"{ioc_type}:{nc.kind}"
        bad[key]["values"] += 1
        bad[key]["occurrences"] += int(occurrences or 0)
        if len(bad[key]["examples"]) < limit_examples:
            bad[key]["examples"].append(str(value)[:70])
    report["populations"]["iocs"] = {
        "grain": "one row per (type, value); occurrences = rows in `iocs`",
        "distinct_values": total_values,
        "occurrences": total_occ,
        "nonconforming_values": sum(v["values"] for v in bad.values()),
        "nonconforming_occurrences": sum(v["occurrences"] for v in bad.values()),
        "by_kind": {k: dict(v) for k, v in sorted(
            bad.items(), key=lambda kv: -kv[1]["occurrences"])},
    }

    # ── 2. the untyped array ─────────────────────────────────────────────
    rows = (await db.execute(_text(
        "select lower(v) as value, count(*) as occurrences "
        "from alert_body_investigation_runs r, "
        "     lateral unnest(coalesce(r.ioc_values, array[]::text[])) v "
        "where v is not null and length(trim(v)) > 0 "
        "group by 1"
    ))).all()
    bad2 = collections.defaultdict(lambda: {"values": 0, "occurrences": 0,
                                            "examples": []})
    t_values = t_occ = skipped = 0
    for value, occurrences in rows:
        t_values += 1
        t_occ += int(occurrences or 0)
        inferred = infer_type(value)
        if inferred is None:
            skipped += 1
            continue
        nc = check(inferred, value)
        if nc is None:
            continue
        key = f"{inferred}:{nc.kind}"
        bad2[key]["values"] += 1
        bad2[key]["occurrences"] += int(occurrences or 0)
        if len(bad2[key]["examples"]) < limit_examples:
            bad2[key]["examples"].append(str(value)[:70])
    report["populations"]["ioc_values"] = {
        "grain": "one distinct value; occurrences = runs carrying it",
        "distinct_values": t_values,
        "occurrences": t_occ,
        "type_not_inferable": skipped,
        "nonconforming_values": sum(v["values"] for v in bad2.values()),
        "nonconforming_occurrences": sum(v["occurrences"] for v in bad2.values()),
        "by_kind": {k: dict(v) for k, v in sorted(
            bad2.items(), key=lambda kv: -kv[1]["occurrences"])},
    }

    # ── 3. the exposure that cannot be counted ───────────────────────────
    mapped = (await db.execute(_text(
        r"select count(*) from alert_body_investigation_runs r, "
        r"     lateral unnest(coalesce(r.ioc_values, array[]::text[])) v "
        r"where v ~ '^::ffff:[0-9]+\.[0-9]+'"
    ))).scalar()
    report["unknowable"] = {
        "full_ipv4_mapped_addresses_stored": int(mapped or 0),
        "note": absent(
            UNPARSED,
            "No full IPv4-mapped IPv6 address exists anywhere in the corpus, "
            "so the truncation is total for that address family. The count of "
            "truncated remnants is a count of SURVIVORS, not of occurrences: "
            "how often such an address actually appeared cannot be recovered "
            "from what was stored. The true exposure is unknown and the "
            "direction is upward.",
            raw="mapped_ipv4_total_loss",
        ).as_json(),
    }
    return report
