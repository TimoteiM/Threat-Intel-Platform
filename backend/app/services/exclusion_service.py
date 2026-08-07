"""
The exclusion list — indicators answered from policy instead of from collectors.

A SOC's own estate dominates its alert volume: the corporate domains, the office
egress ranges, the hashes of software it deploys on purpose. Every one of those
costs a full collector round trip to conclude what the analyst already knew, and
VirusTotal's four-a-minute quota is spent on them before it reaches the indicator
that actually matters.

An exclusion answers once and for all. A matching indicator is reported benign,
attributed to the exclusion row that decided it, and never sent to a collector,
an investigation or the AI analyst.

Matching is deliberately narrow — an entry only ever matches what it says:

    domain   exact, plus subdomains unless match_subdomains is off. A URL is
             matched on its host too, so excluding a domain covers its links.
    ip       exact, or every address in a CIDR (10.0.0.0/8 covers the estate)
    url      exact, after normalising scheme case and the trailing slash
    hash     exact, case-insensitive

Two safety properties are deliberate. `reason` is mandatory, because an
unexplained whitelist entry is how a real detection gets silenced for a year.
And `expires_at` lets an exclusion added during an incident lapse on its own
rather than depending on somebody remembering to remove it.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import Exclusion
from app.utils.domain_utils import normalize_domain, validate_domain

logger = logging.getLogger(__name__)

INDICATOR_TYPES = ("domain", "ip", "url", "hash")

# Indicator kinds the extractor emits, mapped to the exclusion type that governs
# them. Anything absent here is never excluded.
_KIND_TO_TYPE = {"domain": "domain", "ip": "ip", "url": "url", "hash": "hash"}

_HASH_PATTERN = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")

# Refuse to whitelist the entire internet by accident.
_FORBIDDEN_CIDR_PREFIX = {4: 8, 6: 32}


class ExclusionError(ValueError):
    """The submitted exclusion is not one we will store."""


# ── Normalisation ─────────────────────────────────────────────────────────────


def normalize_exclusion(indicator_type: str, value: str) -> tuple[str, str]:
    """
    Validate one entry and return `(indicator_type, normalized_value)`.

    Raises ExclusionError with a message meant for the analyst who typed it.
    """
    kind = str(indicator_type or "").strip().lower()
    raw = str(value or "").strip()
    if kind not in INDICATOR_TYPES:
        raise ExclusionError(f"indicator_type must be one of {', '.join(INDICATOR_TYPES)}")
    if not raw:
        raise ExclusionError("value is required")

    if kind == "hash":
        normalized = raw.lower()
        if not _HASH_PATTERN.match(normalized):
            raise ExclusionError("value must be an MD5, SHA-1 or SHA-256 hex digest")
        return kind, normalized

    if kind == "ip":
        return kind, _normalize_ip(raw)

    if kind == "url":
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        if not parsed.hostname:
            raise ExclusionError("value must be a URL with a host")
        path = parsed.path.rstrip("/")
        return kind, f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{path}"

    domain = normalize_domain(raw).rstrip(".")
    if not validate_domain(domain):
        raise ExclusionError(f"'{raw}' is not a valid domain")
    return kind, domain


def _normalize_ip(raw: str) -> str:
    """An address or a network, rejected if it would whitelist half the internet."""
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ExclusionError(f"'{raw}' is not a valid IP network") from exc
        if network.prefixlen < _FORBIDDEN_CIDR_PREFIX[network.version]:
            raise ExclusionError(
                f"/{network.prefixlen} is too broad to exclude — "
                f"use /{_FORBIDDEN_CIDR_PREFIX[network.version]} or narrower"
            )
        return str(network)
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ExclusionError(f"'{raw}' is not a valid IP address or CIDR range") from exc


# ── Matching ──────────────────────────────────────────────────────────────────


class ExclusionMatcher:
    """
    The active exclusion list, indexed for the one question the pipeline asks.

    Built once per alert run and consulted per indicator, so matching is dict
    lookups and a walk of the (small) CIDR list rather than a query per value.
    """

    def __init__(self, rows: Sequence[Exclusion] | Sequence[dict[str, Any]] = ()):
        self._domains: dict[str, dict[str, Any]] = {}
        self._domain_suffixes: dict[str, dict[str, Any]] = {}
        self._ips: dict[str, dict[str, Any]] = {}
        self._networks: list[tuple[Any, dict[str, Any]]] = []
        self._urls: dict[str, dict[str, Any]] = {}
        self._hashes: dict[str, dict[str, Any]] = {}

        for row in rows:
            entry = _as_dict(row)
            kind = str(entry.get("indicator_type") or "")
            value = str(entry.get("normalized_value") or "")
            if not value:
                continue
            if kind == "domain":
                self._domains[value] = entry
                if entry.get("match_subdomains", True):
                    self._domain_suffixes[f".{value}"] = entry
            elif kind == "ip":
                if "/" in value:
                    try:
                        self._networks.append((ipaddress.ip_network(value, strict=False), entry))
                    except ValueError:
                        continue
                else:
                    self._ips[value] = entry
            elif kind == "url":
                self._urls[value] = entry
            elif kind == "hash":
                self._hashes[value] = entry

    def __bool__(self) -> bool:
        return bool(
            self._domains or self._ips or self._networks or self._urls or self._hashes
        )

    def __len__(self) -> int:
        return len(self._domains) + len(self._ips) + len(self._networks) + len(self._urls) + len(self._hashes)

    def match(self, indicator_type: str, value: str) -> dict[str, Any] | None:
        """The exclusion covering this indicator, or None."""
        kind = _KIND_TO_TYPE.get(str(indicator_type or "").strip().lower())
        raw = str(value or "").strip()
        if not kind or not raw:
            return None
        if kind == "hash":
            return self._hashes.get(raw.lower())
        if kind == "ip":
            return self._match_ip(raw)
        if kind == "domain":
            return self._match_domain(raw)
        return self._match_url(raw)

    # ── Internals ──

    def _match_domain(self, raw: str) -> dict[str, Any] | None:
        domain = normalize_domain(raw).rstrip(".")
        if not domain:
            return None
        hit = self._domains.get(domain)
        if hit is not None:
            return hit
        # mail.corp.example matches an entry for corp.example or example.
        for index, char in enumerate(domain):
            if char == ".":
                suffix = domain[index:]
                hit = self._domain_suffixes.get(suffix)
                if hit is not None:
                    return hit
        return None

    def _match_ip(self, raw: str) -> dict[str, Any] | None:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return None
        hit = self._ips.get(str(address))
        if hit is not None:
            return hit
        for network, entry in self._networks:
            if address.version == network.version and address in network:
                return entry
        return None

    def _match_url(self, raw: str) -> dict[str, Any] | None:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = parsed.hostname or ""
        path = parsed.path.rstrip("/")
        hit = self._urls.get(f"{parsed.scheme.lower()}://{host.lower()}{path}")
        if hit is not None:
            return hit
        # An excluded domain covers the links pointing at it.
        return self._match_domain(host) if host else None


def _as_dict(row: Exclusion | dict[str, Any]) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    return {
        "id": str(row.id),
        "indicator_type": row.indicator_type,
        "value": row.value,
        "normalized_value": row.normalized_value,
        "reason": row.reason,
        "added_by": row.added_by,
        "match_subdomains": row.match_subdomains,
    }


# ── Loading ───────────────────────────────────────────────────────────────────


def _statement():
    now = datetime.now(timezone.utc)
    return select(Exclusion).where(
        Exclusion.active.is_(True),
        (Exclusion.expires_at.is_(None)) | (Exclusion.expires_at > now),
    )


async def load_matcher(db: AsyncSession) -> ExclusionMatcher:
    """Active exclusions, for the FastAPI request path. Never raises."""
    try:
        result = await db.execute(_statement())
        return ExclusionMatcher(result.scalars().all())
    except Exception as exc:
        # An unavailable exclusion list must not stop an alert being investigated
        # — the cost of that is quota, the cost of a failed ingest is a missed alert.
        logger.warning("Exclusion lookup failed, treating the list as empty: %s", exc)
        return ExclusionMatcher()


def load_matcher_sync() -> ExclusionMatcher:
    """Blocking variant for Celery workers. Never raises."""
    try:
        with Session(sync_engine) as db:
            return ExclusionMatcher(db.execute(_statement()).scalars().all())
    except Exception as exc:
        logger.warning("Exclusion lookup failed, treating the list as empty: %s", exc)
        return ExclusionMatcher()


# ── Applying ──────────────────────────────────────────────────────────────────


def apply_to_indicators(
    indicators: Iterable[dict[str, Any]],
    matcher: ExclusionMatcher,
) -> int:
    """
    Mark every excluded indicator in place; return how many matched.

    An excluded indicator stops being investigable — that is what saves the
    quota — but stays in the list carrying the row that excluded it, so the
    report shows what was skipped and why rather than quietly losing it.
    """
    if not matcher:
        return 0
    matched = 0
    for indicator in indicators or []:
        if not indicator.get("investigable"):
            continue
        hit = matcher.match(str(indicator.get("type") or ""), str(indicator.get("value") or ""))
        if hit is None:
            continue
        indicator["investigable"] = False
        indicator["skip_reason"] = "excluded"
        indicator["exclusion"] = {
            "id": hit.get("id"),
            "matched": hit.get("value"),
            "indicator_type": hit.get("indicator_type"),
            "reason": hit.get("reason"),
            "added_by": hit.get("added_by"),
        }
        matched += 1
    return matched


def record_hits_sync(exclusion_ids: Iterable[str]) -> None:
    """
    Count what the list actually saved, best-effort.

    Without this an exclusion added for one incident three years ago is
    indistinguishable from one carrying the estate — `hit_count` is what tells
    an analyst which rows are still earning their place.
    """
    ids = [str(value) for value in exclusion_ids if value]
    if not ids:
        return
    now = datetime.now(timezone.utc)
    try:
        with Session(sync_engine) as db:
            rows = db.execute(select(Exclusion).where(Exclusion.id.in_(ids))).scalars().all()
            for row in rows:
                row.hit_count = int(row.hit_count or 0) + 1
                row.last_hit_at = now
            db.commit()
    except Exception as exc:
        logger.warning("Could not record exclusion hits: %s", exc)
