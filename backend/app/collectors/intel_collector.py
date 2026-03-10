"""
Intel Collector — reputation lookups and certificate transparency.

Sources:
- crt.sh (Certificate Transparency logs) — free, no key
- DNS-based blocklists (SURBL, Spamhaus DBL) — free DNS queries
- Abuse contact lookup via abuse.ch / URLhaus — free API

Facts only. No interpretation.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timedelta, timezone

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import CollectorMeta, IntelEvidence, IntelHit, CertTimelineEntry, CertTimelineEvidence

logger = logging.getLogger(__name__)

# DNS-based blocklists to check
DNSBL_LISTS = [
    ("multi.surbl.org", "SURBL"),
    ("dbl.spamhaus.org", "Spamhaus DBL"),
    ("black.uribl.com", "URIBL"),
]


class IntelCollector(BaseCollector):
    supported_types = frozenset({"domain", "url"})
    name = "intel"

    def _collect(self) -> IntelEvidence:
        evidence = IntelEvidence()
        # For URL type, all intel queries target the extracted hostname
        target = self.target_domain
        settings = get_settings()
        cached = self._load_cached_intel(target)

        if cached:
            evidence.related_certs = list(cached.get("related_certs") or [])[:50]
            evidence.related_subdomains = list(cached.get("related_subdomains") or [])[:100]
            evidence.cert_entries_raw = list(cached.get("cert_entries_raw") or [])[:200]
            for raw_hit in (cached.get("urlhaus_hits") or []):
                try:
                    evidence.blocklist_hits.append(IntelHit(**raw_hit))
                except Exception:
                    continue
            evidence.notes.append("Reused cached intel (crt.sh + URLhaus)")

        # ── 1. Certificate Transparency via crt.sh ──
        if not cached:
            try:
                certs, subdomains, raw_entries = self._query_crtsh(
                    target,
                    timeout=min(self.timeout, settings.intel_crtsh_timeout_seconds),
                )
                evidence.related_certs = certs[:50]  # Cap at 50
                evidence.related_subdomains = subdomains[:100]
                evidence.cert_entries_raw = raw_entries[:200]  # Store for timeline analysis
            except Exception as e:
                logger.warning(f"crt.sh query failed for {target}: {e}")
                evidence.notes.append(f"crt.sh lookup failed: {e}")

        # ── 2. DNS Blocklist checks ──
        try:
            blocklist_hits = self._check_dns_blocklists(target)
            evidence.blocklist_hits = blocklist_hits
        except Exception as e:
            logger.warning(f"DNSBL check failed for {target}: {e}")
            evidence.notes.append(f"DNSBL check failed: {e}")

        # ── 3. URLhaus lookup ──
        urlhaus_hits: list[IntelHit] = []
        if not cached:
            try:
                urlhaus_hits = self._check_urlhaus(
                    target,
                    timeout=min(self.timeout, settings.intel_urlhaus_timeout_seconds),
                )
                evidence.blocklist_hits.extend(urlhaus_hits)
            except Exception as e:
                logger.warning(f"URLhaus lookup failed for {target}: {e}")
                evidence.notes.append(f"URLhaus lookup failed: {e}")
            self._save_cached_intel(
                target,
                related_certs=evidence.related_certs,
                related_subdomains=evidence.related_subdomains,
                cert_entries_raw=evidence.cert_entries_raw,
                urlhaus_hits=urlhaus_hits,
                ttl_hours=settings.intel_cache_ttl_hours,
            )

        # ── Store artifact ──
        self._store_artifact("raw_intel", json.dumps({
            "certs_count": len(evidence.related_certs),
            "subdomains_count": len(evidence.related_subdomains),
            "blocklist_hits": len(evidence.blocklist_hits),
            "subdomains_sample": evidence.related_subdomains[:20],
        }, default=str))

        return evidence

    def _query_crtsh(self, target: str, *, timeout: int) -> tuple[list[str], list[str], list[dict]]:
        """
        Query crt.sh Certificate Transparency logs.
        Returns (cert_identities, unique_subdomains, raw_entries).
        """
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "ThreatInvestigator/1.0"},
        )

        if resp.status_code != 200:
            return [], [], []

        entries = resp.json()
        if not isinstance(entries, list):
            return [], [], []

        certs = []
        subdomains_set = set()
        raw_entries: list[dict] = []
        seen_serials: set[str] = set()

        for entry in entries:
            name_value = entry.get("name_value", "")
            serial = entry.get("serial_number", "")

            if serial and serial not in seen_serials:
                seen_serials.add(serial)
                certs.append(serial)
                # Store full cert detail for timeline analysis
                raw_entries.append({
                    "serial_number": serial,
                    "issuer_name": entry.get("issuer_name", ""),
                    "common_name": entry.get("common_name", name_value.split("\n")[0].strip()),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "entry_timestamp": entry.get("entry_timestamp", ""),
                    "name_value": name_value,
                })

            # Extract subdomains from SAN name_value
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and (name.endswith(f".{target}") or name == target):
                    subdomains_set.add(name)

        subdomains = sorted(subdomains_set)
        return certs, subdomains, raw_entries

    def _check_dns_blocklists(self, target: str) -> list[IntelHit]:
        """
        Check domain against DNS-based blocklists.
        A positive result (DNS resolves) means the domain is listed.
        """
        hits = []

        for dnsbl_zone, source_name in DNSBL_LISTS:
            query = f"{target}.{dnsbl_zone}"
            try:
                answers = socket.getaddrinfo(query, None, socket.AF_INET)
                if answers:
                    # Domain is listed in this blocklist
                    result_ip = answers[0][4][0]
                    hits.append(IntelHit(
                        source=source_name,
                        indicator=target,
                        category="blocklist",
                        severity="high",
                        details=f"Listed in {source_name} (response: {result_ip})",
                    ))
            except socket.gaierror:
                # NXDOMAIN = not listed (good)
                pass
            except Exception as e:
                logger.debug(f"DNSBL {source_name} check error: {e}")

        return hits

    def _check_urlhaus(self, target: str, *, timeout: int) -> list[IntelHit]:
        """
        Check domain against abuse.ch URLhaus.
        Free API, no key needed.
        """
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=timeout,
        )

        if resp.status_code != 200:
            return []

        data = resp.json()

        if data.get("query_status") != "no_results" and data.get("urlhaus_reference"):
            hits = []

            # Main domain hit
            url_count = data.get("url_count", 0)
            if url_count and int(url_count) > 0:
                hits.append(IntelHit(
                    source="URLhaus (abuse.ch)",
                    indicator=target,
                    category="malware_distribution",
                    severity="high",
                    details=f"URLhaus: {url_count} malicious URLs associated",
                    last_seen=self._parse_urlhaus_date(
                        data.get("urls", [{}])[0].get("date_added") if data.get("urls") else None
                    ),
                ))

            # Individual URL entries (cap at 10)
            for url_entry in (data.get("urls") or [])[:10]:
                threat = url_entry.get("threat", "unknown")
                url = url_entry.get("url", "")
                status = url_entry.get("url_status", "")
                hits.append(IntelHit(
                    source="URLhaus",
                    indicator=url,
                    category=threat,
                    severity="high" if status == "online" else "medium",
                    details=f"Threat: {threat}, Status: {status}",
                    last_seen=self._parse_urlhaus_date(url_entry.get("date_added")),
                ))

            return hits

        return []

    @staticmethod
    def _parse_urlhaus_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return None

    def _load_cached_intel(self, target: str) -> dict | None:
        key = f"intel:{target.lower()}"
        try:
            from sqlalchemy import select
            from sqlalchemy.orm import Session
            from app.db.session import sync_engine
            from app.models.database import LookupCache

            with Session(sync_engine) as session:
                row = session.execute(
                    select(LookupCache).where(
                        LookupCache.cache_key == key,
                        LookupCache.expires_at > datetime.now(timezone.utc),
                    )
                ).scalar_one_or_none()
                if row and isinstance(row.cache_value, dict):
                    return row.cache_value
        except Exception as e:
            logger.debug("Intel cache lookup failed for %s: %s", target, e)
        return None

    def _save_cached_intel(
        self,
        target: str,
        *,
        related_certs: list[str],
        related_subdomains: list[str],
        cert_entries_raw: list[dict],
        urlhaus_hits: list[IntelHit],
        ttl_hours: int,
    ) -> None:
        key = f"intel:{target.lower()}"
        payload = {
            "related_certs": list(related_certs or [])[:50],
            "related_subdomains": list(related_subdomains or [])[:100],
            "cert_entries_raw": list(cert_entries_raw or [])[:200],
            "urlhaus_hits": [h.model_dump(mode="json") for h in (urlhaus_hits or [])[:20]],
        }
        expires_at = datetime.now(timezone.utc) + timedelta(hours=max(1, int(ttl_hours or 24)))
        try:
            from sqlalchemy import select
            from sqlalchemy.orm import Session
            from app.db.session import sync_engine
            from app.models.database import LookupCache

            with Session(sync_engine) as session:
                row = session.execute(
                    select(LookupCache).where(LookupCache.cache_key == key)
                ).scalar_one_or_none()
                if row:
                    row.cache_value = payload
                    row.expires_at = expires_at
                    row.source = "intel"
                else:
                    session.add(
                        LookupCache(
                            cache_key=key,
                            cache_value=payload,
                            source="intel",
                            expires_at=expires_at,
                        )
                    )
                session.commit()
        except Exception as e:
            logger.debug("Intel cache save failed for %s: %s", target, e)

    def _empty_evidence(self, meta: CollectorMeta) -> IntelEvidence:
        return IntelEvidence(meta=meta)


def build_cert_timeline(evidence_data: dict, domain: str) -> dict | None:
    """
    Build a certificate transparency timeline from raw crt.sh entries
    stored in the Intel collector's evidence.

    Called from analysis_task.py as a post-processing step.
    Returns a serialized CertTimelineEvidence dict, or None if no data.
    """
    intel = evidence_data.get("intel", {})
    raw_entries = intel.get("cert_entries_raw", [])
    if not raw_entries:
        return None

    SHORT_LIVED_DAYS = 30
    BURST_WINDOW_DAYS = 7
    BURST_THRESHOLD = 5

    entries: list[CertTimelineEntry] = []
    parse_errors = 0

    for raw in raw_entries:
        not_before_str = raw.get("not_before", "")
        not_after_str = raw.get("not_after", "")

        try:
            # crt.sh timestamps can be "2024-01-01T12:00:00" or "2024-01-01 12:00:00"
            not_before_dt = _parse_crtsh_dt(not_before_str)
            not_after_dt = _parse_crtsh_dt(not_after_str)

            if not_before_dt and not_after_dt:
                validity_days = (not_after_dt - not_before_dt).days
            else:
                validity_days = 0

            entries.append(CertTimelineEntry(
                serial_number=raw.get("serial_number", ""),
                issuer_name=_shorten_issuer(raw.get("issuer_name", "")),
                common_name=raw.get("common_name", domain),
                not_before=not_before_str,
                not_after=not_after_str,
                entry_timestamp=raw.get("entry_timestamp", not_before_str),
                validity_days=validity_days,
                is_short_lived=0 < validity_days < SHORT_LIVED_DAYS,
            ))
        except Exception:
            parse_errors += 1
            continue

    if not entries:
        return None

    # Sort by entry_timestamp descending (newest first)
    entries.sort(key=lambda e: e.entry_timestamp, reverse=True)

    unique_issuers = list(dict.fromkeys(e.issuer_name for e in entries if e.issuer_name))
    short_lived_count = sum(1 for e in entries if e.is_short_lived)

    # Detect burst periods: 5+ certs issued within any 7-day window
    burst_periods: list[dict] = []
    cert_burst_detected = False

    timestamps_sorted = sorted(
        [_parse_crtsh_dt(e.entry_timestamp or e.not_before) for e in entries if e.entry_timestamp or e.not_before],
        key=lambda dt: dt or datetime.min.replace(tzinfo=timezone.utc),
    )
    timestamps_sorted = [t for t in timestamps_sorted if t is not None]

    for ts in timestamps_sorted:
        window_end = ts + timedelta(days=BURST_WINDOW_DAYS)
        window_certs = [t for t in timestamps_sorted if ts <= t <= window_end]
        if len(window_certs) >= BURST_THRESHOLD:
            burst_cert_detected_already = any(
                bp["start"] == ts.isoformat() for bp in burst_periods
            )
            if not burst_cert_detected_already:
                burst_periods.append({
                    "start": ts.isoformat(),
                    "end": window_end.isoformat(),
                    "count": len(window_certs),
                })
                cert_burst_detected = True

    notes: list[str] = []
    if parse_errors:
        notes.append(f"{parse_errors} cert entries could not be parsed")
    if short_lived_count > 0:
        notes.append(f"{short_lived_count} certificate(s) had validity < {SHORT_LIVED_DAYS} days (short-lived)")
    if cert_burst_detected:
        notes.append(f"Certificate burst detected: multiple issuances within {BURST_WINDOW_DAYS}-day window(s)")

    earliest = entries[-1].not_before if entries else None
    latest = entries[0].not_before if entries else None

    return CertTimelineEvidence(
        domain=domain,
        total_certs=len(entries),
        entries=entries[:100],  # Cap at 100 for storage
        unique_issuers=unique_issuers,
        cert_burst_detected=cert_burst_detected,
        burst_periods=burst_periods[:10],
        short_lived_count=short_lived_count,
        earliest_cert=earliest,
        latest_cert=latest,
        notes=notes,
    ).model_dump()


def _parse_crtsh_dt(dt_str: str | None) -> datetime | None:
    """Parse crt.sh datetime strings in multiple formats."""
    if not dt_str:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str[:19], fmt[:len(fmt)]).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _shorten_issuer(issuer_dn: str) -> str:
    """Extract CN or O from issuer Distinguished Name for display."""
    if not issuer_dn:
        return ""
    # Try to extract CN=... first, then O=...
    for prefix in ("CN=", "O="):
        idx = issuer_dn.find(prefix)
        if idx != -1:
            value = issuer_dn[idx + len(prefix):]
            end = value.find(",")
            return value[:end].strip() if end != -1 else value.strip()
    return issuer_dn[:60]
