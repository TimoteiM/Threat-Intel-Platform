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
from datetime import datetime, timezone

import requests

from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta, IntelEvidence, IntelHit

logger = logging.getLogger(__name__)

# DNS-based blocklists to check
DNSBL_LISTS = [
    ("multi.surbl.org", "SURBL"),
    ("dbl.spamhaus.org", "Spamhaus DBL"),
    ("black.uribl.com", "URIBL"),
]


class IntelCollector(BaseCollector):
    name = "intel"

    def _collect(self) -> IntelEvidence:
        evidence = IntelEvidence()

        # ── 1. Certificate Transparency via crt.sh ──
        try:
            certs, subdomains = self._query_crtsh()
            evidence.related_certs = certs[:50]  # Cap at 50
            evidence.related_subdomains = subdomains[:100]
        except Exception as e:
            logger.warning(f"crt.sh query failed for {self.domain}: {e}")
            evidence.notes.append(f"crt.sh lookup failed: {e}")

        # ── 2. DNS Blocklist checks ──
        try:
            blocklist_hits = self._check_dns_blocklists()
            evidence.blocklist_hits = blocklist_hits
        except Exception as e:
            logger.warning(f"DNSBL check failed for {self.domain}: {e}")
            evidence.notes.append(f"DNSBL check failed: {e}")

        # ── 3. URLhaus lookup ──
        try:
            urlhaus_hits = self._check_urlhaus()
            evidence.blocklist_hits.extend(urlhaus_hits)
        except Exception as e:
            logger.warning(f"URLhaus lookup failed for {self.domain}: {e}")
            evidence.notes.append(f"URLhaus lookup failed: {e}")

        # ── Store artifact ──
        self._store_artifact("raw_intel", json.dumps({
            "certs_count": len(evidence.related_certs),
            "subdomains_count": len(evidence.related_subdomains),
            "blocklist_hits": len(evidence.blocklist_hits),
            "subdomains_sample": evidence.related_subdomains[:20],
        }, default=str))

        return evidence

    def _query_crtsh(self) -> tuple[list[str], list[str]]:
        """
        Query crt.sh Certificate Transparency logs.
        Returns (cert_identities, unique_subdomains).
        """
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{self.domain}", "output": "json"},
            timeout=self.timeout,
            headers={"User-Agent": "ThreatInvestigator/1.0"},
        )

        if resp.status_code != 200:
            return [], []

        entries = resp.json()
        if not isinstance(entries, list):
            return [], []

        certs = []
        subdomains_set = set()

        for entry in entries:
            # Collect cert identifiers
            name_value = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            not_before = entry.get("not_before", "")
            serial = entry.get("serial_number", "")

            if serial and serial not in certs:
                certs.append(serial)

            # Extract subdomains from SAN name_value
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name.endswith(f".{self.domain}") or name == self.domain:
                    subdomains_set.add(name)

        subdomains = sorted(subdomains_set)
        return certs, subdomains

    def _check_dns_blocklists(self) -> list[IntelHit]:
        """
        Check domain against DNS-based blocklists.
        A positive result (DNS resolves) means the domain is listed.
        """
        hits = []

        for dnsbl_zone, source_name in DNSBL_LISTS:
            query = f"{self.domain}.{dnsbl_zone}"
            try:
                answers = socket.getaddrinfo(query, None, socket.AF_INET)
                if answers:
                    # Domain is listed in this blocklist
                    result_ip = answers[0][4][0]
                    hits.append(IntelHit(
                        source=source_name,
                        indicator=self.domain,
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

    def _check_urlhaus(self) -> list[IntelHit]:
        """
        Check domain against abuse.ch URLhaus.
        Free API, no key needed.
        """
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": self.domain},
            timeout=self.timeout,
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
                    indicator=self.domain,
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

    def _empty_evidence(self, meta: CollectorMeta) -> IntelEvidence:
        return IntelEvidence(meta=meta)
