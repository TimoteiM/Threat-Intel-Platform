"""
VirusTotal Collector — queries VT API v3 for domain reputation.

Extracts:
- Vendor detections (malicious/suspicious/clean/undetected counts)
- Individual vendor results (who flagged it and as what)
- Last analysis stats
- Domain categories (from multiple categorization services)
- Popularity ranks (Alexa, Cisco Umbrella, etc.)
- DNS records (from VT's passive DNS)
- WHOIS info (from VT's perspective)
- Community reputation score

Requires: VIRUSTOTAL_API_KEY in .env
Free tier: 4 requests/min, 500/day — we use 1 per investigation.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import CollectorMeta, VTEvidence, VTVendorResult

logger = logging.getLogger(__name__)


class VTCollector(BaseCollector):
    name = "vt"

    def _collect(self) -> VTEvidence:
        settings = get_settings()
        api_key = settings.virustotal_api_key

        if not api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not configured")

        evidence = VTEvidence()

        # ── Query VT API v3 for domain report ──
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{self.domain}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("Domain not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded (4 req/min free tier)")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        evidence.found = True

        # ── Last analysis stats ──
        stats = attrs.get("last_analysis_stats", {})
        evidence.malicious_count = stats.get("malicious", 0)
        evidence.suspicious_count = stats.get("suspicious", 0)
        evidence.harmless_count = stats.get("harmless", 0)
        evidence.undetected_count = stats.get("undetected", 0)
        evidence.total_vendors = sum(stats.values()) if stats else 0

        # ── Individual vendor results ──
        last_analysis = attrs.get("last_analysis_results", {})
        for vendor_name, result in last_analysis.items():
            category = result.get("category", "undetected")
            vr = VTVendorResult(
                vendor=vendor_name,
                category=category,
                result=result.get("result") or category,
                method=result.get("method", ""),
            )
            evidence.vendor_results.append(vr)

            # Track flagging vendors explicitly
            if category == "malicious":
                evidence.flagged_malicious_by.append(vendor_name)
            elif category == "suspicious":
                evidence.flagged_suspicious_by.append(vendor_name)

        # ── Categories (from categorization services) ──
        categories = attrs.get("categories", {})
        evidence.categories = categories

        # ── Popularity ranks ──
        popularity = attrs.get("popularity_ranks", {})
        for service, rank_data in popularity.items():
            if isinstance(rank_data, dict) and "rank" in rank_data:
                evidence.popularity_ranks[service] = rank_data["rank"]

        # ── Reputation score (community) ──
        evidence.reputation_score = attrs.get("reputation", 0)

        # ── Creation / modification dates ──
        if attrs.get("creation_date"):
            evidence.vt_creation_date = datetime.fromtimestamp(
                attrs["creation_date"], tz=timezone.utc
            ).isoformat()
        if attrs.get("last_modification_date"):
            evidence.vt_last_modified = datetime.fromtimestamp(
                attrs["last_modification_date"], tz=timezone.utc
            ).isoformat()
        if attrs.get("last_analysis_date"):
            evidence.last_analysis_date = datetime.fromtimestamp(
                attrs["last_analysis_date"], tz=timezone.utc
            ).isoformat()

        # ── DNS records (from VT passive DNS) ──
        dns_records = attrs.get("last_dns_records", [])
        evidence.vt_dns_records = dns_records

        # ── HTTPS certificate ──
        cert_info = attrs.get("last_https_certificate", {})
        if cert_info:
            subject = cert_info.get("subject", {})
            issuer = cert_info.get("issuer", {})
            evidence.vt_cert_issuer = issuer.get("O", "")
            evidence.vt_cert_subject = subject.get("CN", "")

        # ── Registrar (from VT WHOIS) ──
        evidence.vt_registrar = attrs.get("registrar", "")

        # ── Tags ──
        evidence.tags = attrs.get("tags", [])

        # ── Store raw artifact ──
        self._store_artifact("raw_vt", json.dumps(data, default=str))

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> VTEvidence:
        return VTEvidence(meta=meta)
