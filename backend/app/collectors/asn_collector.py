"""
ASN / Geo Collector — resolves IP to ASN, org, country, hosting type.

Uses ip-api.com (free tier, no key needed for non-commercial use).
Includes CDN and cloud provider detection.
"""

from __future__ import annotations

import json
import logging

import dns.resolver
import requests

from app.collectors.base import BaseCollector
from app.models.schemas import ASNEvidence, CollectorMeta

logger = logging.getLogger(__name__)

CDN_INDICATORS = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
    "sucuri", "stackpath", "cdn77", "keycdn", "bunnycdn",
]

CLOUD_INDICATORS = [
    "amazon", "aws", "google cloud", "microsoft azure", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "oracle cloud",
]


class ASNCollector(BaseCollector):
    name = "asn"
    supported_types = frozenset({"domain", "ip", "url"})

    def _collect(self) -> ASNEvidence:
        from urllib.parse import urlparse

        evidence = ASNEvidence()

        # ── Determine IP based on observable type ──
        if self.observable_type == "ip":
            # Use directly — no DNS resolution needed
            evidence.ip = self.domain
        else:
            # For domain or url: resolve hostname to IP
            hostname = self.domain
            if self.observable_type == "url":
                parsed = urlparse(self.domain)
                hostname = parsed.hostname or self.domain
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                answers = resolver.resolve(hostname, "A")
                if answers:
                    evidence.ip = str(answers[0])
            except Exception as e:
                raise ValueError(f"Cannot resolve {hostname}: {e}")

        if not evidence.ip:
            return evidence

        # ── Query ip-api.com ──
        resp = requests.get(
            f"http://ip-api.com/json/{evidence.ip}",
            params={
                "fields": "status,message,country,city,isp,org,as,reverse,hosting"
            },
            timeout=self.timeout,
        )
        data = resp.json()

        if data.get("status") != "success":
            logger.warning(f"ip-api failed for {evidence.ip}: {data.get('message')}")
            return evidence

        evidence.country = data.get("country")
        evidence.city = data.get("city")
        evidence.asn_org = data.get("org")
        evidence.asn_description = data.get("isp")
        evidence.reverse_dns = data.get("reverse")
        evidence.is_hosting = data.get("hosting")

        # ── Parse ASN number from "AS12345 Org Name" ──
        as_str = data.get("as", "")
        if as_str.startswith("AS"):
            try:
                evidence.asn = int(as_str.split()[0][2:])
            except (ValueError, IndexError):
                pass

        # ── CDN / Cloud detection ──
        org_lower = (evidence.asn_org or "").lower()
        isp_lower = (evidence.asn_description or "").lower()
        combined = org_lower + " " + isp_lower

        evidence.is_cdn = any(c in combined for c in CDN_INDICATORS)
        evidence.is_cloud = any(c in combined for c in CLOUD_INDICATORS)

        # ── Store raw artifact ──
        self._store_artifact("raw_asn", json.dumps(data, default=str))

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> ASNEvidence:
        return ASNEvidence(meta=meta)
