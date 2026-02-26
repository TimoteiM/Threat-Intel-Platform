"""
VirusTotal Collector — queries VT API v3 for multi-observable reputation.

Supports: domain, IP, URL, file hash, file sample.

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

import base64
import json
import logging
import time
from datetime import datetime, timezone

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import CollectorMeta, VTEvidence, VTVendorResult

logger = logging.getLogger(__name__)


class VTCollector(BaseCollector):
    name = "vt"
    supported_types = frozenset({"domain", "ip", "url", "hash", "file"})

    def _collect(self) -> VTEvidence:
        settings = get_settings()
        api_key = settings.virustotal_api_key

        if not api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not configured")

        if self.observable_type == "ip":
            return self._collect_ip(api_key)
        elif self.observable_type == "url":
            return self._collect_url(api_key)
        elif self.observable_type in ("hash", "file"):
            return self._collect_hash(api_key)
        else:
            return self._collect_domain(api_key)

    # ── Domain ────────────────────────────────────────────────────────────────

    def _collect_domain(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for domain report."""
        evidence = VTEvidence()

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
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        return self._parse_attributes(evidence, data)

    # ── IP ────────────────────────────────────────────────────────────────────

    def _collect_ip(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for IP address report."""
        evidence = VTEvidence()

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{self.domain}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("IP not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        return self._parse_attributes(evidence, data)

    # ── URL ───────────────────────────────────────────────────────────────────

    def _collect_url(self, api_key: str) -> VTEvidence:
        """Submit URL to VT and retrieve analysis."""
        evidence = VTEvidence()
        headers = {"x-apikey": api_key}

        # Submit URL for scanning
        url_id = base64.urlsafe_b64encode(self.domain.encode()).decode().rstrip("=")

        # First try to get existing report
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            # No existing report — submit for fresh scan
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={self.domain}",
                timeout=self.timeout,
            )
            if submit_resp.status_code not in (200, 201):
                raise ValueError(f"VT URL submission failed: {submit_resp.status_code}")

            analysis_id = submit_resp.json().get("data", {}).get("id", "")
            if not analysis_id:
                evidence.notes.append("URL submitted to VT but no analysis ID returned")
                return evidence

            # Poll for result (max 30s)
            for _ in range(6):
                time.sleep(5)
                poll_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=self.timeout,
                )
                if poll_resp.status_code == 200:
                    poll_data = poll_resp.json()
                    status = poll_data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        data = poll_data
                        break
            else:
                evidence.notes.append("VT URL analysis timed out (30s)")
                return evidence
        else:
            if resp.status_code == 429:
                raise ValueError("VirusTotal API rate limit exceeded")
            if resp.status_code != 200:
                raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")
            data = resp.json()

        self._store_artifact("raw_vt", json.dumps(data, default=str))
        return self._parse_attributes(evidence, data)

    # ── Hash ──────────────────────────────────────────────────────────────────

    def _collect_hash(self, api_key: str) -> VTEvidence:
        """Query VT API v3 for file hash report."""
        import re
        evidence = VTEvidence()

        # Clean hash value: strip known prefixes, then extract from compound identifiers
        # e.g. "sha256.exe.zip::shortid" → extract the 64-char SHA256 embedded in the filename
        hash_value = self.domain
        for prefix in ("md5:", "sha1:", "sha256:", "sha512:"):
            if hash_value.lower().startswith(prefix):
                hash_value = hash_value[len(prefix):]
                break

        # If still not a clean hash, try extracting SHA256 (64 hex) or MD5 (32 hex)
        if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", hash_value):
            sha256_match = re.search(r"\b([0-9a-fA-F]{64})\b", hash_value)
            md5_match = re.search(r"\b([0-9a-fA-F]{32})\b", hash_value)
            if sha256_match:
                hash_value = sha256_match.group(1)
            elif md5_match:
                hash_value = md5_match.group(1)
            else:
                evidence.found = False
                evidence.notes.append(f"Could not extract a valid hash from: {self.domain[:80]}")
                return evidence

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": api_key},
            timeout=self.timeout,
        )

        if resp.status_code == 404:
            evidence.found = False
            evidence.notes.append("Hash not found in VirusTotal database")
            return evidence

        if resp.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        if resp.status_code != 200:
            raise ValueError(f"VT API returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        self._store_artifact("raw_vt", json.dumps(data, default=str))
        evidence = self._parse_attributes(evidence, data)

        # Extract file-specific metadata
        attrs = data.get("data", {}).get("attributes", {})
        evidence.vt_registrar = attrs.get("type_description", "")  # reuse field for file type
        if attrs.get("sha256"):
            evidence.notes.append(f"SHA256: {attrs['sha256']}")
        if attrs.get("md5"):
            evidence.notes.append(f"MD5: {attrs['md5']}")
        if attrs.get("size"):
            evidence.notes.append(f"Size: {attrs['size']} bytes")

        return evidence

    # ── Shared parser ─────────────────────────────────────────────────────────

    def _parse_attributes(self, evidence: VTEvidence, data: dict) -> VTEvidence:
        """Parse common VT response attributes into evidence object."""
        attrs = data.get("data", {}).get("attributes", {})
        evidence.found = True

        # Analysis stats
        stats = attrs.get("last_analysis_stats", {})
        evidence.malicious_count = stats.get("malicious", 0)
        evidence.suspicious_count = stats.get("suspicious", 0)
        evidence.harmless_count = stats.get("harmless", 0)
        evidence.undetected_count = stats.get("undetected", 0)
        evidence.total_vendors = sum(stats.values()) if stats else 0

        # Individual vendor results
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
            if category == "malicious":
                evidence.flagged_malicious_by.append(vendor_name)
            elif category == "suspicious":
                evidence.flagged_suspicious_by.append(vendor_name)

        # Categories, popularity, reputation
        evidence.categories = attrs.get("categories", {})
        for service, rank_data in attrs.get("popularity_ranks", {}).items():
            if isinstance(rank_data, dict) and "rank" in rank_data:
                evidence.popularity_ranks[service] = rank_data["rank"]
        evidence.reputation_score = attrs.get("reputation", 0)

        # Dates
        for attr_key, ev_attr in [
            ("creation_date", "vt_creation_date"),
            ("last_modification_date", "vt_last_modified"),
            ("last_analysis_date", "last_analysis_date"),
        ]:
            if attrs.get(attr_key):
                setattr(evidence, ev_attr, datetime.fromtimestamp(
                    attrs[attr_key], tz=timezone.utc
                ).isoformat())

        # Domain-specific extras
        evidence.vt_dns_records = attrs.get("last_dns_records", [])
        cert_info = attrs.get("last_https_certificate", {})
        if cert_info:
            evidence.vt_cert_issuer = cert_info.get("issuer", {}).get("O", "")
            evidence.vt_cert_subject = cert_info.get("subject", {}).get("CN", "")
        if not evidence.vt_registrar:
            evidence.vt_registrar = attrs.get("registrar", "")
        evidence.tags = attrs.get("tags", [])

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> VTEvidence:
        return VTEvidence(meta=meta)
