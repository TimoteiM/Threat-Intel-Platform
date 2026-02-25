"""
Threat Feed Collector — queries external threat intelligence feeds.

Feeds checked:
- AbuseIPDB: IP abuse score and report history
- PhishTank: Known phishing URL database
- ThreatFox (abuse.ch): IOC feed for malware/C2
- OpenPhish: Community phishing URL feed (free, no key)

Feeds are queried in parallel threads. Missing API keys = graceful skip.
"""

from __future__ import annotations

import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import (
    AbuseIPDBResult,
    CollectorMeta,
    PhishTankResult,
    ThreatFeedEvidence,
    ThreatFoxResult,
)

logger = logging.getLogger(__name__)

# AbuseIPDB abuse category descriptions (subset)
ABUSEIPDB_CATEGORIES: dict[int, str] = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class ThreatFeedsCollector(BaseCollector):
    name = "threat_feeds"

    def _collect(self) -> ThreatFeedEvidence:
        settings = get_settings()
        evidence = ThreatFeedEvidence(
            meta=CollectorMeta(collector=self.name),
            feeds_checked=[],
            feeds_skipped=[],
        )

        # Resolve domain → IP for AbuseIPDB
        resolved_ip: str | None = None
        try:
            resolved_ip = socket.gethostbyname(self.domain)
        except socket.gaierror:
            logger.warning(f"[{self.name}] Could not resolve {self.domain} to IP")

        # Run all feed queries concurrently
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            if settings.abuseipdb_api_key and resolved_ip:
                futures[executor.submit(self._query_abuseipdb, resolved_ip, settings.abuseipdb_api_key)] = "abuseipdb"
            else:
                if not settings.abuseipdb_api_key:
                    evidence.feeds_skipped.append("abuseipdb (no API key)")
                elif not resolved_ip:
                    evidence.feeds_skipped.append("abuseipdb (DNS resolution failed)")

            futures[executor.submit(self._query_phishtank, self.domain)] = "phishtank"
            futures[executor.submit(self._query_threatfox, self.domain)] = "threatfox"
            futures[executor.submit(self._query_openphish, self.domain)] = "openphish"

            for future in as_completed(futures):
                feed_name = futures[future]
                try:
                    result = future.result()
                    if feed_name == "abuseipdb" and result is not None:
                        evidence.abuseipdb = result
                        evidence.feeds_checked.append("abuseipdb")
                    elif feed_name == "phishtank":
                        evidence.phishtank = result
                        evidence.feeds_checked.append("phishtank")
                    elif feed_name == "threatfox":
                        evidence.threatfox_matches = result
                        evidence.feeds_checked.append("threatfox")
                    elif feed_name == "openphish":
                        evidence.openphish_listed = result
                        evidence.feeds_checked.append("openphish")
                except Exception as e:
                    logger.warning(f"[{self.name}] Feed '{feed_name}' failed: {e}")
                    evidence.feeds_skipped.append(f"{feed_name} (error: {type(e).__name__})")

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> ThreatFeedEvidence:
        return ThreatFeedEvidence(meta=meta)

    def _query_abuseipdb(self, ip: str, api_key: str) -> AbuseIPDBResult | None:
        """Check IP against AbuseIPDB."""
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        if not data:
            return None

        categories = data.get("reports", [])
        all_cats: list[int] = []
        for report in categories:
            all_cats.extend(report.get("categories", []))
        unique_cats = list(set(all_cats))

        self._store_artifact("abuseipdb_raw", json.dumps(data))

        return AbuseIPDBResult(
            ip=ip,
            abuse_confidence_score=data.get("abuseConfidenceScore", 0),
            total_reports=data.get("totalReports", 0),
            last_reported_at=data.get("lastReportedAt"),
            categories=unique_cats,
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            country_code=data.get("countryCode"),
        )

    def _query_phishtank(self, domain: str) -> PhishTankResult:
        """Check domain against PhishTank (public API, key optional)."""
        settings = get_settings()
        url = f"http://{domain}"

        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe="")

        params: dict = {"url": encoded_url, "format": "json"}
        if settings.phishtank_api_key:
            params["app_key"] = settings.phishtank_api_key

        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=params,
                headers={"User-Agent": "phishtank/threat-investigator"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", {})

            if results.get("in_database"):
                entry = results.get("phish_detail_page", "")
                phish_id = results.get("phish_id", "")
                return PhishTankResult(
                    in_database=True,
                    phish_id=str(phish_id) if phish_id else None,
                    verified=results.get("verified") == "yes",
                    verified_at=results.get("verified_at"),
                )
            return PhishTankResult(in_database=False)
        except Exception as e:
            logger.debug(f"[{self.name}] PhishTank query failed: {e}")
            return PhishTankResult(in_database=False)

    def _query_threatfox(self, domain: str) -> list[ThreatFoxResult]:
        """Search ThreatFox IOC database for domain/subdomain hits."""
        payload = {
            "query": "search_ioc",
            "search_term": domain,
        }
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            headers={"API-KEY": ""},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return []

        matches = []
        for ioc in data.get("data", []) or []:
            matches.append(ThreatFoxResult(
                ioc_value=ioc.get("ioc", domain),
                ioc_type=ioc.get("ioc_type", "domain"),
                threat_type=ioc.get("threat_type", "unknown"),
                malware=ioc.get("malware_printable") or ioc.get("malware"),
                confidence_level=ioc.get("confidence_level"),
                first_seen=ioc.get("first_seen"),
                last_seen=ioc.get("last_seen"),
                tags=ioc.get("tags") or [],
            ))

        if matches:
            self._store_artifact("threatfox_raw", json.dumps(data.get("data", [])))

        return matches

    def _query_openphish(self, domain: str) -> bool:
        """Check domain against OpenPhish community feed."""
        try:
            resp = requests.get(
                "https://openphish.com/feed.txt",
                timeout=self.timeout,
            )
            resp.raise_for_status()
            feed_lines = resp.text.lower().splitlines()
            domain_lower = domain.lower()
            for line in feed_lines:
                if domain_lower in line:
                    return True
            return False
        except Exception as e:
            logger.debug(f"[{self.name}] OpenPhish query failed: {e}")
            return False
