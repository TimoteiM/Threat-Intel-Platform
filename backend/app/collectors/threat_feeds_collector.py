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
from urllib.parse import quote

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.services.abuseipdb_client import abuseipdb_get
from app.services.provider_usage_metrics import record_provider_request
from app.models.schemas import (
    AbuseIPDBResult,
    CollectorMeta,
    GoogleSafeBrowsingResult,
    OTXPassiveDNSRecord,
    OTXPulseResult,
    OTXResult,
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
    supported_types = frozenset({"domain", "ip", "url", "hash"})

    def _collect(self) -> ThreatFeedEvidence:
        from urllib.parse import urlparse

        settings = get_settings()
        evidence = ThreatFeedEvidence(
            meta=CollectorMeta(collector=self.name),
            feeds_checked=[],
            feeds_skipped=[],
        )

        obs_type = self.observable_type

        # ── Determine query value and which feeds apply ──────────────────────
        # For hash: only ThreatFox is applicable
        # For IP: AbuseIPDB directly, skip PhishTank/OpenPhish (URL/domain feeds)
        # For URL: extract hostname for PhishTank/OpenPhish; resolve to IP for AbuseIPDB
        # For domain: existing full logic

        if obs_type == "hash":
            # Only ThreatFox applies for hashes
            evidence.feeds_skipped.extend([
                "abuseipdb (not applicable for hash)",
                "phishtank (not applicable for hash)",
                "openphish (not applicable for hash)",
                "google_safe_browsing (not applicable for hash)",
            ])
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(self._query_threatfox, self.domain): "threatfox"}
                if settings.otx_api_key:
                    futures[executor.submit(self._query_otx, self.domain, obs_type, settings.otx_api_key)] = "otx"
                else:
                    evidence.feeds_skipped.append("otx (no API key)")
                for future in as_completed(futures):
                    feed_name = futures[future]
                    try:
                        result = future.result()
                        if feed_name == "threatfox":
                            evidence.threatfox_matches = result
                            evidence.feeds_checked.append("threatfox")
                        elif feed_name == "otx":
                            evidence.otx = result
                            evidence.feeds_checked.append("otx")
                    except Exception as e:
                        logger.warning(f"[{self.name}] {feed_name} failed: {e}")
                        evidence.feeds_skipped.append(f"{feed_name} (error: {type(e).__name__})")
            return evidence

        # ── Determine IP and domain for feeds that need them ─────────────────
        if obs_type == "ip":
            resolved_ip: str | None = self.domain
            query_domain = self.domain  # use IP string for PhishTank/ThreatFox
        elif obs_type == "url":
            parsed = urlparse(self.domain)
            query_domain = parsed.hostname or self.domain
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(query_domain)
            except socket.gaierror:
                logger.warning(f"[{self.name}] Could not resolve {query_domain} to IP")
        else:  # domain
            query_domain = self.domain
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(self.domain)
            except socket.gaierror:
                logger.warning(f"[{self.name}] Could not resolve {self.domain} to IP")

        # ── Run feed queries concurrently ─────────────────────────────────────
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}

            if obs_type == "ip":
                # AbuseIPDB is the primary feed for IPs
                if settings.abuseipdb_api_key:
                    futures[executor.submit(self._query_abuseipdb, resolved_ip, settings.abuseipdb_api_key)] = "abuseipdb"
                else:
                    evidence.feeds_skipped.append("abuseipdb (no API key)")
                # PhishTank/OpenPhish are URL/domain feeds — skip for pure IP
                evidence.feeds_skipped.extend([
                    "phishtank (not applicable for IP)",
                    "openphish (not applicable for IP)",
                    "google_safe_browsing (not applicable for IP)",
                ])
            else:
                # domain or url: all feeds apply
                if settings.abuseipdb_api_key and resolved_ip:
                    futures[executor.submit(self._query_abuseipdb, resolved_ip, settings.abuseipdb_api_key)] = "abuseipdb"
                else:
                    if not settings.abuseipdb_api_key:
                        evidence.feeds_skipped.append("abuseipdb (no API key)")
                    elif not resolved_ip:
                        evidence.feeds_skipped.append("abuseipdb (DNS resolution failed)")

                futures[executor.submit(self._query_phishtank, query_domain)] = "phishtank"
                futures[executor.submit(self._query_openphish, query_domain)] = "openphish"
                if settings.google_safe_browsing_api_key:
                    gsb_url = self.domain if obs_type == "url" else f"https://{query_domain}"
                    futures[
                        executor.submit(
                            self._query_google_safe_browsing,
                            gsb_url,
                            settings.google_safe_browsing_api_key,
                        )
                    ] = "google_safe_browsing"
                else:
                    evidence.feeds_skipped.append("google_safe_browsing (no API key)")

            futures[executor.submit(self._query_threatfox, self.domain)] = "threatfox"
            if settings.otx_api_key:
                futures[executor.submit(self._query_otx, self.domain, obs_type, settings.otx_api_key)] = "otx"
            else:
                evidence.feeds_skipped.append("otx (no API key)")

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
                    elif feed_name == "google_safe_browsing":
                        evidence.google_safe_browsing = result
                        evidence.feeds_checked.append("google_safe_browsing")
                    elif feed_name == "otx":
                        evidence.otx = result
                        evidence.feeds_checked.append("otx")
                except Exception as e:
                    logger.warning(f"[{self.name}] Feed '{feed_name}' failed: {e}")
                    evidence.feeds_skipped.append(f"{feed_name} (error: {type(e).__name__})")

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> ThreatFeedEvidence:
        return ThreatFeedEvidence(meta=meta)

    def _query_abuseipdb(self, ip: str, api_key: str) -> AbuseIPDBResult | None:
        """
        Check IP against AbuseIPDB.

        `api_key` is ignored in favour of the shared client, which walks every
        configured key so a spent daily allowance falls through to the spare
        instead of ending AbuseIPDB coverage for the day. The parameter stays
        for the existing call sites and tests that pass it.
        """
        resp = abuseipdb_get(
            "check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=self.timeout,
        )
        if resp is None:
            return None
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
            record_provider_request("phishtank")
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
        record_provider_request("threatfox")
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
            record_provider_request("openphish")
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

    def _query_google_safe_browsing(self, url: str, api_key: str) -> GoogleSafeBrowsingResult:
        try:
            record_provider_request("google_safe_browsing")
            resp = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "threat-intel-platform", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json() or {}
            matches = data.get("matches") or []
            return GoogleSafeBrowsingResult(
                checked=True,
                listed=bool(matches),
                matches_count=len(matches),
                threat_types=sorted({str(m.get("threatType") or "") for m in matches if m.get("threatType")}),
                platform_types=sorted({str(m.get("platformType") or "") for m in matches if m.get("platformType")}),
                cache_durations=sorted({str(m.get("cacheDuration") or "") for m in matches if m.get("cacheDuration")}),
            )
        except Exception as e:
            return GoogleSafeBrowsingResult(
                checked=False,
                listed=False,
                error=str(e),
            )

    def _query_otx(self, indicator: str, observable_type: str, api_key: str) -> OTXResult:
        """Look up an observable in AlienVault OTX pulses and supporting sections."""
        indicator_type = self._otx_indicator_type(indicator, observable_type)
        if not indicator_type:
            return OTXResult(
                checked=False,
                found=False,
                error=f"Unsupported OTX indicator type for {observable_type}",
            )

        record_provider_request("otx")
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{quote(indicator, safe='')}/general",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        self._store_artifact("otx_general_raw", json.dumps(data))

        section_data: dict[str, dict] = {}
        sections = {str(section) for section in data.get("sections") or []}
        wanted_sections = [
            section for section in ("geo", "passive_dns", "url_list", "malware", "http_scans")
            if section in sections
        ]
        if wanted_sections:
            with ThreadPoolExecutor(max_workers=min(4, len(wanted_sections))) as executor:
                futures = {
                    executor.submit(
                        self._query_otx_section,
                        indicator,
                        indicator_type,
                        section,
                        api_key,
                    ): section
                    for section in wanted_sections
                }
                for future in as_completed(futures):
                    section = futures[future]
                    try:
                        section_data[section] = future.result()
                    except Exception as e:
                        logger.debug(f"[{self.name}] OTX {section} section failed: {e}")

        if section_data:
            self._store_artifact("otx_sections_raw", json.dumps(section_data))
        return self._parse_otx_general(data, indicator_type, section_data)

    def _query_otx_section(self, indicator: str, indicator_type: str, section: str, api_key: str) -> dict:
        record_provider_request("otx")
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{quote(indicator, safe='')}/{section}",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json() or {}

    def _otx_indicator_type(self, indicator: str, observable_type: str) -> str | None:
        from urllib.parse import urlparse
        import ipaddress

        if observable_type == "url" or indicator.startswith(("http://", "https://")):
            return "URL"
        if observable_type == "hash":
            return "file"
        if observable_type == "ip":
            try:
                ip = ipaddress.ip_address(indicator)
                return "IPv6" if ip.version == 6 else "IPv4"
            except ValueError:
                return None
        if urlparse(indicator).scheme:
            return "URL"
        return "domain"

    def _parse_otx_general(
        self,
        data: dict,
        indicator_type: str,
        section_data: dict[str, dict] | None = None,
    ) -> OTXResult:
        section_data = section_data or {}
        pulse_info = data.get("pulse_info") or {}
        pulse_rows = pulse_info.get("pulses") or []
        pulses: list[OTXPulseResult] = []

        for row in pulse_rows[:12]:
            if not isinstance(row, dict):
                continue
            author = row.get("author") if isinstance(row.get("author"), dict) else {}
            pulses.append(OTXPulseResult(
                id=row.get("id"),
                name=row.get("name") or "",
                description=row.get("description") or None,
                author_name=row.get("author_name") or author.get("username"),
                created=row.get("created"),
                modified=row.get("modified"),
                tlp=row.get("TLP") or row.get("tlp"),
                subscriber_count=row.get("subscriber_count"),
                indicator_count=row.get("indicator_count"),
                related_indicator_is_active=(
                    bool(row.get("related_indicator_is_active"))
                    if row.get("related_indicator_is_active") is not None
                    else None
                ),
                tags=[str(tag) for tag in row.get("tags") or [] if str(tag).strip()][:12],
                malware_families=[
                    str(item) for item in row.get("malware_families") or [] if str(item).strip()
                ][:8],
                adversary=row.get("adversary"),
                references=[str(ref) for ref in row.get("references") or [] if str(ref).strip()][:8],
            ))

        passive_dns_data = section_data.get("passive_dns") or {}
        passive_dns_rows = passive_dns_data.get("passive_dns") or []
        passive_dns: list[OTXPassiveDNSRecord] = []
        nameservers: set[str] = set()
        subdomains: set[str] = set()
        ip_addresses: set[str] = set()

        for row in passive_dns_rows[:24]:
            if not isinstance(row, dict):
                continue
            hostname = str(row.get("hostname") or "").strip() or None
            address = str(row.get("address") or "").strip() or None
            record_type = str(row.get("record_type") or "").strip() or None
            passive_dns.append(OTXPassiveDNSRecord(
                hostname=hostname,
                address=address,
                record_type=record_type,
                first=row.get("first"),
                last=row.get("last"),
                asn=(str(row.get("asn") or "").strip() or None),
                country=row.get("flag_title"),
                asset_type=row.get("asset_type"),
            ))
            if record_type == "NS" and address:
                nameservers.add(address)
            if hostname and hostname != data.get("indicator"):
                subdomains.add(hostname)
            if record_type in {"A", "AAAA"} and address:
                ip_addresses.add(address)

        url_list_data = section_data.get("url_list") or {}
        url_rows = url_list_data.get("url_list") or []
        urls: list[str] = []
        for row in url_rows[:12]:
            if isinstance(row, dict):
                url = row.get("url") or row.get("full_url")
                if url:
                    urls.append(str(url))
            elif row:
                urls.append(str(row))

        malware_data = section_data.get("malware") or {}
        http_scans_data = section_data.get("http_scans") or {}
        geo_data = section_data.get("geo") or {}

        references: list[str] = []
        seen_refs: set[str] = set()
        for pulse in pulses:
            for ref in pulse.references:
                if ref in seen_refs:
                    continue
                seen_refs.add(ref)
                references.append(ref)
                if len(references) >= 16:
                    break
            if len(references) >= 16:
                break

        external_resources: dict[str, str] = {}
        indicator = data.get("indicator")
        if data.get("whois"):
            external_resources["Whois"] = str(data["whois"])
        if data.get("alexa"):
            external_resources["Alexa"] = str(data["alexa"])
        if indicator:
            encoded_indicator = quote(str(indicator), safe="")
            external_resources["OTX"] = f"https://otx.alienvault.com/indicator/{indicator_type}/{encoded_indicator}"
            external_resources["VirusTotal"] = f"https://www.virustotal.com/gui/search/{encoded_indicator}"
            external_resources["URLVoid"] = f"https://www.urlvoid.com/scan/{encoded_indicator}/"

        pulse_count = int(pulse_info.get("count") or len(pulse_rows) or 0)
        passive_dns_count = int(passive_dns_data.get("count") or len(passive_dns_rows) or 0)
        url_count = int(url_list_data.get("full_size") or url_list_data.get("actual_size") or len(url_rows) or 0)
        malware_count = int(malware_data.get("count") or malware_data.get("size") or len(malware_data.get("data") or []) or 0)
        http_scans_count = 0 if http_scans_data.get("Error") else int(
            http_scans_data.get("count") or len(http_scans_data.get("data") or []) or 0
        )
        indicator_facts = self._build_otx_indicator_facts(
            passive_dns_count=passive_dns_count,
            url_count=url_count,
            malware_count=malware_count,
            http_scans_count=http_scans_count,
            subdomain_count=len(subdomains),
            tags={tag for pulse in pulses for tag in pulse.tags},
            malware_families={item for pulse in pulses for item in pulse.malware_families},
        )

        return OTXResult(
            checked=True,
            found=pulse_count > 0,
            indicator=indicator,
            indicator_type=indicator_type,
            type_title=data.get("type_title"),
            pulse_count=pulse_count,
            pulses=pulses,
            sections=[str(section) for section in data.get("sections") or [] if str(section).strip()],
            validation=[str(item) for item in data.get("validation") or [] if str(item).strip()],
            indicator_facts=indicator_facts,
            tags=sorted({tag for pulse in pulses for tag in pulse.tags})[:24],
            malware_families=sorted({item for pulse in pulses for item in pulse.malware_families})[:16],
            adversaries=sorted({pulse.adversary for pulse in pulses if pulse.adversary})[:12],
            references=references,
            external_resources=external_resources,
            geo={
                key: value for key, value in {
                    "ip": geo_data.get("ip"),
                    "asn": geo_data.get("asn"),
                    "country_name": geo_data.get("country_name") or geo_data.get("flag_title"),
                    "country_code": geo_data.get("country_code") or geo_data.get("country_code2"),
                    "city": geo_data.get("city"),
                    "region": geo_data.get("region"),
                    "latitude": geo_data.get("latitude"),
                    "longitude": geo_data.get("longitude"),
                }.items()
                if value not in (None, "")
            },
            passive_dns_count=passive_dns_count,
            passive_dns=passive_dns,
            nameservers=sorted(nameservers)[:12],
            subdomains=sorted(subdomains)[:12],
            ip_addresses=sorted(ip_addresses)[:12],
            url_count=url_count,
            urls=urls,
            malware_count=malware_count,
            http_scans_count=http_scans_count,
            reputation=data.get("reputation"),
        )

    def _build_otx_indicator_facts(
        self,
        *,
        passive_dns_count: int,
        url_count: int,
        malware_count: int,
        http_scans_count: int,
        subdomain_count: int,
        tags: set[str],
        malware_families: set[str],
    ) -> list[str]:
        facts: list[str] = []
        if passive_dns_count:
            facts.append("Historical OTX telemetry")
        if subdomain_count:
            facts.append(f"{subdomain_count} subdomain{'' if subdomain_count == 1 else 's'}")
        if url_count:
            facts.append(f"{url_count} observed URL{'' if url_count == 1 else 's'}")
        if malware_count:
            facts.append(f"{malware_count} malware sample{'' if malware_count == 1 else 's'}")
        if http_scans_count:
            facts.append(f"{http_scans_count} HTTP scan{'' if http_scans_count == 1 else 's'}")
        for label in sorted(tags | malware_families):
            if label and len(facts) < 10:
                facts.append(label)
        return facts[:10]
