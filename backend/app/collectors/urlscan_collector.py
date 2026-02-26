"""
URLScan Collector — submits observable to urlscan.io and retrieves analysis.

Supports: domain, ip, url

Flow:
1. Submit: POST /api/v1/scan/ with the target URL
2. Poll:   GET /api/v1/result/{uuid}/ — retry every 5s up to 60s
3. Parse verdict, page metadata, screenshot, request stats

Requires: URLSCAN_API_KEY in .env (optional — public scans work without key
           but are rate-limited to 1 req/min and visibility is "public")
"""

from __future__ import annotations

import json
import logging
import time
from urllib.parse import urlparse

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import CollectorMeta, URLScanEvidence

logger = logging.getLogger(__name__)

URLSCAN_API = "https://urlscan.io/api/v1"


class URLScanCollector(BaseCollector):
    name = "urlscan"
    supported_types = frozenset({"domain", "ip", "url"})

    def _collect(self) -> URLScanEvidence:
        settings = get_settings()
        api_key = settings.urlscan_api_key
        evidence = URLScanEvidence()

        # ── Build target URL from observable ─────────────────────────────────
        if self.observable_type == "url":
            target_url = self.domain
        elif self.observable_type == "ip":
            target_url = f"http://{self.domain}"
        else:
            target_url = f"https://{self.domain}"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["API-Key"] = api_key

        # ── Search for a recent existing scan first (avoids submission + wait) ─
        result_data = self._search_existing(evidence, headers)
        if result_data:
            return self._parse_result(evidence, result_data)

        # ── No cached result — submit a new scan ─────────────────────────────
        visibility = "unlisted" if api_key else "public"
        try:
            submit_resp = requests.post(
                f"{URLSCAN_API}/scan/",
                headers=headers,
                json={"url": target_url, "visibility": visibility},
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            raise ValueError(f"URLScan submission failed: {e}")

        if submit_resp.status_code == 429:
            raise ValueError("URLScan rate limit exceeded")

        if submit_resp.status_code not in (200, 201):
            raise ValueError(
                f"URLScan submission returned {submit_resp.status_code}: "
                f"{submit_resp.text[:200]}"
            )

        submit_data = submit_resp.json()
        scan_uuid = submit_data.get("uuid")
        if not scan_uuid:
            evidence.notes.append("URLScan returned no scan UUID")
            return evidence

        evidence.scan_id = scan_uuid

        # ── Poll for result (max 30s, 5s intervals) ───────────────────────────
        for attempt in range(6):
            time.sleep(5)
            try:
                result_resp = requests.get(
                    f"{URLSCAN_API}/result/{scan_uuid}/",
                    timeout=self.timeout,
                )
                if result_resp.status_code == 200:
                    result_data = result_resp.json()
                    return self._parse_result(evidence, result_data)
                elif result_resp.status_code == 404:
                    continue  # Not ready yet
                else:
                    logger.debug(
                        f"[urlscan] Poll attempt {attempt + 1}: "
                        f"HTTP {result_resp.status_code}"
                    )
            except requests.exceptions.RequestException as e:
                logger.debug(f"[urlscan] Poll attempt {attempt + 1} failed: {e}")

        evidence.notes.append("URLScan analysis timed out after 30s")
        return evidence

    def _search_existing(self, evidence: URLScanEvidence, headers: dict) -> dict:
        """Search URLScan for a recent existing result to avoid re-scanning."""
        if self.observable_type == "ip":
            query = f"page.ip:{self.domain}"
        elif self.observable_type == "url":
            query = f"page.url:{self.domain}"
        else:
            query = f"page.domain:{self.domain}"

        try:
            resp = requests.get(
                f"{URLSCAN_API}/search/",
                params={"q": query, "size": 1, "sort": "date:desc"},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return {}
            results = resp.json().get("results", [])
            if not results:
                return {}

            scan_uuid = results[0].get("task", {}).get("uuid")
            if not scan_uuid:
                return {}

            evidence.scan_id = scan_uuid
            evidence.notes.append("Using cached URLScan result")

            result_resp = requests.get(
                f"{URLSCAN_API}/result/{scan_uuid}/",
                timeout=self.timeout,
            )
            if result_resp.status_code == 200:
                return result_resp.json()
        except Exception as e:
            logger.debug(f"[urlscan] Existing scan search failed: {e}")

        return {}

    def _parse_result(self, evidence: URLScanEvidence, result_data: dict) -> URLScanEvidence:
        """Parse URLScan result JSON into evidence."""
        self._store_artifact("raw_urlscan", json.dumps(result_data, default=str))

        verdicts = result_data.get("verdicts", {})
        evidence.verdicts = verdicts
        overall = verdicts.get("overall", {})
        evidence.score = overall.get("score")
        if overall.get("malicious"):
            evidence.verdict = "malicious"
        elif overall.get("suspicious"):
            evidence.verdict = "suspicious"
        else:
            evidence.verdict = "benign"

        evidence.tags = overall.get("tags", [])

        page = result_data.get("page", {})
        evidence.page_url = page.get("url")
        evidence.page_ip = page.get("ip")
        evidence.page_country = page.get("country")
        evidence.page_server = page.get("server")
        evidence.page_title = page.get("title")

        stats = result_data.get("stats", {})
        evidence.requests_count = stats.get("requests")

        screenshot_url = result_data.get("task", {}).get("screenshotURL")
        if screenshot_url:
            try:
                sc_resp = requests.get(screenshot_url, timeout=20)
                if sc_resp.status_code == 200 and sc_resp.content:
                    self._store_artifact("screenshot_png", sc_resp.content)
                    evidence.screenshot_artifact_id = (
                        f"{self.investigation_id}_urlscan_screenshot_png"
                    )
            except Exception:
                pass

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> URLScanEvidence:
        return URLScanEvidence(meta=meta)
