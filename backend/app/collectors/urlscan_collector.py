"""
URLScan Collector - submits observable to urlscan.io and retrieves analysis.

Supports: domain, ip, url

Flow:
1. Search existing result first
2. Submit scan if needed (public first, then unlisted fallback)
3. Poll result endpoint
4. Parse verdict, metadata, screenshot
"""

from __future__ import annotations

import json
import logging
import time

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

        if self.observable_type == "url":
            target_url = self.domain
        elif self.observable_type == "ip":
            target_url = f"http://{self.domain}"
        else:
            target_url = f"https://{self.domain}"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["API-Key"] = api_key

        result_data = self._search_existing(evidence, headers=headers)
        if result_data:
            return self._parse_result(evidence, result_data)

        staged_visibilities = ["public"]
        if api_key:
            staged_visibilities.append("unlisted")

        last_error: str | None = None
        for visibility in staged_visibilities:
            scan_uuid, submit_error = self._submit_scan(
                target_url=target_url,
                headers=headers,
                visibility=visibility,
            )
            if submit_error:
                last_error = submit_error
                continue
            if not scan_uuid:
                last_error = "URLScan returned no scan UUID"
                continue

            evidence.scan_id = scan_uuid
            result_data = self._poll_result(scan_uuid)
            if result_data:
                if visibility != "public":
                    evidence.notes.append(
                        "Submitted unlisted scan after public scan path was unavailable"
                    )
                return self._parse_result(evidence, result_data)

            last_error = "URLScan analysis timed out after 30s"

        if last_error:
            evidence.notes.append(last_error)
        return evidence

    def _search_existing(
        self,
        evidence: URLScanEvidence,
        *,
        headers: dict[str, str],
    ) -> dict:
        """
        Fast-path for existing scans.

        Notes:
        - Avoid custom sort values because they may be forbidden on some tiers.
        - Prefer search hits first, then fetch the full result document only for the best hit.
        """
        queries: list[str]
        if self.observable_type == "ip":
            queries = [f"page.ip:{self.domain}"]
        elif self.observable_type == "url":
            queries = [f"task.url:{self.domain}", f"page.url:{self.domain}"]
        else:
            queries = [f"page.domain:{self.domain}", f"page.apexDomain:{self.domain}"]

        for query in queries:
            try:
                resp = requests.get(
                    f"{URLSCAN_API}/search/",
                    params={"q": query, "size": 5},
                    headers=headers,
                    timeout=min(self.timeout, 10),
                )
                if resp.status_code != 200:
                    logger.debug(
                        "[urlscan] Search query failed (%s): HTTP %s",
                        query,
                        resp.status_code,
                    )
                    continue
                results = (resp.json() or {}).get("results", [])
                if not results:
                    continue

                best = self._pick_best_search_result(results)
                scan_uuid = ((best.get("task") or {}).get("uuid"))
                if scan_uuid:
                    evidence.scan_id = scan_uuid
                evidence.notes.append("Using existing URLScan search result")

                result_url = best.get("result")
                if not result_url and scan_uuid:
                    result_url = f"{URLSCAN_API}/result/{scan_uuid}/"
                if result_url:
                    if isinstance(result_url, str) and result_url.startswith("/"):
                        result_url = f"https://urlscan.io{result_url}"
                    try:
                        result_resp = requests.get(
                            str(result_url),
                            headers=headers,
                            timeout=min(self.timeout, 10),
                        )
                        if result_resp.status_code == 200:
                            return result_resp.json() or {}
                    except requests.exceptions.RequestException as e:
                        logger.debug("[urlscan] Result fetch failed for %s: %s", result_url, e)

                evidence.notes.append("Using partial URLScan metadata (full result unavailable)")
                return best
            except Exception as e:
                logger.debug("[urlscan] Existing scan search failed for query %s: %s", query, e)
        return {}

    def _pick_best_search_result(self, results: list[dict]) -> dict:
        """
        Prefer exact observable matches when multiple search hits are returned.
        """
        needle = str(self.domain or "").strip().lower()
        if not needle:
            return results[0]

        def _matches(item: dict) -> bool:
            page = item.get("page") or {}
            task = item.get("task") or {}
            if self.observable_type == "ip":
                return str(page.get("ip") or "").strip().lower() == needle
            if self.observable_type == "url":
                task_url = str(task.get("url") or "").strip().lower()
                page_url = str(page.get("url") or "").strip().lower()
                return needle in {task_url, page_url}
            domain_fields = {
                str(page.get("domain") or "").strip().lower(),
                str(page.get("apexDomain") or "").strip().lower(),
                str(task.get("domain") or "").strip().lower(),
                str(task.get("apexDomain") or "").strip().lower(),
            }
            return needle in domain_fields

        for result in results:
            if _matches(result):
                return result
        return results[0]

    def _submit_scan(
        self,
        *,
        target_url: str,
        headers: dict[str, str],
        visibility: str,
    ) -> tuple[str | None, str | None]:
        try:
            submit_resp = requests.post(
                f"{URLSCAN_API}/scan/",
                headers=headers,
                json={"url": target_url, "visibility": visibility},
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            return None, f"URLScan submission failed ({visibility}): {e}"

        if submit_resp.status_code == 429:
            return None, "URLScan rate limit exceeded"
        if submit_resp.status_code not in (200, 201):
            return None, (
                f"URLScan submission returned {submit_resp.status_code} ({visibility}): "
                f"{submit_resp.text[:200]}"
            )

        submit_data = submit_resp.json() or {}
        return submit_data.get("uuid"), None

    def _poll_result(self, scan_uuid: str) -> dict:
        for attempt in range(4):
            time.sleep(3)
            try:
                result_resp = requests.get(
                    f"{URLSCAN_API}/result/{scan_uuid}/",
                    timeout=self.timeout,
                )
                if result_resp.status_code == 200:
                    return result_resp.json() or {}
                if result_resp.status_code == 404:
                    continue
                logger.debug(
                    "[urlscan] Poll attempt %s: HTTP %s",
                    attempt + 1,
                    result_resp.status_code,
                )
            except requests.exceptions.RequestException as e:
                logger.debug("[urlscan] Poll attempt %s failed: %s", attempt + 1, e)
        return {}

    def _parse_result(self, evidence: URLScanEvidence, result_data: dict) -> URLScanEvidence:
        self._store_artifact("raw_urlscan", json.dumps(result_data, default=str))

        verdicts = result_data.get("verdicts", {})
        evidence.verdicts = verdicts
        overall = verdicts.get("overall", {})
        evidence.score = overall.get("score")
        if overall.get("malicious"):
            evidence.verdict = "malicious"
        elif overall.get("suspicious"):
            evidence.verdict = "suspicious"
        elif overall:
            evidence.verdict = "benign"
        else:
            evidence.verdict = "unknown"

        evidence.tags = overall.get("tags", [])

        page = result_data.get("page", {})
        evidence.page_url = page.get("url")
        evidence.page_ip = page.get("ip")
        evidence.page_country = page.get("country")
        evidence.page_server = page.get("server")
        evidence.page_title = page.get("title")

        stats = result_data.get("stats", {})
        evidence.requests_count = stats.get("requests")

        screenshot_url = (
            (result_data.get("task") or {}).get("screenshotURL")
            or result_data.get("screenshot")
        )
        if screenshot_url:
            if isinstance(screenshot_url, str) and screenshot_url.startswith("/"):
                screenshot_url = f"https://urlscan.io{screenshot_url}"
            try:
                sc_resp = requests.get(screenshot_url, timeout=20)
                if sc_resp.status_code == 200 and sc_resp.content:
                    self._store_artifact("screenshot_png", sc_resp.content)
                    # Real artifact UUID is assigned later during persistence in analysis task.
                    evidence.screenshot_artifact_id = None
            except Exception:
                pass

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> URLScanEvidence:
        return URLScanEvidence(meta=meta)
