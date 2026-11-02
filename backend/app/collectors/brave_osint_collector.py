from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import requests

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.models.schemas import BraveOSINTEvidence, BraveOSINTResult, CollectorMeta
from app.services.provider_usage_metrics import record_provider_request

logger = logging.getLogger(__name__)

SECURITY_KEYWORDS = ("phishing", "scam", "malware", "fraud", "abuse", "attack")
PREFERRED_SOURCE_HINTS = {
    "reddit.com": 35,
    "github.com": 32,
    "gitlab.com": 28,
    "medium.com": 18,
    "substack.com": 18,
    "blog": 16,
    "forum": 16,
    "security": 14,
}
NOISE_HINTS = (
    "directory",
    "listing",
    "yellowpages",
    "business listing",
    "sponsored",
    "advertisement",
)


def _normalize_terms(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        item = str(value or "").strip()
        if not item:
            continue
        lowered = item.lower()
        if lowered in seen:
            continue
        normalized.append(item)
        seen.add(lowered)
    return normalized


def generate_queries(domain: str, context: dict[str, Any] | None = None) -> list[str]:
    domain = domain.strip()
    return [domain] if domain else []


def search_brave(
    query: str,
    *,
    api_key: str,
    base_url: str,
    count: int,
    timeout: int,
) -> list[dict[str, Any]]:
    record_provider_request("brave_search")
    response = requests.get(
        base_url,
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
        },
        params={"q": query, "count": count},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    return (payload.get("web") or {}).get("results") or []


def _result_text(result: dict[str, Any]) -> str:
    return " ".join(
        str(result.get(field) or "")
        for field in ("title", "description")
    ).lower()


def _result_source(url: str) -> str:
    hostname = urlparse(url).hostname or ""
    return hostname.lower().removeprefix("www.") or "unknown"


def filter_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for result in results:
        url = str(result.get("url") or "").strip()
        if not url or url in seen_urls:
            continue
        text = _result_text(result)
        if not any(keyword in text for keyword in SECURITY_KEYWORDS):
            continue
        if any(noise in text for noise in NOISE_HINTS):
            continue
        result = dict(result)
        result["source"] = _result_source(url)
        result["matched_keywords"] = [
            keyword for keyword in SECURITY_KEYWORDS if keyword in text
        ]
        kept.append(result)
        seen_urls.add(url)

    return sorted(
        kept,
        key=lambda item: (
            -max(
                (weight for hint, weight in PREFERRED_SOURCE_HINTS.items() if hint in item["source"]),
                default=0,
            ),
            -len(item.get("matched_keywords") or []),
            item["source"],
        ),
    )


def score_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored: list[dict[str, Any]] = []
    for result in results:
        source = str(result.get("source") or _result_source(str(result.get("url") or "")))
        matched_keywords = list(result.get("matched_keywords") or [])
        if not matched_keywords:
            text = _result_text(result)
            matched_keywords = [keyword for keyword in SECURITY_KEYWORDS if keyword in text]
        score = 20
        score += min(25, 8 * len(matched_keywords))
        for hint, weight in PREFERRED_SOURCE_HINTS.items():
            if hint in source:
                score += weight
                break
        if "security" in source:
            score += 8
        result = dict(result)
        result["source"] = source
        result["matched_keywords"] = matched_keywords
        result["score"] = min(score, 100)
        scored.append(result)
    return sorted(scored, key=lambda item: item["score"], reverse=True)


def build_summary(
    *,
    domain: str,
    queries: list[str],
    raw_results: list[dict[str, Any]] | None = None,
    scored_results: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_results = raw_results or []
    top_hits = [
        BraveOSINTResult(
            title=str(item.get("title") or ""),
            url=str(item.get("url") or ""),
            description=str(item.get("description") or ""),
            source=str(item.get("source") or "unknown"),
            matched_keywords=list(item.get("matched_keywords") or []),
            score=int(item.get("score") or 0),
        )
        for item in scored_results[:5]
    ]
    observed_results: list[BraveOSINTResult] = []
    all_results: list[BraveOSINTResult] = []
    seen_observed_urls: set[str] = set()
    for item in raw_results:
        url = str(item.get("url") or "").strip()
        if not url or url in seen_observed_urls:
            continue
        seen_observed_urls.add(url)
        observed_results.append(
            BraveOSINTResult(
                title=str(item.get("title") or ""),
                url=url,
                description=str(item.get("description") or ""),
                source=_result_source(url),
                matched_keywords=[],
                score=0,
            )
        )
        all_results.append(
            BraveOSINTResult(
                title=str(item.get("title") or ""),
                url=url,
                description=str(item.get("description") or ""),
                source=_result_source(url),
                matched_keywords=[],
                score=0,
            )
        )
        if len(all_results) >= 25:
            break
        if len(observed_results) >= 10:
            break
    source_counts = Counter(hit.source for hit in top_hits)
    overall_score = min(100, max((hit.score for hit in top_hits), default=0) + max(0, len(top_hits) - 1) * 5)
    risk_level = "high" if overall_score >= 70 else "medium" if overall_score >= 40 else "low"

    if top_hits:
        summary = (
            f"Brave OSINT found {len(top_hits)} relevant security-related result(s) for {domain}. "
            f"Top signals reference {', '.join(sorted(source_counts.keys()))} and discuss "
            f"{', '.join(sorted(set(keyword for hit in top_hits for keyword in hit.matched_keywords))[:4]) or 'potential abuse activity'}."
        )
    else:
        summary = (
            f"Brave OSINT did not find high-confidence security discussions for {domain} "
            f"across the generated search queries."
        )

    return {
        "queries": queries,
        "top_hits": [hit.model_dump() for hit in top_hits],
        "observed_results": [hit.model_dump() for hit in observed_results],
        "all_results": [hit.model_dump() for hit in all_results],
        "source_counts": dict(source_counts),
        "score": overall_score,
        "risk_level": risk_level,
        "summary": summary,
    }


class BraveOSINTCollector(BaseCollector):
    name = "brave_osint"
    supported_types = frozenset({"domain", "url"})

    def _collect(self) -> BraveOSINTEvidence:
        settings = get_settings()
        if not settings.brave_search_api_key:
            return BraveOSINTEvidence(
                meta=CollectorMeta(collector=self.name),
                error="BRAVE_SEARCH_API_KEY not configured",
            )

        context = self.external_context if isinstance(self.external_context, dict) else {}
        queries = generate_queries(self.domain, context)
        raw_results: list[dict[str, Any]] = []

        for query in queries:
            raw_results.extend(
                search_brave(
                    query,
                    api_key=settings.brave_search_api_key,
                    base_url=settings.brave_search_base_url,
                    count=settings.brave_search_count,
                    timeout=self.timeout,
                )
            )

        self._store_artifact("raw_results", json.dumps({"queries": queries, "results": raw_results}))
        filtered = filter_results(raw_results)
        scored = score_results(filtered)
        summary = build_summary(domain=self.target_domain, queries=queries, raw_results=raw_results, scored_results=scored)
        return BraveOSINTEvidence(
            meta=CollectorMeta(collector=self.name),
            checked=True,
            queries=summary["queries"],
            top_hits=summary["top_hits"],
            observed_results=summary["observed_results"],
            all_results=summary["all_results"],
            source_counts=summary["source_counts"],
            score=summary["score"],
            risk_level=summary["risk_level"],
            summary=summary["summary"],
            notes=[] if scored else ["No high-signal Brave search results matched the security filter."],
        )

    def _empty_evidence(self, meta: CollectorMeta) -> BraveOSINTEvidence:
        return BraveOSINTEvidence(meta=meta)
