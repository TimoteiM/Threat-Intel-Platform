"""
Hybrid Analysis collector.

Supports URL/hash/file/domain observables and returns cached sandbox verdicts.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

import requests

from sqlalchemy.orm import Session

from app.collectors.base import BaseCollector
from app.db.session import sync_engine
from app.models.database import Artifact
from app.models.schemas import CollectorMeta, HybridAnalysisEvidence, HybridAnalysisItem
from app.services.anyrun_intelligence import build_anyrun_sandbox_intelligence
from app.services.anyrun_false_positive import apply_anyrun_msdw_false_positive_exclusion
from app.services.hybrid_analysis_service import lookup_hybrid_analysis


logger = logging.getLogger(__name__)
_MAX_ANYRUN_SCREENSHOT_BYTES = 12 * 1024 * 1024
_MAX_ANYRUN_SCREENSHOTS = 8


class HybridAnalysisCollector(BaseCollector):
    name = "hybrid_analysis"
    supported_types = frozenset({"domain", "url", "hash", "file"})

    def _collect(self) -> HybridAnalysisEvidence:
        evidence = HybridAnalysisEvidence()
        indicator_type = "url"
        indicator = self.domain
        file_bytes: bytes | None = None
        file_name: str | None = None
        submit_on_not_found = False

        if self.observable_type in {"hash", "file"}:
            indicator_type = "hash"
            # For uploaded file submissions (hash mode), fallback to quick-scan file
            # when hash lookup is not yet present in Hybrid.
            file_name, file_bytes = self._load_uploaded_file()
            submit_on_not_found = bool(file_bytes)
        elif self.observable_type == "domain":
            indicator_type = "url"
            indicator = f"https://{self.domain}"
            submit_on_not_found = True
        elif self.observable_type == "url":
            submit_on_not_found = True

        network_profile = self.external_context.get("network_profile") if isinstance(self.external_context, dict) else {}
        proxy_country = str((network_profile or {}).get("proxy_country") or "").strip() or None
        use_residential_proxy = bool((network_profile or {}).get("use_residential_proxy") or proxy_country)
        result = lookup_hybrid_analysis(
            indicator=indicator,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            submit_on_not_found=submit_on_not_found,
            # TI lookup must run first so existing MALICIOUS community reports are
            # trusted over a fresh sandbox that may return CLEAN (e.g. phishing pages
            # that require user interaction). sandbox_first would bypass TI entirely.
            sandbox_first=False,
            use_residential_proxy=use_residential_proxy,
            proxy_country=proxy_country,
        )

        self._refresh_anyrun_screenshot_metadata(result)
        self._download_anyrun_screenshots(result, item_index=0)
        for item_index, extra in enumerate(list(result.get("additional_items") or []), start=1):
            if isinstance(extra, dict):
                self._refresh_anyrun_screenshot_metadata(extra)
                self._download_anyrun_screenshots(extra, item_index=item_index)

        def _make_item(r: dict, *, is_primary: bool = True) -> HybridAnalysisItem:
            if str(((r.get("raw_summary") or {}).get("source") or "")).strip().lower() == "anyrun":
                r = apply_anyrun_msdw_false_positive_exclusion(r)
            raw = r.get("raw_summary") or {}
            # Tags live in raw_summary.tags (AnyRun community tags like "phishing", "credential-harvesting")
            _tags = list(raw.get("tags") or [])
            sandbox_intelligence = build_anyrun_sandbox_intelligence(r)
            return HybridAnalysisItem(
                checked=bool(r.get("checked")),
                indicator_type=str(r.get("indicator_type") or indicator_type),
                verdict=str(r.get("verdict") or "unknown"),
                provider_verdict=r.get("provider_verdict"),
                verdict_context=r.get("verdict_context") or raw.get("verdict_context") or {},
                analysis_id=r.get("analysis_id"),
                analysis_link=r.get("analysis_link"),
                threat_score=r.get("threat_score"),
                threat_names=list(r.get("threat_names") or []),
                tags=_tags,
                error=r.get("error"),
                cache_hit=r.get("cache_hit"),
                dynamic_io_summary=r.get("dynamic_io_summary") or {},
                raw_summary=raw,
                sandbox_intelligence=sandbox_intelligence,
                # domain_intelligence only on the primary row to avoid duplication
                domain_intelligence=r.get("domain_intelligence") or None if is_primary else None,
            )

        items = [_make_item(result, is_primary=True)]
        for extra in list(result.get("additional_items") or []):
            items.append(_make_item(extra, is_primary=False))

        evidence.items = items
        return evidence

    @staticmethod
    def _configured_anyrun_keys() -> list[str]:
        from app.config import get_settings

        settings = get_settings()
        return list(
            dict.fromkeys(
                str(key or "").strip()
                for key in (settings.anyrun_api_key, settings.anyrun_api_key_fallback)
                if str(key or "").strip()
            )
        )

    def _refresh_anyrun_screenshot_metadata(self, result: dict) -> None:
        """Repair cached results that predate original screenshot extraction."""
        raw = result.get("raw_summary") if isinstance(result, dict) else None
        if not isinstance(raw, dict) or str(raw.get("source") or "").strip().lower() != "anyrun":
            return
        existing = raw.get("screenshots") if isinstance(raw.get("screenshots"), list) else []
        if any(isinstance(shot, dict) and "/screens/" in str(shot.get("url") or "") for shot in existing):
            return
        analysis_id = str(result.get("analysis_id") or "").strip()
        if not analysis_id:
            return

        try:
            from anyrun.connectors import SandboxConnector
            from app.services.anyrun_service import _extract_screenshot_thumbnails
        except Exception:
            return

        for api_key in self._configured_anyrun_keys():
            try:
                with SandboxConnector.windows(api_key) as connector:
                    report = connector.get_analysis_report(analysis_id, report_format="json")
                report_data = (report or {}).get("data") or {}
                screenshots = _extract_screenshot_thumbnails(report_data, "")
                if screenshots:
                    raw["screenshots"] = screenshots
                    return
            except Exception:
                continue

    def _download_anyrun_screenshots(self, result: dict, *, item_index: int) -> None:
        """Fetch original ANY.RUN captures with API auth and store them locally."""
        raw = result.get("raw_summary") if isinstance(result, dict) else None
        if not isinstance(raw, dict) or str(raw.get("source") or "").strip().lower() != "anyrun":
            return

        screenshots = raw.get("screenshots")
        if not isinstance(screenshots, list):
            return

        api_keys = self._configured_anyrun_keys()
        if not api_keys:
            return

        for shot_index, shot in enumerate(screenshots[:_MAX_ANYRUN_SCREENSHOTS]):
            if not isinstance(shot, dict):
                continue
            source_url = str(shot.get("url") or "").strip()
            parsed = urlparse(source_url)
            if parsed.scheme != "https" or parsed.hostname != "content.any.run":
                continue

            image_bytes, extension = self._fetch_anyrun_screenshot(source_url, api_keys)
            if not image_bytes:
                continue

            artifact_name = f"anyrun_screenshot_{item_index + 1:02d}_{shot_index + 1:02d}.{extension}"
            self._store_artifact(artifact_name, image_bytes)
            shot["artifact_name"] = f"{self.name}_{artifact_name}"
            shot["quality"] = "original"

    @staticmethod
    def _fetch_anyrun_screenshot(source_url: str, api_keys: list[str]) -> tuple[bytes | None, str]:
        for api_key in api_keys:
            try:
                authorization = api_key if api_key.lower().startswith(("api-key ", "basic ")) else f"API-KEY {api_key}"
                with requests.get(
                    source_url,
                    headers={"Authorization": authorization, "x-anyrun-connector": "Threat-Intel-Platform"},
                    timeout=25,
                    stream=True,
                ) as response:
                    if response.status_code != 200:
                        continue
                    data = bytearray()
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        data.extend(chunk)
                        if len(data) > _MAX_ANYRUN_SCREENSHOT_BYTES:
                            raise ValueError("ANY.RUN screenshot exceeds size limit")
                    payload = bytes(data)
                    content_type = str(response.headers.get("Content-Type") or "").lower()
                    if payload.startswith(b"\xff\xd8\xff"):
                        return payload, "jpeg"
                    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
                        return payload, "png"
                    if payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
                        return payload, "webp"
                    if content_type.startswith("image/"):
                        extension = content_type.split("/", 1)[1].split(";", 1)[0]
                        return payload, "jpeg" if extension == "jpg" else extension
            except Exception as exc:
                logger.warning("Failed to download ANY.RUN original screenshot: %s", exc)
        return None, "jpeg"

    def _empty_evidence(self, meta: CollectorMeta) -> HybridAnalysisEvidence:
        return HybridAnalysisEvidence(meta=meta)

    def _load_uploaded_file(self) -> tuple[str | None, bytes | None]:
        if not self.file_artifact_id:
            return None, None
        try:
            with Session(sync_engine) as db:
                art = db.get(Artifact, self.file_artifact_id)
                if not art:
                    return None, None
                path = Path(str(art.storage_path or "")).expanduser()
                if not path.is_absolute():
                    path = Path("/app") / path
                if not path.exists() or not path.is_file():
                    return art.artifact_name, None
                return art.artifact_name, path.read_bytes()
        except Exception:
            return None, None
