"""
Hybrid Analysis API integration with caching and retry controls.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import LookupCache

HYBRID_CACHE_TTL_HOURS = 24
DEFAULT_BASE_URL = "https://hybrid-analysis.com/api/v2"


def lookup_hybrid_analysis(
    *,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None = None,
    file_name: str | None = None,
    submit_on_not_found: bool = False,
) -> dict[str, Any]:
    """
    indicator_type: "url" | "hash"
    """
    key = _cache_key(indicator=indicator, indicator_type=indicator_type)
    cached = _cache_get(key)
    if cached:
        # Avoid persisting stale "checked but unknown" hash results for full TTL.
        # Hybrid hash search response formats changed, and older cached entries may
        # contain incomplete UNKNOWN verdicts even for known malicious hashes.
        cached_verdict = str(cached.get("verdict") or "").strip().lower()
        if indicator_type == "hash" and cached_verdict == "unknown":
            cached = None
        # For URL lookups, stale UNKNOWN entries with no analysis identifier are
        # not useful for analysts and should be retried.
        if indicator_type == "url" and cached_verdict == "unknown" and not cached.get("analysis_id"):
            cached = None
    if cached:
        out = dict(cached)
        out["cache_hit"] = True
        return out

    settings = get_settings()
    api_key = (getattr(settings, "hybrid_analysis_api_key", "") or "").strip()
    base_url = _normalize_base_url((getattr(settings, "hybrid_analysis_base_url", "") or "").strip() or DEFAULT_BASE_URL)
    if not api_key:
        return {"checked": False, "verdict": "unknown", "error": "HYBRID_ANALYSIS_API_KEY not configured", "cache_hit": False}

    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }
    result = _retry_lookup(base_url=base_url, headers=headers, indicator=indicator, indicator_type=indicator_type)
    if (
        indicator_type == "hash"
        and submit_on_not_found
        and file_bytes
        and not bool(result.get("checked"))
        and "not found" in str(result.get("error") or "").lower()
    ):
        try:
            submitted = _submit_sandbox_file(
                base_url=base_url,
                headers=headers,
                file_bytes=file_bytes,
                file_name=file_name or "sample.bin",
                environment_id=int(getattr(settings, "hybrid_analysis_environment_id", 160) or 160),
            )
            if submitted.get("checked"):
                result = submitted
            else:
                result = submitted
        except Exception as exc:
            exc_text = str(exc)
            if "validation_errors" in exc_text and "field': 'id'" in exc_text:
                friendly = (
                    "Hybrid file submission is not supported for this API access (hash lookup only). "
                    "Use VT/URLScan/static evidence for this sample."
                )
            else:
                friendly = f"Hybrid file submission unavailable: {exc}"
            result = {
                "checked": False,
                "indicator_type": "hash",
                "hash": indicator,
                "verdict": "unknown",
                "error": friendly,
                "raw_summary": {
                    "submission_mode": "submit-file",
                    "hint": "Hash lookup succeeded path exists; file submit endpoints may be unavailable for this API tier/base URL.",
                },
            }
    result["cache_hit"] = False
    if result.get("checked"):
        _cache_set(key, result, source="hybrid_analysis", ttl_hours=HYBRID_CACHE_TTL_HOURS)
    return result


def _retry_lookup(*, base_url: str, headers: dict[str, str], indicator: str, indicator_type: str) -> dict[str, Any]:
    attempts = 3
    delay = 1.0
    last_error = ""
    for i in range(attempts):
        try:
            if indicator_type == "hash":
                return _lookup_hash(base_url, headers, indicator)
            return _lookup_url(base_url, headers, indicator)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            detail = ""
            try:
                body = exc.response.json() if exc.response is not None else {}
                if isinstance(body, dict):
                    detail = str(body.get("message") or body.get("error") or "").strip()
            except Exception:
                detail = ""
            if detail:
                last_error = f"HTTP {status}: {detail}"
            else:
                last_error = f"HTTP {status}: {exc}"
            if status in {429, 500, 502, 503, 504} and i < attempts - 1:
                time.sleep(delay)
                delay *= 2.0
                continue
            break
        except Exception as exc:
            last_error = str(exc)
            if i < attempts - 1:
                time.sleep(delay)
                delay *= 2.0
                continue
            break
    return {"checked": False, "verdict": "unknown", "error": last_error or "Hybrid Analysis lookup failed"}


def _lookup_hash(base_url: str, headers: dict[str, str], hash_value: str) -> dict[str, Any]:
    resp = requests.get(
        f"{base_url}/search/hash",
        headers=headers,
        params={"hash": hash_value},
        timeout=20,
    )
    if resp.status_code == 404:
        return {
            "checked": False,
            "indicator_type": "hash",
            "hash": hash_value,
            "verdict": "unknown",
            "error": "Requested hash not found",
        }
    resp.raise_for_status()
    data = resp.json() or []
    best: dict[str, Any] = {}
    if isinstance(data, list) and data:
        # Legacy/alternate response format
        best = data[0] if isinstance(data[0], dict) else {}
    elif isinstance(data, dict):
        # Common format:
        # {"sha256s":[...], "reports":[{"id":..., "verdict":..., ...}]}
        reports = data.get("reports")
        if isinstance(reports, list) and reports:
            best = reports[0] if isinstance(reports[0], dict) else {}
        else:
            for key in ("result", "results", "items", "data"):
                arr = data.get(key)
                if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                    best = arr[0]
                    break
    if not best:
        return {
            "checked": False,
            "indicator_type": "hash",
            "hash": hash_value,
            "verdict": "unknown",
            "error": "Hash lookup returned no report entries",
            "raw_summary": {"response_keys": list(data.keys()) if isinstance(data, dict) else None},
        }
    verdict = _normalize_verdict(best.get("verdict") or best.get("threat_score"))
    return {
        "checked": True,
        "indicator_type": "hash",
        "hash": hash_value,
        "verdict": verdict,
        "threat_score": best.get("threat_score") or best.get("score"),
        "analysis_id": best.get("id") or best.get("sha256"),
        "environment": best.get("environment_description") or best.get("environment"),
        "raw_summary": {
            "type_short": best.get("type_short"),
            "submit_name": best.get("submit_name"),
            "vx_family": best.get("vx_family"),
            "state": best.get("state"),
        },
    }


def _submit_sandbox_file(
    *,
    base_url: str,
    headers: dict[str, str],
    file_bytes: bytes,
    file_name: str,
    environment_id: int,
) -> dict[str, Any]:
    files = {"file": (file_name, file_bytes, "application/octet-stream")}
    data = {"environment_id": str(environment_id)}
    resp = requests.post(
        f"{base_url}/submit/file",
        headers=headers,
        files=files,
        data=data,
        timeout=60,
    )
    if resp.status_code >= 400:
        detail = _extract_http_detail(resp)
        raise RuntimeError(f"HTTP {resp.status_code}: {detail or resp.text[:300]}")
    payload = resp.json() or {}
    qid = str(payload.get("id") or payload.get("job_id") or payload.get("analysis_id") or "").strip()
    sha256 = str(payload.get("sha256") or "").strip().lower()
    latest = payload

    # Poll sandbox report state until terminal.
    if qid:
        latest = _poll_report_state(base_url=base_url, headers=headers, report_id=qid)
        if not sha256:
            sha256 = str(latest.get("sha256") or "").strip().lower()

    # If we got a SHA, fetch authoritative verdict via hash lookup.
    if sha256:
        looked_up = _lookup_hash(base_url, headers, sha256)
        if looked_up.get("checked"):
            looked_up["raw_summary"] = {
                **(looked_up.get("raw_summary") or {}),
                "submission_mode": "submit-file",
                "report_id": qid or None,
            }
            return looked_up

    verdict = _normalize_verdict(
        latest.get("verdict")
        or latest.get("verdict_human")
        or latest.get("threat_score")
        or latest.get("score")
    )
    return {
        "checked": bool(latest),
        "indicator_type": "hash",
        "hash": sha256 or None,
        "verdict": verdict,
        "threat_score": latest.get("threat_score") or latest.get("score"),
        "analysis_id": qid or latest.get("id"),
        "raw_summary": {
            "submission_mode": "submit-file",
            "finished": latest.get("finished"),
            "report_id": qid or None,
        },
    }


def _extract_http_detail(resp: requests.Response) -> str:
    try:
        payload = resp.json()
    except Exception:
        return ""
    if isinstance(payload, dict):
        msg = str(payload.get("message") or payload.get("error") or "").strip()
        validation = payload.get("validation_errors")
        if validation:
            return f"{msg}; validation_errors={validation}"
        return msg
    return ""


def _lookup_url(base_url: str, headers: dict[str, str], url: str) -> dict[str, Any]:
    # 1) Search existing analyses first (fast, no forced detonation).
    search_resp = requests.post(
        f"{base_url}/search/terms",
        headers=headers,
        data={"url": url},
        timeout=25,
    )
    search_resp.raise_for_status()
    search_payload = search_resp.json() or []
    best = _best_url_result(search_payload)

    # 2) If no prior result exists, run sandbox URL submission and fetch report.
    if not best:
        settings = get_settings()
        submit_resp = requests.post(
            f"{base_url}/submit/url",
            headers=headers,
            data={
                "environment_id": str(int(getattr(settings, "hybrid_analysis_environment_id", 160) or 160)),
                "url": url,
            },
            timeout=30,
        )
        submit_resp.raise_for_status()
        submit_payload = submit_resp.json() or {}
        report_id = str(
            submit_payload.get("id")
            or submit_payload.get("job_id")
            or submit_payload.get("analysis_id")
            or ""
        ).strip()
        if report_id:
            _poll_report_state(base_url=base_url, headers=headers, report_id=report_id)
            summary = _get_report_summary(base_url=base_url, headers=headers, report_id=report_id)
            if isinstance(summary, dict):
                summary = {
                    **summary,
                    "id": summary.get("id") or report_id,
                }
            best = _best_url_result(summary or submit_payload)
        else:
            best = _best_url_result(submit_payload)

    if not best:
        return {
            "checked": False,
            "indicator_type": "url",
            "url": url,
            "verdict": "unknown",
            "error": "No Hybrid Analysis URL result available",
        }

    verdict = _normalize_verdict(
        best.get("verdict")
        or best.get("classification")
        or best.get("threat_level")
        or best.get("threat_score")
        or best.get("score")
    )
    return {
        "checked": True,
        "indicator_type": "url",
        "url": url,
        "verdict": verdict,
        "threat_score": best.get("threat_score") or best.get("score"),
        "analysis_id": best.get("id") or best.get("analysis_id") or best.get("job_id") or best.get("sha256"),
        "submit_name": best.get("submit_name") or best.get("url") or best.get("submission_type"),
        "url_scan_id": best.get("sha256") or best.get("analysis_id") or best.get("job_id"),
        "dynamic_io_summary": {
            "domains": best.get("domains") or [],
            "hosts": best.get("hosts") or [],
            "mitre_attcks": best.get("mitre_attcks") or [],
        },
        "raw_summary": {
            "status": best.get("status"),
            "message": best.get("message"),
            "finished": best.get("finished"),
        },
    }


def _best_url_result(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        return next((x for x in payload if isinstance(x, dict)), {}) or {}
    if isinstance(payload, dict):
        for key in ("result", "results", "items", "data", "reports"):
            arr = payload.get(key)
            if isinstance(arr, list):
                cand = next((x for x in arr if isinstance(x, dict)), None)
                if isinstance(cand, dict):
                    return cand
        report_like_keys = {
            "id",
            "job_id",
            "sha256",
            "verdict",
            "threat_score",
            "classification",
            "state",
            "submission_type",
        }
        if any(k in payload for k in report_like_keys):
            return payload
        return {}
    return {}


def _poll_report_state(*, base_url: str, headers: dict[str, str], report_id: str, max_wait_seconds: int = 90) -> dict[str, Any]:
    latest: dict[str, Any] = {}
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        resp = requests.get(
            f"{base_url}/report/{report_id}/state",
            headers=headers,
            timeout=20,
        )
        if resp.status_code >= 400:
            detail = _extract_http_detail(resp)
            raise RuntimeError(f"HTTP {resp.status_code}: {detail or resp.text[:300]}")
        payload = resp.json() or {}
        latest = payload if isinstance(payload, dict) else {}
        state = str(latest.get("state") or latest.get("status") or "").upper()
        if state in {"SUCCESS", "ERROR"}:
            return latest
        time.sleep(2)
    return latest


def _get_report_summary(*, base_url: str, headers: dict[str, str], report_id: str) -> dict[str, Any]:
    resp = requests.get(
        f"{base_url}/report/{report_id}/summary",
        headers=headers,
        timeout=20,
    )
    if resp.status_code >= 400:
        detail = _extract_http_detail(resp)
        raise RuntimeError(f"HTTP {resp.status_code}: {detail or resp.text[:300]}")
    payload = resp.json() or {}
    if isinstance(payload, dict):
        return payload
    return {}


def _normalize_verdict(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"malicious", "suspicious", "clean", "benign"}:
        return "clean" if text == "benign" else text
    try:
        score = float(value)
        if score >= 75:
            return "malicious"
        if score >= 35:
            return "suspicious"
        return "clean"
    except Exception:
        return "unknown"


def _cache_key(*, indicator: str, indicator_type: str) -> str:
    raw = f"hybrid:{indicator_type}:{str(indicator).strip()}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return f"hybrid:{indicator_type}:{digest}"


def _cache_get(key: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    with Session(sync_engine) as db:
        row = db.execute(
            select(LookupCache).where(
                LookupCache.cache_key == key,
                LookupCache.expires_at > now,
            )
        ).scalar_one_or_none()
        if not row or not isinstance(row.cache_value, dict):
            return None
        return dict(row.cache_value)


def _cache_set(key: str, value: dict[str, Any], *, source: str, ttl_hours: int) -> None:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=max(1, ttl_hours))
    with Session(sync_engine) as db:
        row = db.execute(
            select(LookupCache).where(LookupCache.cache_key == key)
        ).scalar_one_or_none()
        if row:
            row.cache_value = value
            row.source = source
            row.expires_at = expires_at
        else:
            db.add(
                LookupCache(
                    cache_key=key,
                    cache_value=value,
                    source=source,
                    expires_at=expires_at,
                )
            )
        db.commit()


def _normalize_base_url(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return DEFAULT_BASE_URL
    # Hybrid submission/search endpoints can return 404 on www host while
    # equivalent non-www host works for the same API key.
    if "://www.hybrid-analysis.com" in base:
        base = base.replace("://www.hybrid-analysis.com", "://hybrid-analysis.com")
    return base
