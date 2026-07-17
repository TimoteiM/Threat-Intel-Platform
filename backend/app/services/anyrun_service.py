"""
ANY.RUN integration (TI lookup + sandbox analysis).

Primary strategy:
1) Query TI lookup first (fast, no detonation) for URL/hash.
2) If not found and permitted, submit sandbox task (URL/file).
"""

from __future__ import annotations

import logging
import queue
import re
import threading
import time
from contextlib import ExitStack
from inspect import Parameter, signature
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from app.config import get_settings
from app.services.provider_usage_metrics import record_provider_request

# ── AnyRun sandbox scheduling ─────────────────────────────────────────────────
#
# Problem: N simultaneous investigations each try to submit a sandbox task.
# AnyRun's per-account parallel limit rejects all but one per account, causing
# 8×10 s exponential backoff loops (~250 s wasted per investigation).
#
# Strategy — key pool queue:
#   A queue is pre-loaded with all configured API keys (one entry per key).
#   Each sandbox submission checks out a key from the queue, uses it, then
#   returns it when done. queue.get() blocks until ANY key is available,
#   so the caller always gets the first free key — regardless of which one.
#
#   With 2 keys and 3 simultaneous investigations (A, B, C — different domains):
#     • Inv-A: gets key1 immediately, submits domain A  ┐ parallel
#     • Inv-B: gets key2 immediately, submits domain B  ┘
#     • Inv-C: blocks on queue.get() — waits for whichever of key1/key2 is
#              returned first, then submits domain C with that key.
#
#   With 3 investigations of the SAME domain (A, A, A):
#     • Inv-1: gets key1, submits, caches result, returns key1.
#     • Inv-2: gets key2, submits in parallel, caches result, returns key2.
#     • Inv-3: blocks → gets key1 (whichever returns first) → cache hit →
#              returns immediately without submitting to AnyRun at all.
#
# All state is process-scoped (threading) — correct for worker_pool="threads".

_ANYRUN_KEY_POOL:       "queue.Queue[str] | None" = None
_ANYRUN_POOL_LOCK:      threading.Lock = threading.Lock()
_ANYRUN_POOL_KEY_COUNT: int = 0  # total keys ever added; 0 means "not configured"
_ANYRUN_POOL_KEYS:      tuple[str, ...] = ()

_ANYRUN_CACHE_LOCK   = threading.Lock()
_ANYRUN_RESULT_CACHE: dict[str, tuple[float, dict]] = {}  # key → (ts, result)
_ANYRUN_CACHE_TTL    = 600  # seconds — 10 minutes

_ANYRUN_HTML_THREAT_MARKERS: tuple[tuple[str, str], ...] = (
    ("clickfix", "clickfix"),
    ("clearfake", "clearfake"),
    ("phishing", "phishing"),
    ("credential harvesting", "credential-harvesting"),
    ("credential theft", "credential-theft"),
    ("exploit-kit", "exploit-kit"),
    ("exploit kit", "exploit-kit"),
    ("obfuscated-js", "obfuscated-js"),
    ("obfuscated js", "obfuscated-js"),
    ("etherhiding", "etherhiding"),
    ("tdsshop", "tdsshop"),
    ("fake captcha", "fake-captcha"),
    ("fake-captcha", "fake-captcha"),
)


def _get_key_pool() -> "queue.Queue[str]":
    """Return (and lazily initialise) the shared API key pool queue."""
    global _ANYRUN_KEY_POOL, _ANYRUN_POOL_KEY_COUNT, _ANYRUN_POOL_KEYS
    keys = tuple(_configured_anyrun_api_keys(get_settings()))
    if _ANYRUN_KEY_POOL is not None and _ANYRUN_POOL_KEYS == keys:
        return _ANYRUN_KEY_POOL
    with _ANYRUN_POOL_LOCK:
        if _ANYRUN_KEY_POOL is not None and _ANYRUN_POOL_KEYS == keys:
            return _ANYRUN_KEY_POOL
        pool: queue.Queue[str] = queue.Queue()
        for k in keys:
            pool.put(k)
        _ANYRUN_POOL_KEY_COUNT = len(keys)
        _ANYRUN_POOL_KEYS = keys
        _ANYRUN_KEY_POOL = pool
    return _ANYRUN_KEY_POOL


def lookup_anyrun(
    *,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None = None,
    file_name: str | None = None,
    submit_on_not_found: bool = False,
    sandbox_first: bool = False,
    use_residential_proxy: bool = False,
    proxy_country: str | None = None,
) -> dict[str, Any]:
    record_provider_request("anyrun")
    settings = get_settings()
    api_keys = _configured_anyrun_api_keys(settings)
    api_key = api_keys[0] if api_keys else ""
    fallback_api_key = api_keys[1] if len(api_keys) > 1 else ""
    sandbox_os = str(getattr(settings, "anyrun_sandbox_os", "windows") or "windows").strip().lower()
    privacy_type = str(getattr(settings, "anyrun_privacy_type", "owner") or "owner").strip().lower()
    timeout_url_domain = int(getattr(settings, "anyrun_timeout_url_domain_seconds", 45) or 45)
    timeout_file_hash = int(getattr(settings, "anyrun_timeout_file_hash_seconds", 90) or 90)
    sandbox_analysis_timeout = int(getattr(settings, "anyrun_url_sandbox_analysis_timeout", 120) or 120)
    if not api_key:
        return _error(indicator_type, "ANYRUN_API_KEY not configured")

    value = str(indicator or "").strip()
    if not value:
        return _error(indicator_type, "Empty indicator")

    try:
        from anyrun.connectors import LookupConnector, SandboxConnector
    except Exception as exc:
        return _error(indicator_type, f"anyrun-sdk unavailable: {exc}")

    sandbox_timeout = timeout_file_hash if indicator_type in {"hash", "file"} else timeout_url_domain
    can_run_sandbox_first = bool(
        sandbox_first
        and submit_on_not_found
        and (
            indicator_type == "url"
            or indicator_type == "file"
            or (indicator_type == "hash" and file_bytes)
        )
    )

    if can_run_sandbox_first:
        sandbox_result = _run_anyrun_sandbox_with_fallback(
            SandboxConnector,
            api_key=api_key,
            fallback_api_key=fallback_api_key,
            sandbox_os=sandbox_os,
            privacy_type=privacy_type,
            indicator=value,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            timeout_seconds=sandbox_timeout,
            use_residential_proxy=use_residential_proxy,
            proxy_country=proxy_country,
        )
        if sandbox_result.get("checked"):
            return sandbox_result

    require_domain_intel = _requires_domain_intelligence_for_indicator(
        indicator=value,
        indicator_type=indicator_type,
        submit_on_not_found=submit_on_not_found,
    )

    # Closure initialised here so it's available to the sandbox-fallback path (path 2) as well.
    domain_intel: dict[str, Any] | None = None

    def _attach_domain_intel(result: dict[str, Any]) -> dict[str, Any]:
        if domain_intel is None:
            return result
        r = dict(result)
        r["domain_intelligence"] = domain_intel
        return r

    # 1) TI lookup + sandbox run in parallel for URLs so both rows are always available.
    #    For hashes, TI only (sandbox needs file bytes which may be absent).
    if indicator_type in {"url", "hash"}:
        import concurrent.futures as _cf

        # Extract hostname for domain TI lookup (URL only)
        _hostname = ""
        if indicator_type == "url":
            try:
                _hostname = (urlparse(value).hostname or "").strip().lower()
            except Exception:
                pass

        _can_sandbox = bool(
            submit_on_not_found
            and (indicator_type == "url" or (indicator_type == "hash" and file_bytes))
        )

        _workers = 1 + (1 if _hostname else 0) + (1 if _can_sandbox else 0)
        _executor = _cf.ThreadPoolExecutor(max_workers=_workers)
        try:
            # Always run URL/hash TI lookup
            _ti_future = _executor.submit(
                _lookup_intelligence,
                LookupConnector, SandboxConnector, api_key,
                indicator=value, indicator_type=indicator_type, sandbox_os=sandbox_os,
            )
            # Domain TI lookup in parallel (URL only)
            _domain_future = (
                _executor.submit(
                    _lookup_intelligence,
                    LookupConnector, SandboxConnector, api_key,
                    indicator=_hostname, indicator_type="domain", sandbox_os=sandbox_os,
                ) if _hostname else None
            )
            # Sandbox also runs in parallel (URL only, not hash — hash sandbox needs file bytes
            # and is handled below when TI returns not-found)
            _sandbox_future = (
                _executor.submit(
                    _run_anyrun_sandbox_with_fallback,
                    SandboxConnector,
                    api_key=api_key,
                    fallback_api_key=fallback_api_key,
                    sandbox_os=sandbox_os,
                    privacy_type=privacy_type,
                    indicator=value,
                    indicator_type=indicator_type,
                    file_bytes=file_bytes,
                    file_name=file_name,
                    timeout_seconds=sandbox_timeout,
                    use_residential_proxy=use_residential_proxy,
                    proxy_country=proxy_country,
                ) if _can_sandbox and indicator_type == "url" else None
            )

            lookup_result = _ti_future.result(timeout=sandbox_timeout + 10)

            if _domain_future is not None:
                try:
                    _di = _domain_future.result(timeout=timeout_url_domain)
                    if isinstance(_di, dict) and (_di.get("checked") or require_domain_intel):
                        _di = dict(_di)
                        _di["hostname"] = _hostname  # carried so frontend can label the section
                        domain_intel = _di
                except Exception as exc:
                    if require_domain_intel:
                        domain_intel = {
                            "checked": False,
                            "indicator_type": "domain",
                            "verdict": "unknown",
                            "error": f"Any.Run domain intelligence lookup failed: {exc}",
                            "hostname": _hostname,
                            "raw_summary": {"source": "anyrun", "mode": "lookup"},
                        }

            sandbox_result: dict[str, Any] | None = None
            if _sandbox_future is not None:
                try:
                    # Use the actual sandbox analysis timeout (120s) + buffer, not the
                    # collector-level sandbox_timeout (45s) which is far too short for live detonation.
                    _sr = _sandbox_future.result(timeout=sandbox_analysis_timeout + 30)
                    if isinstance(_sr, dict):
                        sandbox_result = _sr
                except Exception:
                    pass
        finally:
            _executor.shutdown(wait=False)

        logger.info(
            "AnyRun branch outcomes for %s: lookup_checked=%s lookup_verdict=%s domain_checked=%s sandbox_checked=%s sandbox_error=%s",
            value,
            bool(lookup_result.get("checked")),
            str(lookup_result.get("verdict") or "").strip().lower(),
            bool((domain_intel or {}).get("checked")),
            bool((sandbox_result or {}).get("checked")),
            str((sandbox_result or {}).get("error") or "").strip(),
        )

        if lookup_result.get("checked"):
            lookup_verdict = str(lookup_result.get("verdict") or "").strip().lower()
            lookup_analysis_id = str(lookup_result.get("analysis_id") or "").strip()
            lookup_is_malicious = lookup_verdict == "malicious"
            force_hash_sandbox = bool(indicator_type == "hash" and submit_on_not_found and file_bytes)

            if sandbox_result is not None and sandbox_result.get("checked"):
                # Both TI and sandbox completed — decide which is primary.
                # TI MALICIOUS takes precedence; sandbox provides behavioral context.
                if lookup_is_malicious:
                    primary = _attach_domain_intel(lookup_result)
                    primary = dict(primary)
                    primary["additional_items"] = [dict(sandbox_result)]
                else:
                    # Sandbox is primary, but conflicting clean lookup data means
                    # the analyst-facing verdict must explain whether concrete
                    # behavior supports the provider's task verdict.
                    if (sandbox_result.get("raw_summary") or {}).get("api_key_slot") != "fallback":
                        sandbox_result = _reconcile_anyrun_sandbox_lookup_verdict(sandbox_result, lookup_result)
                    raw = sandbox_result.get("raw_summary") or {}
                    sandbox_result["raw_summary"] = {
                        **(raw if isinstance(raw, dict) else {}),
                        "lookup_fallback_used": True,
                        "lookup_summary": (lookup_result.get("raw_summary") or {}),
                    }
                    primary = _attach_domain_intel(sandbox_result)
                    if lookup_result.get("checked"):
                        primary = dict(primary)
                        primary["additional_items"] = [dict(lookup_result)]
                return primary

            # Sandbox didn't run or failed — handle TI result alone
            if lookup_is_malicious:
                primary = _attach_domain_intel(lookup_result)
                if isinstance(sandbox_result, dict):
                    primary = dict(primary)
                    primary["additional_items"] = [dict(sandbox_result)]
                return primary

            needs_enriched_sandbox = (
                _is_sparse_lookup_result(lookup_result)
                or (indicator_type == "url" and not lookup_analysis_id)
                or force_hash_sandbox
            )
            if submit_on_not_found and indicator_type == "hash" and needs_enriched_sandbox:
                if not file_bytes:
                    return _attach_domain_intel(lookup_result)
                # Hash sandbox (needs file bytes — wasn't run in parallel above)
                hash_sandbox = _run_anyrun_sandbox_with_fallback(
                    SandboxConnector,
                    api_key=api_key, fallback_api_key=fallback_api_key,
                    sandbox_os=sandbox_os, privacy_type=privacy_type,
                    indicator=value, indicator_type=indicator_type,
                    file_bytes=file_bytes, file_name=file_name,
                    timeout_seconds=sandbox_timeout,
                    use_residential_proxy=use_residential_proxy,
                    proxy_country=proxy_country,
                )
                if hash_sandbox.get("checked"):
                    raw = hash_sandbox.get("raw_summary") or {}
                    hash_sandbox["raw_summary"] = {
                        **(raw if isinstance(raw, dict) else {}),
                        "lookup_fallback_used": True,
                        "lookup_summary": (lookup_result.get("raw_summary") or {}),
                    }
                    primary = _attach_domain_intel(hash_sandbox)
                    if lookup_result.get("checked"):
                        primary = dict(primary)
                        primary["additional_items"] = [dict(lookup_result)]
                    return primary
                if _is_deferred_anyrun_sandbox_error(hash_sandbox.get("error")):
                    lookup_result = dict(lookup_result)
                    raw = lookup_result.get("raw_summary") or {}
                    lookup_result["raw_summary"] = {
                        **(raw if isinstance(raw, dict) else {}),
                        "source": "anyrun", "mode": "lookup_deferred",
                        "sandbox_deferred": True,
                        "sandbox_error": str(hash_sandbox.get("error") or "").strip(),
                    }
                    return _attach_domain_intel(lookup_result)
                return _attach_domain_intel(hash_sandbox)

            if (
                submit_on_not_found
                and indicator_type == "url"
                and needs_enriched_sandbox
                and isinstance(sandbox_result, dict)
                and not sandbox_result.get("checked")
            ):
                sandbox_error = str(sandbox_result.get("error") or "").strip()
                if _is_deferred_anyrun_sandbox_error(sandbox_error):
                    lookup_result = dict(lookup_result)
                    raw = lookup_result.get("raw_summary") or {}
                    lookup_result["raw_summary"] = {
                        **(raw if isinstance(raw, dict) else {}),
                        "source": "anyrun",
                        "mode": "lookup_deferred",
                        "sandbox_deferred": True,
                        "sandbox_error": sandbox_error,
                    }
                    return _attach_domain_intel(lookup_result)
                return _attach_domain_intel(sandbox_result)

            primary = _attach_domain_intel(lookup_result)
            if isinstance(sandbox_result, dict) and not sandbox_result.get("checked"):
                primary = dict(primary)
                primary["additional_items"] = [dict(sandbox_result)]
            return primary

        not_found = "not found" in str(lookup_result.get("error") or "").lower() or "no info" in str(lookup_result.get("error") or "").lower()
        if not submit_on_not_found or (indicator_type == "hash" and not file_bytes):
            # Reuse parallel sandbox result if available, otherwise return TI-only result
            if sandbox_result is not None:
                return _attach_domain_intel(sandbox_result)
            return _attach_domain_intel(lookup_result)
        if not not_found:
            # TI returned an error that isn't "not found" — reuse sandbox if available
            if sandbox_result is not None:
                return _attach_domain_intel(sandbox_result)
            return _attach_domain_intel(lookup_result)

        # TI said "not found" — reuse the already-collected parallel sandbox result
        # instead of submitting a redundant second sandbox task.
        if sandbox_result is not None:
            return _attach_domain_intel(sandbox_result)

    # 2) Sandbox submission fallback (domain observable_type or URL genuinely not yet run)
    return _attach_domain_intel(
        _run_anyrun_sandbox_with_fallback(
            SandboxConnector,
            api_key=api_key,
            fallback_api_key=fallback_api_key,
            sandbox_os=sandbox_os,
            privacy_type=privacy_type,
            indicator=value,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            timeout_seconds=sandbox_timeout,
            use_residential_proxy=use_residential_proxy,
            proxy_country=proxy_country,
        )
    )


def _requires_domain_intelligence_for_indicator(
    *,
    indicator: str,
    indicator_type: str,
    submit_on_not_found: bool,
) -> bool:
    if indicator_type != "url" or not submit_on_not_found:
        return False
    try:
        from urllib.parse import urlparse as _urlparse

        parsed = _urlparse(str(indicator or "").strip())
    except Exception:
        return False

    hostname = str(parsed.hostname or "").strip().lower()
    path = str(parsed.path or "").strip()
    return bool(hostname and "." in hostname and path in {"", "/"} and not parsed.params and not parsed.query and not parsed.fragment)


def _anyrun_cache_get(cache_key: str) -> dict | None:
    """Return a cached sandbox result if still fresh, else None."""
    with _ANYRUN_CACHE_LOCK:
        entry = _ANYRUN_RESULT_CACHE.get(cache_key)
        if entry and (time.time() - entry[0]) < _ANYRUN_CACHE_TTL:
            return entry[1]
        if entry:
            del _ANYRUN_RESULT_CACHE[cache_key]  # evict stale
    return None


def _anyrun_cache_set(cache_key: str, result: dict) -> None:
    """Store a sandbox result in the cache."""
    with _ANYRUN_CACHE_LOCK:
        _ANYRUN_RESULT_CACHE[cache_key] = (time.time(), result)


def _anyrun_cache_evict(cache_key: str) -> None:
    """Remove a single entry from the in-memory cache."""
    with _ANYRUN_CACHE_LOCK:
        _ANYRUN_RESULT_CACHE.pop(cache_key, None)


def _run_anyrun_sandbox_with_fallback(
    sandbox_connector_cls: Any,
    *,
    api_key: str,
    fallback_api_key: str,
    sandbox_os: str,
    privacy_type: str,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None,
    file_name: str | None,
    timeout_seconds: int,
    use_residential_proxy: bool = False,
    proxy_country: str | None = None,
) -> dict[str, Any]:
    normalized_proxy_country = _normalize_anyrun_proxy_country(proxy_country)
    use_residential_proxy = bool(use_residential_proxy or normalized_proxy_country)
    cache_key    = (
        f"{indicator_type}:{indicator}:{sandbox_os}:{privacy_type}:"
        f"{api_key}:{fallback_api_key}:{normalized_proxy_country}:{id(_run_sandbox)}"
    )
    gate_timeout = int(timeout_seconds or 60) + 120
    cache_enabled = getattr(_run_sandbox, "__module__", "") == __name__

    # ── 1. Fast path: cache hit → no pool checkout needed ────────────────────
    if cache_enabled:
        cached = _anyrun_cache_get(cache_key)
        if cached is not None:
            logger.info("AnyRun cache hit for %s — skipping submission", indicator)
            return cached

    if not cache_enabled:
        sandbox_result = _run_sandbox(
            sandbox_connector_cls=sandbox_connector_cls,
            api_key=api_key,
            sandbox_os=sandbox_os,
            privacy_type=privacy_type,
            indicator=indicator,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            timeout_seconds=timeout_seconds,
            use_residential_proxy=use_residential_proxy,
            proxy_country=normalized_proxy_country,
        )
        raw = sandbox_result.get("raw_summary") or {}
        sandbox_result["raw_summary"] = {
            **(raw if isinstance(raw, dict) else {}),
            "api_key_slot": "primary",
        }
        if fallback_api_key and not sandbox_result.get("checked") and _is_deferred_anyrun_sandbox_error(sandbox_result.get("error")):
            fallback_result = _run_sandbox(
                sandbox_connector_cls=sandbox_connector_cls,
                api_key=fallback_api_key,
                sandbox_os=sandbox_os,
                privacy_type=privacy_type,
                indicator=indicator,
                indicator_type=indicator_type,
                file_bytes=file_bytes,
                file_name=file_name,
                timeout_seconds=timeout_seconds,
                use_residential_proxy=use_residential_proxy,
                proxy_country=normalized_proxy_country,
            )
            raw = fallback_result.get("raw_summary") or {}
            fallback_result["raw_summary"] = {
                **(raw if isinstance(raw, dict) else {}),
                "api_key_slot": "fallback",
            }
            if fallback_result.get("checked"):
                return fallback_result
            if _is_deferred_anyrun_sandbox_error(fallback_result.get("error")):
                return _merge_deferred_sandbox_errors(sandbox_result, fallback_result)
        return sandbox_result

    # ── 2. Check out a key from the pool (blocks until one is free) ──────────
    # Initialise pool first; _ANYRUN_POOL_KEY_COUNT reflects how many keys were
    # ever configured — a count of 0 means no keys at all (different from "all
    # keys temporarily checked out by other investigations").
    pool = _get_key_pool()
    if _ANYRUN_POOL_KEY_COUNT == 0:
        return _error(indicator_type, "ANYRUN_API_KEY not configured", mode="sandbox")

    try:
        chosen_key = pool.get(block=True, timeout=gate_timeout)
    except queue.Empty:
        logger.warning("AnyRun key pool timeout (%ss) for %s — skipping sandbox", gate_timeout, indicator)
        return _error(indicator_type, "AnyRun sandbox gate timeout — no API key available", mode="sandbox")

    key_label = "primary" if chosen_key == api_key else "fallback"
    logger.info("AnyRun checked out %s key for %s", key_label, indicator)

    try:
        # ── 3. Double-check cache (another thread may have finished while we waited)
        if cache_enabled:
            cached = _anyrun_cache_get(cache_key)
            if cached is not None:
                logger.info("AnyRun cache hit (post-pool) for %s", indicator)
                return cached

        # ── 4. Submit sandbox with the checked-out key ────────────────────────
        logger.info("AnyRun submitting sandbox for %s using %s key", indicator, key_label)
        sandbox_result = _run_sandbox(
            sandbox_connector_cls=sandbox_connector_cls,
            api_key=chosen_key,
            sandbox_os=sandbox_os,
            privacy_type=privacy_type,
            indicator=indicator,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            timeout_seconds=timeout_seconds,
            use_residential_proxy=use_residential_proxy,
            proxy_country=normalized_proxy_country,
        )
        raw = sandbox_result.get("raw_summary") or {}
        sandbox_result["raw_summary"] = {
            **(raw if isinstance(raw, dict) else {}),
            "api_key_slot": key_label,
        }

        if (
            fallback_api_key
            and chosen_key == api_key
            and not sandbox_result.get("checked")
            and _is_deferred_anyrun_sandbox_error(sandbox_result.get("error"))
        ):
            logger.info("AnyRun retrying sandbox for %s using fallback key after deferred primary result", indicator)
            fallback_result = _run_sandbox(
                sandbox_connector_cls=sandbox_connector_cls,
                api_key=fallback_api_key,
                sandbox_os=sandbox_os,
                privacy_type=privacy_type,
                indicator=indicator,
                indicator_type=indicator_type,
                file_bytes=file_bytes,
                file_name=file_name,
                timeout_seconds=timeout_seconds,
                use_residential_proxy=use_residential_proxy,
                proxy_country=normalized_proxy_country,
            )
            raw = fallback_result.get("raw_summary") or {}
            fallback_result["raw_summary"] = {
                **(raw if isinstance(raw, dict) else {}),
                "api_key_slot": "fallback",
            }
            if fallback_result.get("checked"):
                sandbox_result = fallback_result
            elif _is_deferred_anyrun_sandbox_error(fallback_result.get("error")):
                sandbox_result = _merge_deferred_sandbox_errors(sandbox_result, fallback_result)

        # ── 5. Cache successful results so waiting investigations get a hit ────
        if cache_enabled and sandbox_result.get("checked"):
            _anyrun_cache_set(cache_key, sandbox_result)

        return sandbox_result

    finally:
        # Always return the key to the pool so the next investigation can use it
        pool.put(chosen_key)


def _configured_anyrun_api_keys(settings: Any) -> list[str]:
    seen: set[str] = set()
    keys: list[str] = []
    for raw in (
        getattr(settings, "anyrun_api_key", ""),
        getattr(settings, "anyrun_api_key_fallback", ""),
    ):
        key = str(raw or "").strip()
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def _anyrun_key_scope(api_key: str) -> str:
    keys = _configured_anyrun_api_keys(get_settings())
    for index, configured_key in enumerate(keys, start=1):
        if api_key == configured_key:
            return f"key_{index}"
    return "unknown_key"


def _normalize_anyrun_proxy_country(proxy_country: str | None) -> str:
    country = "".join(ch for ch in str(proxy_country or "").strip().upper() if ch.isalnum())
    if not country:
        return ""
    if country == "FASTEST":
        return "fastest"
    return country[:12]


def _anyrun_network_profile(use_residential_proxy: bool, proxy_country: str | None) -> dict[str, Any]:
    country = _normalize_anyrun_proxy_country(proxy_country)
    if not use_residential_proxy and not country:
        return {}
    return {
        "use_residential_proxy": True,
        **({"proxy_country": country} if country else {}),
        "anyrun_residential_proxy": True,
        "anyrun_residential_proxy_geo": country or "fastest",
    }


def _merge_deferred_sandbox_errors(primary_result: dict[str, Any], fallback_result: dict[str, Any]) -> dict[str, Any]:
    primary_error = str(primary_result.get("error") or "").strip()
    fallback_error = str(fallback_result.get("error") or "").strip()
    if not primary_error:
        return fallback_result or primary_result
    if not fallback_error:
        return primary_result
    merged = dict(primary_result)
    merged["error"] = (
        f"{primary_error}; fallback key attempt result: {fallback_error}"
    )
    raw = merged.get("raw_summary") or {}
    merged["raw_summary"] = {
        **(raw if isinstance(raw, dict) else {}),
        "primary_error": primary_error,
        "fallback_error": fallback_error,
    }
    return merged


def _lookup_intelligence(
    lookup_connector_cls: Any,
    sandbox_connector_cls: Any,
    api_key: str,
    *,
    indicator: str,
    indicator_type: str,
    sandbox_os: str,
) -> dict[str, Any]:
    try:
        record_provider_request("anyrun", scope=_anyrun_key_scope(api_key))
        with ExitStack() as stack:
            conn = lookup_connector_cls(api_key)
            if hasattr(conn, "__enter__") and hasattr(conn, "__exit__"):
                conn = stack.enter_context(conn)
            kwargs: dict[str, Any] = {"lookup_depth": 180}
            if indicator_type == "url":
                kwargs["url"] = indicator
            elif indicator_type == "domain":
                kwargs["domain_name"] = indicator
            else:
                kwargs["sha256"] = indicator
            data = conn.get_intelligence(**kwargs)
        if not isinstance(data, dict):
            return _error(indicator_type, "ANY.RUN lookup returned an unexpected response")

        summary = data.get("summary") or {}
        threat_level = summary.get("threatLevel")
        verdict = _normalize_lookup_verdict(threat_level)
        related_tasks = _ensure_list(data.get("sourceTasks") or data.get("relatedTasks"))
        related_incidents = _ensure_list(data.get("relatedIncidents"))
        threat_names = _normalize_anyrun_labels(
            data.get("threatName") or summary.get("threatName") or summary.get("threatNames")
        )
        destination_ip_geo = _ensure_list(data.get("destinationIPgeo") or data.get("destination_ip_geo"))
        destination_ports = _extract_ports(data)
        analysis_id = None
        analysis_link = None
        if isinstance(related_tasks, list) and related_tasks:
            first = related_tasks[0] if isinstance(related_tasks[0], dict) else {}
            analysis_link = str(first.get("related") or "").strip() or None
            analysis_id = _extract_task_id(analysis_link)

        if verdict == "unknown":
            return {
                "checked": False,
                "indicator_type": indicator_type,
                "verdict": "unknown",
                "error": "Not found in ANY.RUN intelligence lookup",
                "raw_summary": {"source": "anyrun", "mode": "lookup"},
            }

        threat_score: float | None = _lookup_level_to_score(threat_level)
        dyn_domains = data.get("relatedDNS") or []
        dyn_hosts = data.get("destinationIP") or []
        ioc_items: list[dict[str, Any]] = []
        report_excerpt: dict[str, Any] = {}
        behavior_details: dict[str, Any] = {}
        if analysis_id:
            try:
                with ExitStack() as stack:
                    sconn = _create_sandbox_connector(sandbox_connector_cls, api_key=api_key, sandbox_os=sandbox_os)
                    if sconn and hasattr(sconn, "__enter__") and hasattr(sconn, "__exit__"):
                        sconn = stack.enter_context(sconn)
                    if sconn:
                        report = _get_anyrun_summary_report(sconn, analysis_id)
                        ioc_report = sconn.get_analysis_report(analysis_id, report_format="ioc")
                        html_report = sconn.get_analysis_report(analysis_id, report_format="html")
                        html_threat_labels = _extract_anyrun_html_threat_labels(html_report)
                        report_data = (report or {}).get("data") or {}
                        ioc_items = _extract_iocs(ioc_report)
                        network = report_data.get("network") or {}
                        dyn_domains = network.get("domains") or dyn_domains
                        dyn_hosts = network.get("hosts") or dyn_hosts
                        destination_ip_geo = _ensure_list(
                            report_data.get("destinationIPgeo")
                            or network.get("destinationIPgeo")
                            or destination_ip_geo
                        )
                        destination_ports = _extract_ports(report_data) or _extract_ports(network) or destination_ports
                        related_incidents = _ensure_list(report_data.get("relatedIncidents")) or related_incidents
                        threat_names = _normalize_anyrun_labels(report_data.get("threatName")) or threat_names
                        threat_names = _dedupe_strings([*threat_names, *html_threat_labels])
                        related_tasks = _ensure_list(report_data.get("relatedTasks")) or related_tasks
                        processes = _ensure_list(report_data.get("processes"))
                        dns_requests = _ensure_list(network.get("dnsRequests"))
                        http_requests = _ensure_list(network.get("httpRequests"))
                        connections = _ensure_list(network.get("connections"))
                        network_threats = _ensure_list(network.get("threats"))
                        behavior_details = {
                            "dns_requests": dns_requests[:200],
                            "http_requests": http_requests[:200],
                            "connections": connections[:200],
                            "network_threats": network_threats[:200],
                            "processes": processes[:200],
                            "process_details": _extract_process_details(
                                report_data,
                                processes,
                                dns_requests=dns_requests,
                                http_requests=http_requests,
                                connections=connections,
                                network_threats=network_threats,
                            )[:400],
                        }
                        analysis_block = report_data.get("analysis") or {}
                        score_block = analysis_block.get("scores") or {}
                        report_verdict_raw = (
                            (score_block.get("verdict") or {}).get("threatLevelText")
                            or score_block.get("verdict_text")
                            or score_block.get("classification")
                        )
                        report_threat_score = _as_float(
                            score_block.get("threatScore")
                            or score_block.get("threat_score")
                            or score_block.get("threatLevel")
                            or score_block.get("threat_level")
                        )
                        if report_verdict_raw:
                            verdict = _normalize_anyrun_verdict(report_verdict_raw)
                        if report_threat_score is not None:
                            threat_score = _clamp_score_0_100(report_threat_score)

                        report_excerpt = {
                            "analysis": report_data.get("analysis") or {},
                            "reports": ((report_data.get("analysis") or {}).get("reports") or {}),
                            "network": {
                                "domains_count": len(dyn_domains),
                                "hosts_count": len(dyn_hosts),
                                "requests_count": (network.get("requests_count") or network.get("requestsCount")),
                            },
                            "ioc_count": len(ioc_items),
                            "html_report_bytes": len(html_report) if isinstance(html_report, str) else None,
                            "html_threat_labels": html_threat_labels,
                            "screenshots": _extract_screenshot_thumbnails(report_data, html_report),
                        }
            except Exception as exc:
                report_excerpt = {"report_error": str(exc)}

        return {
            "checked": True,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "threat_score": threat_score,
            "analysis_id": analysis_id,
            "analysis_link": analysis_link,
            "dynamic_io_summary": {
                "domains": dyn_domains,
                "hosts": dyn_hosts,
                "mitre_attcks": [],
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
            },
            "raw_summary": {
                "source": "anyrun",
                "mode": "lookup",
                "summary": summary,
                "anyrun_ai_summary": _derive_lookup_summary(
                    verdict, threat_score, threat_names,
                    tags=_normalize_anyrun_labels(summary.get("tags") or []),
                    analysis_id=analysis_id,
                    analysis_link=analysis_link,
                    related_tasks_count=len(related_tasks) if isinstance(related_tasks, list) else 0,
                    related_incidents=related_incidents,
                ),
                "threatName": threat_names,
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
                "relatedTasks": related_tasks,
                "relatedIncidents": related_incidents,
                "tags": _dedupe_strings([
                    *_normalize_anyrun_labels(summary.get("tags") or []),
                    *_normalize_anyrun_labels((report_excerpt or {}).get("html_threat_labels") or []),
                ]),
                "related_tasks_count": len(related_tasks) if isinstance(related_tasks, list) else 0,
                "iocs": ioc_items[:500],
                "report_excerpt": report_excerpt,
                "screenshots": (report_excerpt.get("screenshots") or [])[:12],
                "behavior_details": behavior_details,
                "behavior_graph": _build_behavior_graph(
                    processes=_ensure_list((behavior_details or {}).get("processes")),
                    dns_requests=_ensure_list((behavior_details or {}).get("dns_requests")),
                    http_requests=_ensure_list((behavior_details or {}).get("http_requests")),
                    connections=_ensure_list((behavior_details or {}).get("connections")),
                    domains=dyn_domains,
                    hosts=dyn_hosts,
                ),
            },
        }
    except Exception as exc:
        return _error(indicator_type, f"ANY.RUN intelligence lookup failed: {exc}")


def _run_sandbox(
    *,
    sandbox_connector_cls: Any,
    api_key: str,
    sandbox_os: str,
    privacy_type: str,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None,
    file_name: str | None,
    timeout_seconds: int,
    use_residential_proxy: bool = False,
    proxy_country: str | None = None,
) -> dict[str, Any]:
    try:
        if indicator_type in {"hash", "file"}:
            max_upload_mb = int(getattr(get_settings(), "anyrun_max_upload_mb", 100) or 100)
            if file_bytes:
                file_size_mb = len(file_bytes) / (1024 * 1024)
                if file_size_mb > max_upload_mb:
                    return _error(
                        indicator_type,
                        f"ANY.RUN file sandbox skipped: sample size {file_size_mb:.1f} MB exceeds configured max {max_upload_mb} MB",
                    )
        with ExitStack() as stack:
            connector = _create_sandbox_connector(sandbox_connector_cls, api_key=api_key, sandbox_os=sandbox_os)
            if connector is None:
                return _error(indicator_type, "Failed to initialize ANY.RUN sandbox connector", mode="sandbox")
            if hasattr(connector, "__enter__") and hasattr(connector, "__exit__"):
                connector = stack.enter_context(connector)

            task_id = _submit_anyrun_task_with_fallback(
                connector=connector,
                indicator=indicator,
                indicator_type=indicator_type,
                privacy_type=privacy_type,
                file_bytes=file_bytes,
                file_name=file_name,
                use_residential_proxy=use_residential_proxy,
                proxy_country=proxy_country,
            )
            if isinstance(task_id, dict) and task_id.get("__error__"):
                return _error(indicator_type, str(task_id.get("__error__")), mode="sandbox")

            analysis_id = str(task_id or "").strip()
            if not analysis_id:
                return _error(indicator_type, "ANY.RUN sandbox submission returned empty task id", mode="sandbox")

            wait_timeout = max(90, int(timeout_seconds or 60) + 60)
            final_status = _wait_status_stream(connector, analysis_id, timeout_seconds=wait_timeout)
            # Poll for report readiness — stream may end before the report data is ready.
            # Budget: max(120, timeout_seconds + 60) — URL/domain tasks can take 2-3 min.
            # Catch SDK exceptions that indicate the task is still processing (e.g.
            # "task is still running") and continue polling rather than propagating.
            report = None
            poll_deadline = time.time() + max(120, int(timeout_seconds or 60) + 60)
            while time.time() < poll_deadline:
                try:
                    report = _get_anyrun_summary_report(connector, analysis_id)
                except Exception as poll_exc:
                    _poll_exc_str = str(poll_exc).lower()
                    if (
                        "task is still running" in _poll_exc_str
                        or "still running" in _poll_exc_str
                        or "not ready" in _poll_exc_str
                        or "pending" in _poll_exc_str
                    ):
                        time.sleep(5)
                        continue
                    raise
                report_data = (report or {}).get("data") or {}
                report_status = str(report_data.get("status") or "").strip().upper()
                if report_status not in {"RUNNING", "PENDING", "QUEUED"}:
                    break
                time.sleep(5)
            report_data = (report or {}).get("data") or {}
            report_status = str(report_data.get("status") or "").strip().upper()
            if report_status in {"RUNNING", "PENDING", "QUEUED"}:
                return _error(
                    indicator_type,
                    "ANY.RUN sandbox task is still running and the report is not ready yet.",
                )
            verdict_raw = connector.get_analysis_verdict(analysis_id)
            verdict = _normalize_anyrun_verdict(verdict_raw)
            ioc_report = connector.get_analysis_report(analysis_id, report_format="ioc")
            html_report = connector.get_analysis_report(analysis_id, report_format="html")
        report_data = (report or {}).get("data") or {}
        analysis = (report_data.get("analysis") or {})
        network = (report_data.get("network") or {})
        counters = (report_data.get("counters") or {})
        processes = _ensure_list(report_data.get("processes"))
        scores = (analysis.get("scores") or {})
        summary = report_data.get("summary") or {}
        html_threat_labels = _extract_anyrun_html_threat_labels(html_report)
        threat_names = _dedupe_strings([
            *_ensure_list(report_data.get("threatName") or summary.get("threatName")),
            *html_threat_labels,
        ])
        destination_ip_geo = _ensure_list(report_data.get("destinationIPgeo") or network.get("destinationIPgeo"))
        destination_ports = _extract_ports(report_data) or _extract_ports(network)
        related_tasks = _ensure_list(report_data.get("relatedTasks"))
        related_incidents = _ensure_list(report_data.get("relatedIncidents"))
        dns_requests = _ensure_list(network.get("dnsRequests"))
        http_requests = _ensure_list(network.get("httpRequests"))
        connections = _ensure_list(network.get("connections"))
        network_threats = _ensure_list(network.get("threats"))
        ioc_items = _extract_iocs(ioc_report)
        ioc_types = [str(x.get("type") or "").lower() for x in ioc_items if isinstance(x, dict)]
        logger.debug(
            "AnyRun sandbox IOC report: total=%d types=%s http_requests=%d dns_requests=%d",
            len(ioc_items),
            sorted(set(ioc_types)),
            len(http_requests),
            len(dns_requests),
        )

        dyn_domains = []
        for entry in dns_requests:
            if isinstance(entry, dict):
                dyn_domains.append(
                    {
                        "domainName": entry.get("domainName") or entry.get("domain") or entry.get("hostname"),
                        "threatLevel": entry.get("threatLevel") or 0,
                        "threatName": _ensure_list(entry.get("threatName")),
                        "date": entry.get("date") or entry.get("timestamp"),
                        "isMalconf": bool(entry.get("isMalconf")),
                    }
                )
        dyn_hosts = []
        for entry in connections:
            if isinstance(entry, dict):
                dyn_hosts.append(
                    {
                        "destinationIP": entry.get("destinationIP") or entry.get("ip") or entry.get("host"),
                        "threatLevel": entry.get("threatLevel") or 0,
                        "threatName": _ensure_list(entry.get("threatName")),
                        "date": entry.get("date") or entry.get("timestamp"),
                        "isMalconf": bool(entry.get("isMalconf")),
                        "destinationPort": entry.get("destinationPort") or entry.get("port"),
                    }
                )
        if not dyn_domains:
            dyn_domains = _ensure_list(network.get("domains"))
        if not dyn_hosts:
            dyn_hosts = _ensure_list(network.get("hosts"))
        # Build URL list from HTTP requests observed during sandbox execution
        dyn_urls: list[dict[str, Any]] = []
        for entry in http_requests:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or entry.get("requestUrl") or "").strip()
            if url and url.startswith("http"):
                dyn_urls.append(
                    {
                        "url": url,
                        "method": entry.get("method") or "GET",
                        "threatLevel": entry.get("threatLevel") or 0,
                        "threatName": _ensure_list(entry.get("threatName")),
                        "status": entry.get("status") or entry.get("responseCode"),
                    }
                )

        threat_score = _as_float(
            scores.get("threatScore")
            or scores.get("threat_score")
            or scores.get("threatLevel")
            or scores.get("threat_level")
        )
        process_details = _extract_process_details(
            report_data,
            processes,
            dns_requests=dns_requests,
            http_requests=http_requests,
            connections=connections,
            network_threats=network_threats,
        )
        network_profile = _anyrun_network_profile(use_residential_proxy, proxy_country)

        return {
            "checked": True,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "threat_score": threat_score,
            "analysis_id": analysis_id,
            "analysis_link": analysis.get("permanentUrl"),
            "dynamic_io_summary": {
                "domains": dyn_domains,
                "hosts": dyn_hosts,
                "urls": dyn_urls,
                "mitre_attcks": (report_data.get("mitre") or []),
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
                **({"network_profile": network_profile} if network_profile else {}),
            },
            "raw_summary": {
                "source": "anyrun",
                "mode": "sandbox",
                **({"network_profile": network_profile} if network_profile else {}),
                "summary": summary,
                "anyrun_ai_summary": _derive_anyrun_summary(analysis, network, report_data),
                "permanentUrl": analysis.get("permanentUrl"),
                "behavior_graph_url": ((analysis.get("reports") or {}).get("graph")),
                "ioc_report_url": ((analysis.get("reports") or {}).get("IOC")),
                "report_links": (analysis.get("reports") or {}),
                "screenshots": _extract_screenshot_thumbnails(report_data, html_report),
                "iocs": ioc_items[:500],
                "tags": _dedupe_strings([
                    *_normalize_anyrun_labels(summary.get("tags") or []),
                    *html_threat_labels,
                ]),
                "html_report_bytes": len(html_report) if isinstance(html_report, str) else None,
                "html_threat_labels": html_threat_labels,
                "behavior_counts": {
                    "http_requests": len(http_requests) or _as_int(counters.get("httpRequests")),
                    "connections": len(connections) or _as_int(counters.get("connections")),
                    "dns_requests": len(dns_requests) or _as_int(counters.get("dnsRequests")),
                    "network_threats": len(network_threats) or _as_int(counters.get("threats")),
                    "processes": len(processes) or _as_int(counters.get("processes")),
                },
                "behavior_details": {
                    "dns_requests": dns_requests[:200],
                    "http_requests": http_requests[:200],
                    "connections": connections[:200],
                    "network_threats": network_threats[:200],
                    "processes": processes[:200],
                    "process_details": process_details[:400],
                },
                "behavior_graph": _build_behavior_graph(
                    processes=processes,
                    dns_requests=dns_requests,
                    http_requests=http_requests,
                    connections=connections,
                    domains=dyn_domains,
                    hosts=dyn_hosts,
                ),
                "threatName": threat_names,
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
                "relatedTasks": related_tasks,
                "relatedIncidents": related_incidents,
                "verdict_text": str(verdict_raw or ""),
            },
        }
    except Exception as exc:
        import traceback as _tb
        logger.warning("AnyRun sandbox exception traceback:\n%s", _tb.format_exc())
        err = str(exc or "")
        lower_err = err.lower()
        if "task is still running" in lower_err:
            return _error(
                indicator_type,
                "ANY.RUN sandbox task is still running and the report is not ready yet.",
            )
        if "nonetype" in lower_err and "get" in lower_err:
            return _error(
                indicator_type,
                "ANY.RUN sandbox report retrieval failed: provider returned an empty/invalid response (SDK null payload).",
            )
        if "contenttypeerror" in lower_err and "not supported between instances" in lower_err:
            return _error(
                indicator_type,
                "ANY.RUN sandbox submission failed: API returned non-JSON response (often HTTP 413 file too large or plan restriction).",
                mode="sandbox",
            )
        if "413" in lower_err:
            return _error(indicator_type, "ANY.RUN sandbox submission failed: file too large for this API tier (HTTP 413).", mode="sandbox")
        if "parallel task limit" in lower_err:
            return _error(indicator_type, "ANY.RUN sandbox submission deferred: parallel task limit reached", mode="sandbox")
        return _error(indicator_type, f"ANY.RUN sandbox submission failed: {exc}", mode="sandbox")


def _submit_anyrun_task_with_fallback(
    *,
    connector: Any,
    indicator: str,
    indicator_type: str,
    privacy_type: str,
    file_bytes: bytes | None,
    file_name: str | None,
    use_residential_proxy: bool = False,
    proxy_country: str | None = None,
) -> Any:
    record_provider_request("anyrun")
    connector_key = getattr(connector, "api_key", None) or getattr(connector, "_api_key", None) or ""
    if connector_key:
        record_provider_request("anyrun", scope=_anyrun_key_scope(str(connector_key)))
    settings = get_settings()
    if indicator_type in {"hash", "file"} and not file_bytes:
        return {"__error__": f"ANY.RUN {indicator_type} sandbox submission requires uploaded file bytes"}
    if indicator_type not in {"url", "hash", "file"}:
        return {"__error__": f"Unsupported Any.Run indicator type: {indicator_type}"}

    attempts: list[str | None] = []
    preferred = str(privacy_type or "").strip()
    if preferred:
        attempts.append(preferred)
    attempts.append(None)

    last_exc: Exception | None = None
    max_parallel_retries = int(getattr(settings, "anyrun_parallel_limit_retries", 8) or 8)
    base_parallel_backoff_seconds = int(getattr(settings, "anyrun_parallel_backoff_seconds", 10) or 10)
    max_transient_retries = int(getattr(settings, "anyrun_transient_retries", 3) or 3)
    base_transient_backoff_seconds = int(getattr(settings, "anyrun_transient_backoff_seconds", 6) or 6)
    url_analysis_timeout = int(getattr(settings, "anyrun_url_sandbox_analysis_timeout", 120) or 120)
    url_mitm = bool(getattr(settings, "anyrun_url_sandbox_mitm", True))
    anyrun_proxy_country = _normalize_anyrun_proxy_country(proxy_country)
    use_residential_proxy = bool(use_residential_proxy or anyrun_proxy_country)

    for privacy in attempts:
        parallel_retry = 0
        transient_retry = 0
        while True:
            try:
                if indicator_type == "url":
                    target = _normalize_submission_url(indicator)
                    url_kwargs: dict[str, Any] = {
                        "opt_timeout": url_analysis_timeout,
                        "opt_automated_interactivity": True,
                        "opt_network_mitm": url_mitm,
                    }
                    if privacy:
                        url_kwargs["opt_privacy_type"] = privacy
                    if use_residential_proxy:
                        url_kwargs["opt_network_residential_proxy"] = True
                        url_kwargs["opt_network_residential_proxy_geo"] = anyrun_proxy_country or "fastest"
                    return _call_with_supported_kwargs(connector.run_url_analysis, target, **url_kwargs)
                file_kwargs: dict[str, Any] = {
                    "file_content": file_bytes,
                    "filename": (file_name or "sample.bin"),
                    "opt_timeout": 60,
                }
                if privacy:
                    file_kwargs["opt_privacy_type"] = privacy
                if use_residential_proxy:
                    file_kwargs["opt_network_residential_proxy"] = True
                    file_kwargs["opt_network_residential_proxy_geo"] = anyrun_proxy_country or "fastest"
                return _call_with_supported_kwargs(connector.run_file_analysis, **file_kwargs)
            except Exception as exc:
                last_exc = exc
                if _is_parallel_limit_error(exc):
                    if parallel_retry < max_parallel_retries:
                        parallel_retry += 1
                        time.sleep(base_parallel_backoff_seconds * parallel_retry)
                        continue
                    return {
                        "__error__": (
                            "ANY.RUN sandbox submission failed: parallel task limit reached "
                            f"after {max_parallel_retries} retries."
                        )
                    }
                if _is_transient_provider_error(exc):
                    if transient_retry < max_transient_retries:
                        transient_retry += 1
                        time.sleep(base_transient_backoff_seconds * transient_retry)
                        continue
                    return {
                        "__error__": (
                            "ANY.RUN sandbox submission failed: provider transient/server error "
                            f"persisted after {max_transient_retries} retries. Last error: {exc}"
                        )
                    }
                if _is_submission_fallback_candidate(exc):
                    logger.debug("AnyRun submission fallback candidate (privacy=%s): %s", privacy, exc)
                    break
                return {"__error__": f"ANY.RUN sandbox submission failed: {exc}"}

    if isinstance(last_exc, Exception) and _is_submission_fallback_candidate(last_exc):
        logger.warning("AnyRun submission failed with null payload for both privacy variants: %s", last_exc)
        return {
            "__error__": (
                "ANY.RUN sandbox submission failed: provider returned an empty/invalid response "
                "(SDK null payload)."
            )
        }
    return {"__error__": f"ANY.RUN sandbox submission failed: {last_exc}"}


def _call_with_supported_kwargs(method: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        sig = signature(method)
    except (TypeError, ValueError):
        return method(*args, **kwargs)

    if any(param.kind == Parameter.VAR_KEYWORD for param in sig.parameters.values()):
        return method(*args, **kwargs)

    supported = {
        name
        for name, param in sig.parameters.items()
        if param.kind in {Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY}
    }
    return method(*args, **{key: value for key, value in kwargs.items() if key in supported})


def _get_anyrun_summary_report(connector: Any, analysis_id: str) -> Any:
    try:
        record_provider_request("anyrun")
        connector_key = getattr(connector, "api_key", None) or getattr(connector, "_api_key", None) or ""
        if connector_key:
            record_provider_request("anyrun", scope=_anyrun_key_scope(str(connector_key)))
        return connector.get_analysis_report(analysis_id, report_format="summary")
    except Exception as exc:
        if "invalid summary type" not in str(exc or "").lower():
            raise
        record_provider_request("anyrun")
        connector_key = getattr(connector, "api_key", None) or getattr(connector, "_api_key", None) or ""
        if connector_key:
            record_provider_request("anyrun", scope=_anyrun_key_scope(str(connector_key)))
        return connector.get_analysis_report(analysis_id)


def _is_submission_fallback_candidate(exc: Exception) -> bool:
    text = str(exc or "").strip().lower()
    if not text:
        return False
    return (
        "nonetype" in text and "get" in text
    ) or (
        "privacy" in text and ("plan" in text or "settings" in text or "unavailable" in text)
    ) or (
        "status code: 403" in text
        and (
            "free plan" in text
            or "api is not available" in text
            or "unavailable" in text
        )
    )


def _is_parallel_limit_error(exc: Exception) -> bool:
    text = str(exc or "").strip().lower()
    if not text:
        return False
    return "parallel task limit" in text or ("status code: 403" in text and "parallel" in text)


def _is_transient_provider_error(exc: Exception) -> bool:
    text = str(exc or "").strip().lower()
    if not text:
        return False
    return (
        "status code: 500" in text
        or "status code: 502" in text
        or "status code: 503" in text
        or "status code: 504" in text
        or "status code: 408" in text
        or "unknown error" in text
    )


def _normalize_submission_url(indicator: str) -> str:
    value = str(indicator or "").strip()
    if not value:
        return value
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return value
    if parsed.scheme and not parsed.netloc and parsed.path:
        return f"{parsed.scheme}://{parsed.path}"
    return f"https://{value}"


def _create_sandbox_connector(sandbox_connector_cls: Any, *, api_key: str, sandbox_os: str) -> Any | None:
    order = ("linux", "windows") if sandbox_os == "linux" else ("windows", "linux")
    for method in order:
        fn = getattr(sandbox_connector_cls, method, None)
        if callable(fn):
            try:
                return fn(api_key, enable_requests=True)
            except Exception:
                continue
    return None


def _wait_status_stream(connector: Any, task_id: str, timeout_seconds: int) -> str | None:
    deadline = time.time() + max(10, timeout_seconds)
    last_status: str | None = None
    try:
        statuses = connector.get_task_status(task_id)
        for item in statuses:
            if time.time() > deadline:
                break
            status = str((item or {}).get("status") or "").upper()
            last_status = status or last_status
            if status in {"COMPLETED", "FAILED"}:
                break
    except Exception:
        pass
    return last_status


def _normalize_lookup_verdict(level: Any) -> str:
    try:
        n = int(level)
    except Exception:
        return "unknown"
    if n >= 2:
        return "malicious"
    if n == 1:
        return "suspicious"
    if n == 0:
        return "clean"
    return "unknown"


def _normalize_anyrun_verdict(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "malicious" in text:
        return "malicious"
    if "suspicious" in text:
        return "suspicious"
    if "no threats" in text or "clean" in text or "benign" in text:
        return "clean"
    return _normalize_lookup_verdict(value)


def _reconcile_anyrun_sandbox_lookup_verdict(sandbox_result: dict[str, Any], lookup_result: dict[str, Any]) -> dict[str, Any]:
    sandbox_verdict = str(sandbox_result.get("verdict") or "").strip().lower()
    lookup_verdict = str(lookup_result.get("verdict") or "").strip().lower()
    if sandbox_verdict != "malicious" or lookup_verdict not in {"clean", "benign", "safe"}:
        return sandbox_result

    concrete_reasons = _anyrun_concrete_sandbox_reasons(sandbox_result)
    reconciled = dict(sandbox_result)
    raw = reconciled.get("raw_summary") or {}
    raw = dict(raw if isinstance(raw, dict) else {})
    context = {
        "conflict": True,
        "provider_verdict": sandbox_verdict,
        "lookup_verdict": lookup_verdict,
        "lookup_threat_score": lookup_result.get("threat_score"),
        "sandbox_threat_score": sandbox_result.get("threat_score"),
        "confidence": "medium" if concrete_reasons else "low",
        "evidence_reasons": concrete_reasons,
    }
    if concrete_reasons:
        context["final_verdict"] = "malicious"
        context["explanation"] = (
            "ANY.RUN sandbox marked this task malicious while lookup reputation was clean. "
            "Concrete sandbox evidence was present, so the malicious sandbox verdict is retained but flagged as conflicting."
        )
    else:
        context["final_verdict"] = "suspicious"
        context["explanation"] = (
            "ANY.RUN sandbox marked this task malicious while lookup reputation was clean, but the completed task did not expose "
            "concrete behavioral evidence such as threat score, network threats, malicious tags, or threat names. "
            "Treat this as suspicious and review the task before blocking."
        )
        reconciled["provider_verdict"] = sandbox_verdict
        reconciled["verdict"] = "suspicious"

    raw["verdict_context"] = context
    reconciled["verdict_context"] = context
    reconciled["raw_summary"] = raw
    return reconciled


def _anyrun_concrete_sandbox_reasons(result: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    raw = result.get("raw_summary") or {}
    raw = raw if isinstance(raw, dict) else {}
    threat_score = _as_float(result.get("threat_score")) or 0.0
    if threat_score > 0:
        reasons.append(f"Sandbox threat score {threat_score:g}.")
    threat_names = _normalize_anyrun_labels(result.get("threat_names") or raw.get("threatName") or raw.get("threat_names"))
    if threat_names:
        reasons.append(f"Threat labels: {', '.join(threat_names[:4])}.")
    tags = _normalize_anyrun_labels(raw.get("tags") or result.get("tags"))
    summary = raw.get("summary") or {}
    if isinstance(summary, dict):
        tags = _dedupe_strings([
            *tags,
            *_normalize_anyrun_labels(summary.get("tags")),
            *_normalize_anyrun_labels(summary.get("detectedType")),
            *_normalize_anyrun_labels(summary.get("tracker") or summary.get("trackers")),
        ])
    suspicious_tags = [
        tag for tag in tags
        if any(
            word in tag.lower()
            for word in (
                "phish",
                "credential",
                "malware",
                "trojan",
                "steal",
                "c2",
                "exploit",
                "clickfix",
                "clearfake",
                "fake captcha",
                "fake-captcha",
                "tds",
                "obfuscated-js",
                "obfuscated js",
                "etherhiding",
            )
        )
    ]
    if suspicious_tags:
        reasons.append(f"Malicious tags: {', '.join(suspicious_tags[:4])}.")
    counts = raw.get("behavior_counts") or {}
    if isinstance(counts, dict) and _as_int(counts.get("network_threats")) > 0:
        reasons.append(f"Network threats observed: {_as_int(counts.get('network_threats'))}.")
    details = raw.get("behavior_details") or {}
    if isinstance(details, dict) and _ensure_list(details.get("network_threats")):
        reasons.append("Sandbox reported network threat details.")
    return reasons[:6]


def _is_deferred_anyrun_sandbox_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return (
        "parallel task limit" in text
        or "sandbox submission deferred" in text
        or "empty/invalid response" in text
        or "sdk null payload" in text
        or "api is not available on the free plan" in text
        or "provider transient/server error" in text
        or "unknown error" in text
        or "task is still running" in text
        or "report is not ready" in text
    )


def _lookup_level_to_score(level: Any) -> float | None:
    try:
        n = int(level)
    except Exception:
        return None
    # Conservative normalization for lookup-only confidence (0..100 scale).
    if n <= 0:
        return 0.0
    if n == 1:
        return 40.0
    if n == 2:
        return 75.0
    if n == 3:
        return 90.0
    return 100.0


def _clamp_score_0_100(value: float | int | None) -> float | None:
    if value is None:
        return None
    try:
        v = float(value)
    except Exception:
        return None
    if v < 0:
        return 0.0
    if v > 100:
        return 100.0
    return v


def _extract_task_id(related: str | None) -> str | None:
    text = str(related or "").strip()
    if not text:
        return None
    if "/tasks/" in text:
        try:
            tail = text.split("/tasks/", 1)[1]
            return tail.split("/", 1)[0].strip() or None
        except Exception:
            return None
    return text


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _extract_ports(payload: Any) -> list[int]:
    if not isinstance(payload, dict):
        return []
    ports: set[int] = set()
    keys = ("destinationPort", "destinationPorts", "port", "ports")
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float, str)):
            maybe = _to_port(value)
            if maybe is not None:
                ports.add(maybe)
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    maybe = _to_port(item.get("port") or item.get("destinationPort"))
                else:
                    maybe = _to_port(item)
                if maybe is not None:
                    ports.add(maybe)
    network = payload.get("network")
    if isinstance(network, dict):
        for host in _ensure_list(network.get("hosts")):
            if isinstance(host, dict):
                maybe = _to_port(host.get("destinationPort") or host.get("port"))
                if maybe is not None:
                    ports.add(maybe)
        for conn in _ensure_list(network.get("connections")):
            if isinstance(conn, dict):
                maybe = _to_port(conn.get("destinationPort") or conn.get("port"))
                if maybe is not None:
                    ports.add(maybe)
    return sorted(ports)


def _to_port(value: Any) -> int | None:
    try:
        n = int(str(value).strip())
    except Exception:
        return None
    if 0 < n <= 65535:
        return n
    return None


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _extract_iocs(ioc_report: Any) -> list[dict[str, Any]]:
    if isinstance(ioc_report, list):
        return [x for x in ioc_report if isinstance(x, dict)]
    if isinstance(ioc_report, dict):
        data = ioc_report.get("data")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            # some shapes may nest under known keys
            for key in ("items", "iocs", "indicators"):
                v = data.get(key)
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
    return []


def _extract_screenshot_thumbnails(report_data: Any, html_report: Any) -> list[dict[str, Any]]:
    screenshots: list[dict[str, Any]] = []
    seen: set[str] = set()
    screenshot_report_url = _extract_anyrun_screenshot_report_url(report_data, html_report)

    def add(url: Any, label: str = "ANY.RUN screenshot") -> None:
        text = str(url or "").strip()
        if not text:
            return
        if text.startswith("//"):
            text = f"https:{text}"
        if not (text.startswith("http://") or text.startswith("https://") or text.startswith("data:image/")):
            return
        if text.startswith("data:image/") and len(text) > 250_000:
            return
        key = text.lower()
        if key in seen:
            return
        seen.add(key)
        row = {"label": label[:80], "url": text}
        if screenshot_report_url:
            row["report_url"] = screenshot_report_url
        screenshots.append(row)

    def walk(value: Any, label: str = "ANY.RUN screenshot") -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                key_label = str(key or "")
                lowered = key_label.lower()
                next_label = key_label if key_label else label
                if any(token in lowered for token in ("screen", "shot", "thumb", "image", "png", "jpg", "jpeg", "webp")):
                    walk(inner, next_label)
                elif isinstance(inner, (dict, list, tuple)):
                    walk(inner, label)
            return
        if isinstance(value, (list, tuple)):
            for inner in value:
                walk(inner, label)
            return
        add(value, label)

    if isinstance(report_data, dict):
        analysis = report_data.get("analysis") or {}
        walk((analysis or {}).get("reports") or {}, "ANY.RUN report image")
        walk(report_data.get("screenshots") or report_data.get("images") or [], "ANY.RUN screenshot")

    if isinstance(html_report, str) and html_report:
        for match in re.finditer(r"<img\b[^>]*\bsrc=[\"']([^\"']+)[\"'][^>]*>", html_report, flags=re.I):
            tag = match.group(0).lower()
            src = match.group(1)
            if any(token in tag for token in ("screen", "shot", "thumb", "task", "image")):
                add(src, "ANY.RUN HTML thumbnail")
        for match in re.finditer(r"https?://[^\s\"'<>]+?\.(?:png|jpe?g|webp)(?:\?[^\s\"'<>]*)?", html_report, flags=re.I):
            url = match.group(0)
            lowered = url.lower()
            if any(token in lowered for token in ("screen", "shot", "thumb", "task", "image")):
                add(url, "ANY.RUN HTML image")

    return screenshots[:12]


def _extract_anyrun_screenshot_report_url(report_data: Any, html_report: Any) -> str | None:
    if isinstance(html_report, str) and html_report:
        match = re.search(r"https?://report\.any\.run/[^\s\"'<>]+/#Screenshots", html_report, flags=re.I)
        if match:
            return match.group(0)

    if isinstance(report_data, dict):
        analysis = report_data.get("analysis") or {}
        permanent = str(analysis.get("permanentUrl") or "").strip()
        if permanent.startswith("http://") or permanent.startswith("https://"):
            return f"{permanent.rstrip('/')}#Screenshots"
    return None


def _extract_anyrun_html_threat_labels(html_report: Any) -> list[str]:
    if not isinstance(html_report, str) or not html_report:
        return []
    # The SDK JSON sometimes omits the chips visible in the ANY.RUN HTML report.
    # Scan only for specific threat-family/behavior phrases. Generic words such as
    # "credential" and "tds" occur in AnyRun's own UI/scripts and must not become
    # threat labels merely because they exist somewhere in the HTML document.
    compact = re.sub(r"[\s_]+", " ", html_report.casefold())
    out: list[str] = []
    seen: set[str] = set()
    for marker, label in _ANYRUN_HTML_THREAT_MARKERS:
        normalized_marker = re.sub(r"[\s_]+", " ", marker.casefold())
        if normalized_marker in compact and label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _normalize_anyrun_labels(values: Any) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for value in _ensure_list(values):
        text = ""
        if isinstance(value, str):
            text = value.strip()
        elif isinstance(value, dict):
            for key in ("threatName", "name", "tag", "title", "label", "value"):
                candidate = str(value.get(key) or "").strip()
                if candidate:
                    text = candidate
                    break
        elif value is not None:
            text = str(value).strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        labels.append(text)
    return labels


def _dedupe_strings(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _derive_lookup_summary(
    verdict: str,
    threat_score: float | None,
    threat_names: list[str],
    tags: list[str],
    analysis_id: str | None,
    analysis_link: str | None,
    related_tasks_count: int = 0,
    related_incidents: list[Any] | None = None,
) -> str:
    """Build a human-readable summary for TI lookup results (no live sandbox data)."""
    try:
        parts: list[str] = []
        verdict_label = (verdict or "unknown").capitalize()
        score_str = f" (threat score: {int(threat_score)}/100)" if threat_score else ""
        parts.append(f"AnyRun threat intelligence verdict: {verdict_label}{score_str}.")

        # Combine threat categories and tags — deduplicated, most informative first
        all_labels: list[str] = []
        seen_lower: set[str] = set()
        for label in list(threat_names or []) + list(tags or []):
            s = str(label or "").strip()
            if s and s.lower() not in seen_lower:
                seen_lower.add(s.lower())
                all_labels.append(s)
        if all_labels:
            parts.append(f"Threat categories / tags: {', '.join(all_labels[:10])}.")

        if related_tasks_count:
            parts.append(f"Community sandbox submissions for this indicator: {related_tasks_count}.")

        inc_titles = []
        for inc in list(related_incidents or [])[:3]:
            if isinstance(inc, dict):
                t = str(inc.get("title") or inc.get("name") or "").strip()
                if t:
                    inc_titles.append(t)
        if inc_titles:
            parts.append(f"Related incidents: {'; '.join(inc_titles)}.")

        if analysis_id:
            parts.append(
                f"Prior analysis: {analysis_link or ('https://app.any.run/tasks/' + analysis_id)}."
                " Behavioral details (process tree, network traffic) are not available in lookup-only results"
                " — submit the sandbox for live execution data."
            )
        else:
            parts.append(
                "No prior sandbox analysis found for this indicator."
                " Verdict is based on AnyRun threat intelligence community data."
            )
        return " ".join(parts)
    except Exception:
        return ""


def _derive_anyrun_summary(analysis: dict[str, Any], network: dict[str, Any], report_data: dict[str, Any]) -> str:
    try:
        verdict = ((analysis.get("scores") or {}).get("verdict") or {})
        tl_text = str(verdict.get("threatLevelText") or "").strip()
        tl = verdict.get("threatLevel")
        dns_n = len(_ensure_list(network.get("dnsRequests")))
        http_n = len(_ensure_list(network.get("httpRequests")))
        conn_n = len(_ensure_list(network.get("connections")))
        thr_n = len(_ensure_list(network.get("threats")))
        incidents = _ensure_list(report_data.get("incidents"))
        top_inc = []
        for inc in incidents[:3]:
            if isinstance(inc, dict):
                title = str(inc.get("title") or inc.get("desc") or "").strip()
                if title:
                    top_inc.append(title)
        parts = []
        if tl_text:
            parts.append(tl_text)
        elif tl is not None:
            parts.append(f"Threat level {tl}")
        parts.append(f"Observed {http_n} HTTP requests, {conn_n} connections, {dns_n} DNS requests, {thr_n} network threat events.")
        if top_inc:
            parts.append("Top incidents: " + "; ".join(top_inc) + ".")
        return " ".join(parts).strip()
    except Exception:
        return ""


def _build_behavior_graph(
    *,
    processes: list[Any],
    dns_requests: list[Any],
    http_requests: list[Any],
    connections: list[Any],
    domains: list[Any] | None = None,
    hosts: list[Any] | None = None,
) -> dict[str, Any]:
    proc_rows = [p for p in _ensure_list(processes) if isinstance(p, dict)]
    normalized = _normalize_process_graph_rows(proc_rows)
    collapsed = _collapse_low_signal_system_processes(normalized)
    collapsed = _collapse_low_signal_system_chains(collapsed)

    nodes = [{"id": "analysis:root", "label": "AnyRun Task", "kind": "analysis"}]
    edges: list[dict[str, Any]] = []

    collapsed_ids = {str(proc.get("node_id")) for proc in collapsed}

    for proc in collapsed:
        nodes.append(
            {
                "id": str(proc["node_id"]),
                "label": str(proc["label"]),
                "kind": "process",
                "process": proc["process"],
            }
        )
        parent_id = str(proc.get("parent_node_id") or "").strip()
        source = parent_id if parent_id in collapsed_ids else "analysis:root"
        edges.append(
            {
                "id": f"{source}->{proc['node_id']}:spawns",
                "source": source,
                "target": proc["node_id"],
                "label": "spawns",
            }
        )

    return {"nodes": nodes[:300], "edges": edges[:600]}


_LOW_SIGNAL_SYSTEM_PROCESSES = {
    "svchost.exe",
    "conhost.exe",
    "explorer.exe",
    "runtimebroker.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "searchapp.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "taskhostw.exe",
    "textinputhost.exe",
    "useroobebroker.exe",
    "musnotification.exe",
    "musnotificationux.exe",
    "mousocoreworker.exe",
    "sihclient.exe",
    "sihost.exe",
    "sppextcomobj.exe",
    "systemsettings.exe",
    "officeclicktorun.exe",
    "spoolsv.exe",
    "sppsvc.exe",
    "fontdrvhost.exe",
    "usoclient.exe",
    "unsecapp.exe",
    "upfc.exe",
}


def _direct_anyrun_process_signal(process: dict[str, Any]) -> int:
    scores = process.get("scores") or {}
    verdict = scores.get("verdict") or {} if isinstance(scores, dict) else {}
    threat_level = _as_int(
        process.get("threat_level")
        or process.get("threatLevel")
        or (verdict.get("threatLevel") if isinstance(verdict, dict) else 0)
    )
    threat_names = _ensure_list(process.get("threat_name") or process.get("threatName"))
    is_malconf = bool(process.get("is_malconf") or process.get("isMalconf"))

    score = 0
    if threat_level >= 2:
        score += 5
    elif threat_level >= 1:
        score += 3
    if threat_names:
        score += 3
    if is_malconf:
        score += 2
    return score


_COMMAND_ANOMALY_TOKENS = (
    " -enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-webrequest",
    " iwr ",
    " iwr.exe",
    "curl ",
    "wget ",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "powershell.exe -e",
    "bypass",
    "hidden",
    "schtasks",
    "reg add",
    "\\appdata\\",
    "\\temp\\",
    "/tmp/",
)


def _process_network_activity_count(process: dict[str, Any]) -> int:
    counts = process.get("event_counts") or {}
    return (
        _as_int(counts.get("connections"))
        + _as_int(counts.get("http_requests"))
        + _as_int(counts.get("dns_requests"))
        + _as_int(counts.get("network_threats"))
    )


def _process_file_write_count(process: dict[str, Any]) -> int:
    counts = process.get("event_counts") or {}
    return (
        _as_int(counts.get("modified_files"))
        + _as_int(counts.get("created_files"))
        + _as_int(counts.get("dropped_files"))
        + _as_int(counts.get("deleted_files"))
    )


def _process_privilege_activity_count(process: dict[str, Any]) -> int:
    counts = process.get("event_counts") or {}
    cmd = str(process.get("command_line") or process.get("commandLine") or process.get("cmd") or "").lower()
    integrity = str(process.get("integrity_level") or process.get("integrityLevel") or "").lower()
    privilege_terms = ("runas", "uac", "token", "privilege", "sebackupprivilege", "sedebugprivilege")
    score = _as_int(counts.get("registry_changes"))
    if integrity in {"high", "system"}:
        score += 1
    if any(term in cmd for term in privilege_terms):
        score += 1
    return score


def _has_command_line_anomaly(process: dict[str, Any]) -> bool:
    cmd = f" {str(process.get('command_line') or process.get('commandLine') or process.get('cmd') or '').lower()} "
    return any(token in cmd for token in _COMMAND_ANOMALY_TOKENS)


def _is_detection_triggering_process(process: dict[str, Any]) -> bool:
    return _direct_anyrun_process_signal(process) > 0 or _as_int((process.get("event_counts") or {}).get("network_threats")) > 0


def _is_meaningful_graph_process(process: dict[str, Any]) -> bool:
    return (
        _is_detection_triggering_process(process)
        or _process_network_activity_count(process) > 0
        or _process_file_write_count(process) > 0
        or _process_privilege_activity_count(process) > 0
        or _has_command_line_anomaly(process)
    )


def _process_relevance_score(process: dict[str, Any], *, parent_is_suspicious: bool) -> int:
    score = _direct_anyrun_process_signal(process)
    network_count = _process_network_activity_count(process)
    if network_count > 0:
        score += 3
    if _process_file_write_count(process) > 0:
        score += 2
    if _process_privilege_activity_count(process) > 0:
        score += 2
    children = _ensure_list(process.get("children"))
    if len(children) > 0:
        score += 2
    if _has_command_line_anomaly(process):
        score += 3
    if parent_is_suspicious:
        score += 2
    name = str(process.get("name") or process.get("image") or "").strip().lower()
    if name in _LOW_SIGNAL_SYSTEM_PROCESSES:
        score -= 3
    return score


def _intrinsic_process_relevance_score(process: dict[str, Any]) -> int:
    return _process_relevance_score(process, parent_is_suspicious=False)


def _suspicious_anchor_rank(row: dict[str, Any]) -> tuple[int, int, int, int, int, int, int]:
    proc = row.get("process") or {}
    counts = proc.get("event_counts") or {}
    cmd = str(proc.get("command_line") or proc.get("commandLine") or proc.get("cmd") or "").lower()
    suspicious_cmd = int(
        any(
            token in cmd
            for token in (
                " -enc",
                "frombase64string",
                "downloadstring",
                "iwr ",
                "invoke-webrequest",
                "rundll32",
                "regsvr32",
                "mshta",
                "powershell.exe -e",
            )
        )
    )
    name = str(proc.get("name") or proc.get("image") or row.get("label") or "").strip().lower()
    is_low_signal = int(name in _LOW_SIGNAL_SYSTEM_PROCESSES)
    network_threats = _as_int(counts.get("network_threats"))
    http_requests = _as_int(counts.get("http_requests"))
    modified_files = _as_int(counts.get("modified_files"))
    registry_changes = _as_int(counts.get("registry_changes"))
    network_total = (
        _as_int(counts.get("connections"))
        + http_requests
        + _as_int(counts.get("dns_requests"))
        + network_threats
    )
    intrinsic_score = _as_int(row.get("intrinsic_relevance_score"))
    relevance_score = _as_int(row.get("relevance_score"))
    direct_signal = _direct_anyrun_process_signal(proc)
    return (
        direct_signal,
        suspicious_cmd,
        network_threats + http_requests,
        modified_files + registry_changes,
        intrinsic_score,
        relevance_score,
        network_total,
        -is_low_signal,
    )


def _normalize_process_graph_rows(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ref: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for i, proc in enumerate(processes):
        pid = str(proc.get("pid") or "").strip()
        puid = str(proc.get("uuid") or proc.get("guid") or "").strip()
        node_key = puid or (f"pid:{pid}" if pid else f"idx:{i}")
        row = {
            "node_id": f"process:{node_key}",
            "parent_ref": str(proc.get("ppid") or proc.get("parentPid") or "").strip(),
            "pid": pid,
            "uuid": puid,
            "label": str(proc.get("name") or proc.get("fileName") or proc.get("image") or proc.get("processName") or f"process-{i}"),
            "process": dict(proc),
        }
        rows.append(row)
        if puid:
            by_ref[puid] = row
        if pid:
            by_ref[f"pid:{pid}"] = row
            by_ref[pid] = row

    for row in rows:
        parent_ref = row.get("parent_ref") or ""
        parent = by_ref.get(str(parent_ref)) if parent_ref else None
        row["parent_node_id"] = parent["node_id"] if isinstance(parent, dict) else ""
        row["children"] = []

    by_node_id = {row["node_id"]: row for row in rows}
    for row in rows:
        parent_node_id = str(row.get("parent_node_id") or "")
        if parent_node_id and parent_node_id in by_node_id:
            by_node_id[parent_node_id]["children"].append(row["node_id"])

    for row in rows:
        proc = row["process"]
        proc["children"] = list(row["children"])
        intrinsic_score = _intrinsic_process_relevance_score(proc)
        row["intrinsic_relevance_score"] = intrinsic_score
        row["process"]["intrinsic_relevance_score"] = intrinsic_score

    intrinsic_suspicious_nodes = {
        row["node_id"]
        for row in rows
        if _as_int(row.get("intrinsic_relevance_score")) >= 3
    }

    for row in rows:
        parent_id = str(row.get("parent_node_id") or "")
        parent_suspicious = parent_id in intrinsic_suspicious_nodes
        score = _process_relevance_score(row["process"], parent_is_suspicious=parent_suspicious)
        row["relevance_score"] = score
        row["process"]["relevance_score"] = score

    keep: set[str] = set()
    roots = [row for row in rows if not row.get("parent_node_id")]
    root_row = roots[0] if roots else (rows[0] if rows else None)
    if root_row:
        keep.add(root_row["node_id"])

    meaningful_rows = [row for row in rows if _is_meaningful_graph_process(row["process"])]
    suspicious_rows = [
        row
        for row in meaningful_rows
        if _is_detection_triggering_process(row["process"])
        or _as_int(row.get("intrinsic_relevance_score")) >= 3
        or _has_command_line_anomaly(row["process"])
    ]

    for row in meaningful_rows:
        keep.add(row["node_id"])

    # Show only the useful neighborhood around suspicious anchors: the parent,
    # the suspicious node, and its immediate children. This keeps execution
    # context visible without dragging every descendant into the graph.
    for row in suspicious_rows:
        keep.add(row["node_id"])
        parent_id = str(row.get("parent_node_id") or "")
        if parent_id:
            keep.add(parent_id)
        for child_id in _ensure_list(row.get("children")):
            child_id = str(child_id or "")
            if child_id:
                keep.add(child_id)

    # Connect any meaningful node back to its nearest visible ancestor so sibling
    # network/file activity remains readable without showing each quiet hop.
    for row in meaningful_rows:
        cur = row
        guard = 0
        while cur and guard < 200:
            parent_id = str(cur.get("parent_node_id") or "")
            if not parent_id:
                break
            keep.add(parent_id)
            parent_row = by_node_id.get(parent_id)
            if not parent_row or parent_id in keep:
                break
            cur = parent_row
            guard += 1

    if not meaningful_rows:
        candidate_rows = [row for row in rows if _as_int(row.get("intrinsic_relevance_score")) >= 3]
        if not candidate_rows:
            candidate_rows = [row for row in rows if _as_int(row.get("relevance_score")) >= 3]

        anchor_row = max(candidate_rows, key=_suspicious_anchor_rank) if candidate_rows else root_row
        cur = anchor_row
        guard = 0
        while cur and guard < 200:
            keep.add(cur["node_id"])
            parent_id = str(cur.get("parent_node_id") or "")
            cur = by_node_id.get(parent_id) if parent_id else None
            guard += 1

    for row in rows:
        row["kept"] = row["node_id"] in keep
    return [row for row in rows if row["kept"]]


def _collapse_low_signal_system_processes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return rows
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []
    for row in rows:
        proc = row["process"]
        name = str(proc.get("name") or row.get("label") or "").strip().lower()
        if name not in _LOW_SIGNAL_SYSTEM_PROCESSES or row.get("relevance_score", 0) >= 3:
            passthrough.append(row)
            continue
        key = (str(row.get("parent_node_id") or ""), name)
        groups.setdefault(key, []).append(row)

    collapsed: list[dict[str, Any]] = list(passthrough)
    for (_parent, name), group in groups.items():
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        representative = dict(group[0])
        representative["label"] = f"{group[0]['label']} ({len(group)} instances)"
        representative["process"] = dict(group[0]["process"])
        representative["process"]["collapsed_instances"] = len(group)
        representative["process"]["duplicate_count"] = len(group)
        representative["node_id"] = f"{group[0]['node_id']}:collapsed"
        collapsed.append(representative)
    by_old_to_new = {}
    for row in collapsed:
        proc = row["process"]
        duplicate_count = _as_int(proc.get("duplicate_count"))
        if duplicate_count > 1:
            base = str(row["node_id"]).replace(":collapsed", "")
            by_old_to_new[base] = row["node_id"]
    for row in collapsed:
        parent_node_id = str(row.get("parent_node_id") or "")
        if parent_node_id in by_old_to_new:
            row["parent_node_id"] = by_old_to_new[parent_node_id]
    collapsed.sort(key=lambda item: (str(item.get("parent_node_id") or ""), str(item.get("label") or "")))
    return collapsed


def _collapse_low_signal_system_chains(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return rows

    by_id = {str(row["node_id"]): row for row in rows}
    children: dict[str, list[str]] = {str(row["node_id"]): [] for row in rows}
    indegree: dict[str, int] = {str(row["node_id"]): 0 for row in rows}
    for row in rows:
        parent_id = str(row.get("parent_node_id") or "")
        node_id = str(row["node_id"])
        if parent_id and parent_id in by_id:
            children[parent_id].append(node_id)
            indegree[node_id] = indegree.get(node_id, 0) + 1

    def _eligible(row: dict[str, Any] | None) -> bool:
        if not isinstance(row, dict):
            return False
        proc = row.get("process") or {}
        name = str(proc.get("name") or row.get("label") or "").strip().lower()
        return (
            name in _LOW_SIGNAL_SYSTEM_PROCESSES
            and _as_int(row.get("intrinsic_relevance_score")) < 3
            and _as_int(row.get("relevance_score")) < 3
        )

    consumed: set[str] = set()
    collapsed_rows: list[dict[str, Any]] = []
    replacements: dict[str, str] = {}

    for row in rows:
        node_id = str(row["node_id"])
        if node_id in consumed:
            continue
        if not _eligible(row):
            collapsed_rows.append(row)
            continue

        parent_id = str(row.get("parent_node_id") or "")
        parent_row = by_id.get(parent_id) if parent_id else None
        parent_is_chain = _eligible(parent_row) and len(children.get(parent_id, [])) == 1 if parent_row else False
        if parent_is_chain:
            continue

        chain: list[dict[str, Any]] = [row]
        cur = row
        cur_id = node_id
        while True:
            child_ids = children.get(cur_id, [])
            if len(child_ids) != 1:
                break
            next_row = by_id.get(child_ids[0])
            if not _eligible(next_row):
                break
            chain.append(next_row)
            cur = next_row
            cur_id = str(cur["node_id"])

        if len(chain) <= 1:
            collapsed_rows.append(row)
            continue

        representative = dict(chain[0])
        representative["label"] = f"Windows system chain ({len(chain)} processes)"
        representative["node_id"] = f"{chain[0]['node_id']}:chain"
        representative["process"] = dict(chain[0].get("process") or {})
        representative["process"]["collapsed_chain_length"] = len(chain)
        representative["process"]["collapsed_chain_names"] = [
            str((item.get("process") or {}).get("name") or item.get("label") or "")
            for item in chain
        ]
        representative["process"]["name"] = representative["label"]
        representative["process"]["duplicate_count"] = len(chain)
        representative["intrinsic_relevance_score"] = max(_as_int(item.get("intrinsic_relevance_score")) for item in chain)
        representative["relevance_score"] = max(_as_int(item.get("relevance_score")) for item in chain)
        collapsed_rows.append(representative)

        for item in chain:
            item_id = str(item["node_id"])
            consumed.add(item_id)
            replacements[item_id] = representative["node_id"]

    for row in collapsed_rows:
        parent_id = str(row.get("parent_node_id") or "")
        if parent_id in replacements:
            row["parent_node_id"] = replacements[parent_id]

    deduped: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in collapsed_rows:
        node_id = str(row["node_id"])
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        deduped.append(row)

    deduped.sort(key=lambda item: (str(item.get("parent_node_id") or ""), str(item.get("label") or "")))
    return deduped


def _extract_process_details(
    report_data: dict[str, Any],
    processes: list[Any],
    *,
    dns_requests: list[Any] | None = None,
    http_requests: list[Any] | None = None,
    connections: list[Any] | None = None,
    network_threats: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Normalize per-process details (metadata + grouped events) for AnyRun-like deep process view.
    """
    out: list[dict[str, Any]] = []
    proc_rows = _ensure_list(processes)
    dns_requests = _ensure_list(dns_requests)
    http_requests = _ensure_list(http_requests)
    connections = _ensure_list(connections)
    network_threats = _ensure_list(network_threats)
    process_name_counts: dict[str, int] = {}
    for proc in proc_rows:
        if not isinstance(proc, dict):
            continue
        pname = str(proc.get("fileName") or proc.get("image") or proc.get("processName") or proc.get("name") or "").strip().lower()
        if pname:
            process_name_counts[pname] = process_name_counts.get(pname, 0) + 1

    def _matches_process(ev: dict[str, Any], *, pid: Any, puid: Any, name: Any) -> bool:
        pid_ref = str(pid or "").strip()
        uuid_ref = str(puid or "").strip()
        name_ref = str(name or "").strip().lower()
        process_ref = str(ev.get("process") or "").strip()

        ev_pid_refs = {
            str(ev.get("pid") or "").strip(),
        }
        ev_pid_refs.discard("")
        if pid_ref and pid_ref in ev_pid_refs:
            return True

        ev_uuid_refs = {
            process_ref,
            str(ev.get("processUuid") or "").strip(),
            str(ev.get("uuid") or "").strip(),
            str(ev.get("guid") or "").strip(),
        }
        ev_uuid_refs.discard("")
        if uuid_ref and uuid_ref in ev_uuid_refs:
            return True

        ev_name = str(ev.get("processName") or ev.get("name") or "").strip().lower()
        if (
            name_ref
            and ev_name
            and name_ref == ev_name
            and process_name_counts.get(name_ref, 0) == 1
            and not ev_pid_refs
            and not ev_uuid_refs
        ):
            return True

        return False

    for idx, proc in enumerate(proc_rows):
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        ppid = proc.get("ppid") or proc.get("parentPid")
        puid = proc.get("uuid") or proc.get("guid")
        pname = proc.get("fileName") or proc.get("image") or proc.get("processName") or proc.get("name")

        def _take_list(v: Any, limit: int = 120) -> list[Any]:
            return _ensure_list(v)[:limit]

        ev_http = _take_list(proc.get("httpRequests") or proc.get("http"))
        ev_conn = _take_list(proc.get("connections"))
        ev_threats = _take_list(proc.get("networkThreats") or proc.get("threats"))
        ev_dns = _take_list(proc.get("dnsRequests"))
        if not ev_dns:
            ev_dns = [x for x in dns_requests if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_http:
            ev_http = [x for x in http_requests if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_conn:
            ev_conn = [x for x in connections if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_threats:
            ev_threats = [x for x in network_threats if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]

        events = {
            "modified_files": _take_list(proc.get("modifiedFiles") or proc.get("files_modified")),
            "created_files": _take_list(proc.get("createdFiles") or proc.get("files_created")),
            "dropped_files": _take_list(proc.get("droppedFiles") or proc.get("files_dropped")),
            "deleted_files": _take_list(proc.get("deletedFiles") or proc.get("files_deleted")),
            "registry_changes": _take_list(proc.get("registryChanges") or proc.get("registry")),
            "synchronization": _take_list(proc.get("synchronization")),
            "dns_requests": ev_dns,
            "http_requests": ev_http,
            "connections": ev_conn,
            "network_threats": ev_threats,
            "modules": _take_list(proc.get("modules")),
            "debug": _take_list(proc.get("debug")),
        }
        event_counts = {k: len(v) for k, v in events.items()}

        out.append(
            {
                "id": proc.get("id") or f"proc-{idx}",
                "uuid": puid,
                "pid": pid,
                "ppid": ppid,
                "name": pname,
                "image": proc.get("image"),
                "file_path": proc.get("filePath") or proc.get("path"),
                "command_line": proc.get("commandLine") or proc.get("cmd"),
                "username": (
                    proc.get("user")
                    or proc.get("username")
                    or proc.get("userName")
                    or ((proc.get("context") or {}).get("userName") if isinstance(proc.get("context"), dict) else None)
                ),
                "sid": proc.get("sid"),
                "integrity_level": (
                    proc.get("integrityLevel")
                    or proc.get("integrity_level")
                    or proc.get("il")
                    or ((proc.get("context") or {}).get("integrityLevel") if isinstance(proc.get("context"), dict) else None)
                ),
                "company": (
                    proc.get("company")
                    or proc.get("companyName")
                    or ((proc.get("versionInfo") or {}).get("company") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "description": (
                    proc.get("description")
                    or proc.get("fileDescription")
                    or ((proc.get("versionInfo") or {}).get("description") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "version": (
                    proc.get("version")
                    or proc.get("productVersion")
                    or ((proc.get("versionInfo") or {}).get("version") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "start": (
                    proc.get("start")
                    or proc.get("startedAt")
                    or proc.get("time")
                    or ((proc.get("times") or {}).get("start") if isinstance(proc.get("times"), dict) else None)
                ),
                "threat_level": (
                    proc.get("threatLevel")
                    or (((proc.get("scores") or {}).get("verdict") or {}).get("threatLevel") if isinstance(proc.get("scores"), dict) else None)
                ),
                "threat_score": proc.get("threatScore") or proc.get("score"),
                "threat_name": _ensure_list(proc.get("threatName")),
                "is_malconf": bool(proc.get("isMalconf")),
                "scores": proc.get("scores") if isinstance(proc.get("scores"), dict) else None,
                "cert": proc.get("cert") if isinstance(proc.get("cert"), dict) else None,
                "events": events,
                "event_counts": event_counts,
            }
        )
    return out


def _is_sparse_lookup_result(result: dict[str, Any]) -> bool:
    raw = result.get("raw_summary") or {}
    summary = raw.get("summary") or {}
    details = _ensure_list(summary.get("details"))
    io = result.get("dynamic_io_summary") or {}
    domains = _ensure_list(io.get("domains"))
    hosts = _ensure_list(io.get("hosts"))
    ports = _ensure_list(raw.get("destinationPort")) or _ensure_list(io.get("destinationPort"))
    geo = _ensure_list(raw.get("destinationIPgeo")) or _ensure_list(io.get("destinationIPgeo"))
    related_tasks = _ensure_list(raw.get("relatedTasks"))
    behavior_details = raw.get("behavior_details") or {}
    process_details = _ensure_list((behavior_details or {}).get("process_details"))
    processes = _ensure_list((behavior_details or {}).get("processes"))
    dns_requests = _ensure_list((behavior_details or {}).get("dns_requests"))
    http_requests = _ensure_list((behavior_details or {}).get("http_requests"))
    connections = _ensure_list((behavior_details or {}).get("connections"))
    analysis_id = str(result.get("analysis_id") or "").strip()
    has_behavior = (
        len(processes) > 0
        or len(process_details) > 0
        or len(dns_requests) > 0
        or len(http_requests) > 0
        or len(connections) > 0
    )
    # A linked analysis_id without actual behavioral rows means AnyRun has a prior
    # record for this indicator but the lookup endpoint didn't return live detail.
    # Treat this as sparse so a fresh sandbox submission is triggered to fill the gap.
    if analysis_id:
        return not has_behavior
    return (
        len(details) == 0
        and len(domains) == 0
        and len(hosts) == 0
        and len(ports) == 0
        and len(geo) == 0
        and len(related_tasks) == 0
        and not has_behavior
    )


def _error(indicator_type: str, message: str, mode: str = "lookup") -> dict[str, Any]:
    return {
        "checked": False,
        "indicator_type": indicator_type,
        "verdict": "unknown",
        "error": message,
        "raw_summary": {"source": "anyrun", "mode": mode},
    }


def _safe_close(conn: Any) -> None:
    if conn is None:
        return
    close = getattr(conn, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass
