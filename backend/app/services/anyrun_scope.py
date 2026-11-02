"""Scope ANY.RUN lookup matches to the observable that was actually investigated."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def task_matches_domain(task: dict[str, Any], domain: str) -> bool:
    """True only when the task's main object is hosted on domain/subdomain.

    Domain text in a URL query, path, userinfo, or fragment is deliberately not
    ownership evidence. This prevents phishing URLs containing victim email
    addresses from poisoning the reputation of the victim's legitimate domain.
    """
    expected = str(domain or "").strip().lower().rstrip(".").removeprefix("www.")
    if not expected or not isinstance(task, dict):
        return False
    main = task.get("mainObject") or task.get("main_object") or {}
    if not isinstance(main, dict):
        return False
    value = str(main.get("name") or main.get("url") or main.get("domain") or "").strip()
    object_type = str(main.get("type") or "").strip().lower()
    if not value:
        return False
    if object_type == "domain" and "://" not in value:
        host = value.lower().rstrip(".").removeprefix("www.")
    else:
        try:
            host = str(urlparse(value if "://" in value else f"https://{value}").hostname or "").lower().rstrip(".").removeprefix("www.")
        except Exception:
            return False
    return host == expected or host.endswith(f".{expected}")


def scope_anyrun_lookup_item(item: dict[str, Any], *, indicator: str, indicator_type: str) -> dict[str, Any]:
    """Annotate and, where necessary, downgrade out-of-scope domain lookup hits."""
    # Keep large report payloads and screenshots shared; only the dictionaries
    # whose decision-facing fields we change need copies.
    scoped = dict(item or {})
    raw = dict(scoped.get("raw_summary") or {})
    if not isinstance(raw, dict) or str(raw.get("mode") or scoped.get("mode") or "").lower() != "lookup":
        return scoped
    if str(indicator_type or "").lower() != "domain":
        return scoped

    tasks = raw.get("relatedTasks") or raw.get("sourceTasks") or []
    if not isinstance(tasks, list) or not tasks:
        return scoped
    matched = [task for task in tasks if isinstance(task, dict) and task_matches_domain(task, indicator)]
    excluded = len(tasks) - len(matched)
    scope = {
        "checked": True,
        "scope_match": bool(matched),
        "indicator": indicator,
        "matched_tasks": len(matched),
        "excluded_tasks": excluded,
        "reason": (
            "Related task main-object host matches the investigated domain."
            if matched else
            "Related tasks mention the domain but their main-object hosts are third-party infrastructure."
        ),
    }
    raw["scope_validation"] = scope
    scoped["scope_validation"] = scope

    if not matched:
        scoped["provider_verdict"] = scoped.get("provider_verdict") or scoped.get("verdict")
        scoped["verdict"] = "unknown"
        scoped["threat_score"] = None
        scoped["tags"] = []
        raw["provider_verdict"] = scoped.get("provider_verdict")
        raw["anyrun_ai_summary"] = "AnyRun lookup matches were excluded because no related task was hosted on the investigated domain."
        raw["tags"] = []
        raw["threatName"] = []
        if isinstance(raw.get("summary"), dict):
            raw["summary"] = {**raw["summary"], "tags": [], "threatName": [], "tracker": None}
        scoped["raw_summary"] = raw
        return scoped

    # Recompute the lookup verdict from in-scope tasks only. The provider's
    # aggregate summary may include unrelated tasks found by textual mention.
    levels = []
    matched_tags: list[str] = []
    for task in matched:
        try:
            levels.append(int(task.get("threatLevel") or 0))
        except (TypeError, ValueError):
            pass
        for tag in task.get("tags") or []:
            text = str(tag or "").strip()
            if text and text not in matched_tags:
                matched_tags.append(text)
    highest = max(levels or [0])
    verdict = "malicious" if highest >= 2 else ("suspicious" if highest == 1 else "clean")
    scoped["provider_verdict"] = scoped.get("provider_verdict") or scoped.get("verdict")
    scoped["verdict"] = verdict
    scoped["threat_score"] = 100.0 if highest >= 3 else (70.0 if highest == 2 else (40.0 if highest == 1 else 0.0))
    scoped["tags"] = matched_tags
    raw["relatedTasksInScope"] = matched
    raw["anyrun_ai_summary"] = f"AnyRun in-scope domain lookup verdict: {verdict.upper()} from {len(matched)} matching task(s); {excluded} textual/out-of-scope task(s) excluded."
    raw["tags"] = matched_tags
    raw["threatName"] = matched_tags
    if isinstance(raw.get("summary"), dict):
        raw["summary"] = {
            **raw["summary"],
            "tags": matched_tags,
            "threatName": matched_tags,
            "tracker": None,
            "threatLevel": highest,
        }
    scoped["raw_summary"] = raw
    return scoped


def apply_anyrun_scope_guard(evidence: dict[str, Any]) -> dict[str, Any]:
    """Apply domain scoping to all lookup items in an evidence payload in place."""
    if not isinstance(evidence, dict):
        return evidence
    domain = str(evidence.get("domain") or "")
    observable_type = str(evidence.get("observable_type") or "domain")
    hybrid = evidence.get("hybrid_analysis")
    if not isinstance(hybrid, dict):
        return evidence
    items = hybrid.get("items")
    if isinstance(items, list):
        hybrid["items"] = [
            scope_anyrun_lookup_item(item, indicator=domain, indicator_type=observable_type)
            if isinstance(item, dict) else item
            for item in items
        ]
    else:
        guarded = scope_anyrun_lookup_item(hybrid, indicator=domain, indicator_type=observable_type)
        evidence["hybrid_analysis"] = guarded
    return evidence
