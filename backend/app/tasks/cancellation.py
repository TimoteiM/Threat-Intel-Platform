from __future__ import annotations

import ast
import logging
from typing import Any

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def revoke_task_ids(task_ids: list[str]) -> list[str]:
    revoked: list[str] = []
    for task_id in task_ids:
        tid = str(task_id or "").strip()
        if not tid:
            continue
        try:
            celery_app.control.revoke(tid, terminate=True, signal="SIGTERM")
            revoked.append(tid)
        except Exception as exc:
            logger.warning("Failed to revoke task %s: %s", tid, exc)
    return revoked


def find_task_ids(
    *,
    task_name: str,
    kwarg_key: str | None = None,
    kwarg_value: str | None = None,
    first_arg_value: str | None = None,
) -> list[str]:
    """
    Best-effort task discovery in Celery workers across active/reserved/scheduled.
    """
    out: list[str] = []
    try:
        inspect = celery_app.control.inspect(timeout=1)
        snapshots = [
            inspect.active() or {},
            inspect.reserved() or {},
            inspect.scheduled() or {},
        ]
    except Exception as exc:
        logger.warning("Celery inspect failed while finding task ids: %s", exc)
        return out

    for snap in snapshots:
        for tasks in (snap or {}).values():
            for entry in tasks or []:
                req = _extract_request(entry)
                if not isinstance(req, dict):
                    continue
                if str(req.get("name") or "") != task_name:
                    continue
                if not _matches(req, kwarg_key=kwarg_key, kwarg_value=kwarg_value, first_arg_value=first_arg_value):
                    continue
                tid = str(req.get("id") or "").strip()
                if tid and tid not in out:
                    out.append(tid)
    return out


def _extract_request(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict) and isinstance(entry.get("request"), dict):
        return entry.get("request") or {}
    if isinstance(entry, dict):
        return entry
    return {}


def _matches(
    req: dict[str, Any],
    *,
    kwarg_key: str | None,
    kwarg_value: str | None,
    first_arg_value: str | None,
) -> bool:
    kwargs = _coerce_mapping(req.get("kwargs"))
    args = _coerce_sequence(req.get("args"))

    if kwarg_key and kwarg_value is not None:
        if str(kwargs.get(kwarg_key) or "") != str(kwarg_value):
            return False

    if first_arg_value is not None:
        if not args:
            return False
        if str(args[0]) != str(first_arg_value):
            return False

    return True


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _coerce_sequence(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, (list, tuple)):
                return list(parsed)
        except Exception:
            return []
    return []
