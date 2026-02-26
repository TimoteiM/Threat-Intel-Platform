from __future__ import annotations

import re
import socket
import subprocess
from typing import Any


def _port_owners_windows(port: int) -> list[str]:
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return []

    pids: set[str] = set()
    needle = f":{port}"
    for line in proc.stdout.splitlines():
        if "LISTENING" not in line.upper():
            continue
        if needle not in line:
            continue
        cols = line.split()
        if cols:
            pid = cols[-1].strip()
            if pid.isdigit():
                pids.add(pid)
    return sorted(pids)


def get_api_port_report(port: int = 8000) -> dict[str, Any]:
    pids = _port_owners_windows(port)
    warnings: list[str] = []
    if len(pids) > 1:
        warnings.append(
            f"Multiple processes are listening on TCP {port}: {', '.join(pids)}. "
            "This can indicate duplicate API runtimes."
        )
    return {
        "port": port,
        "listener_pids": pids,
        "warning_count": len(warnings),
        "warnings": warnings,
    }


def _is_likely_container_hostname(name: str) -> bool:
    host = name.split("@", 1)[-1].strip().lower()
    return bool(re.fullmatch(r"[a-f0-9]{10,64}", host))


def get_celery_worker_report() -> dict[str, Any]:
    warnings: list[str] = []
    try:
        nodes = _inspect_celery_nodes()
    except Exception as exc:
        return {
            "nodes": [],
            "node_count": 0,
            "warnings": [f"Unable to inspect celery workers: {exc}"],
            "warning_count": 1,
        }

    local_host = socket.gethostname().lower()
    has_local = any(node.split("@", 1)[-1].lower() == local_host for node in nodes)
    has_container_like = any(_is_likely_container_hostname(node) for node in nodes)

    if len(nodes) > 1:
        warnings.append(
            f"{len(nodes)} celery workers detected: {', '.join(nodes)}. "
            "Ensure this is intentional."
        )
    if has_local and has_container_like:
        warnings.append(
            "Detected mixed local + container celery workers on the same broker. "
            "Use a single runtime mode to avoid duplicate processing."
        )

    return {
        "nodes": nodes,
        "node_count": len(nodes),
        "warnings": warnings,
        "warning_count": len(warnings),
    }


def _inspect_celery_nodes() -> list[str]:
    from app.tasks.celery_app import celery_app

    inspector = celery_app.control.inspect(timeout=1)
    ping = inspector.ping() or {}
    return sorted(ping.keys())


def build_runtime_guardrail_report() -> dict[str, Any]:
    api = get_api_port_report(8000)
    workers = get_celery_worker_report()
    warnings = [*api["warnings"], *workers["warnings"]]
    return {
        "ok": len(warnings) == 0,
        "warnings": warnings,
        "api_runtime": api,
        "celery_runtime": workers,
    }
