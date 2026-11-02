#!/usr/bin/env python3
"""
Run end-to-end diagnostics for Celery-backed investigations.

What it checks:
1. API is reachable.
2. Celery worker responds to inspect ping.
3. Investigations complete for representative observable types.
4. Evidence contains collector status/duration metadata.
5. Domain/URL runs include screenshot and js_analysis sections.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests


CASES = [
    {"label": "domain", "domain": "example.com", "observable_type": "domain"},
    {"label": "url", "domain": "https://example.com", "observable_type": "url"},
    {"label": "ip", "domain": "1.1.1.1", "observable_type": "ip"},
    {
        "label": "hash",
        "domain": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "observable_type": "hash",
    },
]


def _iso_to_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None


def _check_celery_ping(repo_root: Path, timeout_sec: int) -> tuple[bool, str]:
    celery_exe = repo_root / "backend" / "venv" / "Scripts" / "celery.exe"
    if not celery_exe.exists():
        return False, f"Missing Celery executable: {celery_exe}"
    cmd = [
        str(celery_exe),
        "-A",
        "app.tasks.celery_app",
        "inspect",
        "ping",
        "--timeout",
        str(timeout_sec),
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(repo_root / "backend"),
        capture_output=True,
        text=True,
        check=False,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0 and "pong" in out.lower()
    return ok, out.strip()


def _start_case(base_url: str, payload: dict[str, Any]) -> str:
    r = requests.post(f"{base_url}/investigations", json=payload, timeout=30)
    r.raise_for_status()
    data = r.json()
    return data["investigation_id"]


def _poll_detail(base_url: str, inv_id: str, timeout_sec: int) -> dict[str, Any]:
    deadline = time.time() + timeout_sec
    last = {}
    while time.time() < deadline:
        r = requests.get(f"{base_url}/investigations/{inv_id}", timeout=30)
        r.raise_for_status()
        last = r.json()
        if last.get("state") in ("concluded", "failed"):
            return last
        time.sleep(3)
    raise TimeoutError(f"Timed out waiting for investigation {inv_id}")


def _safe_get_json(url: str) -> dict[str, Any] | None:
    r = requests.get(url, timeout=30)
    if r.status_code >= 400:
        return None
    return r.json()


def _collector_summary(evidence: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not evidence:
        return {}
    key_map = {
        "dns": "dns",
        "http": "http",
        "tls": "tls",
        "whois": "whois",
        "asn": "hosting",
        "intel": "intel",
        "vt": "vt",
        "threat_feeds": "threat_feeds",
        "urlscan": "urlscan",
    }
    out: dict[str, dict[str, Any]] = {}
    for name, ev_key in key_map.items():
        item = evidence.get(ev_key) or {}
        meta = item.get("meta") or {}
        if meta:
            out[name] = {
                "status": meta.get("status"),
                "duration_ms": meta.get("duration_ms"),
                "error": meta.get("error"),
            }
    return out


def run(base_url: str, timeout_sec: int, include: set[str], repo_root: Path) -> int:
    print(f"[diag] API base: {base_url}")

    api_probe = requests.get(f"{base_url}/investigations?limit=1", timeout=20)
    api_probe.raise_for_status()
    print("[diag] API reachable: OK")

    celery_ok, celery_out = _check_celery_ping(repo_root, timeout_sec=5)
    print(f"[diag] Celery ping: {'OK' if celery_ok else 'FAILED'}")
    if celery_out:
        print(celery_out)

    failures: list[str] = []

    for case in CASES:
        if case["label"] not in include:
            continue

        payload = {
            "domain": case["domain"],
            "observable_type": case["observable_type"],
        }
        print(f"\n[diag] Starting {case['label']} -> {case['domain']}")
        inv_id = _start_case(base_url, payload)
        detail = _poll_detail(base_url, inv_id, timeout_sec=timeout_sec)
        evidence = _safe_get_json(f"{base_url}/investigations/{inv_id}/evidence")
        report = _safe_get_json(f"{base_url}/investigations/{inv_id}/report")

        started = _iso_to_dt(detail.get("created_at"))
        ended = _iso_to_dt(detail.get("concluded_at"))
        total_ms = int((ended - started).total_seconds() * 1000) if started and ended else None

        collectors = _collector_summary(evidence)
        completed_count = sum(1 for c in collectors.values() if c.get("status") == "completed")

        print(json.dumps({
            "id": inv_id,
            "state": detail.get("state"),
            "classification": detail.get("classification"),
            "total_duration_ms": total_ms,
            "collectors": collectors,
            "has_screenshot": bool((evidence or {}).get("screenshot")),
            "has_js_analysis": bool((evidence or {}).get("js_analysis")),
        }, indent=2))

        if detail.get("state") != "concluded":
            failures.append(f"{case['label']}: state={detail.get('state')}")
        if not evidence:
            failures.append(f"{case['label']}: missing evidence")
        if not report:
            failures.append(f"{case['label']}: missing report")
        if completed_count == 0:
            failures.append(f"{case['label']}: no collectors completed")
        if case["label"] in {"domain", "url"}:
            if not (evidence or {}).get("screenshot"):
                failures.append(f"{case['label']}: missing screenshot section")
            if not (evidence or {}).get("js_analysis"):
                failures.append(f"{case['label']}: missing js_analysis section")

    if not celery_ok:
        failures.append("celery ping failed")

    if failures:
        print("\n[diag] FAILURES")
        for f in failures:
            print(f" - {f}")
        return 1

    print("\n[diag] All checks passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Celery collector diagnostics")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api")
    parser.add_argument("--timeout-sec", type=int, default=360)
    parser.add_argument(
        "--only",
        default="domain,url,ip,hash",
        help="Comma-separated subset: domain,url,ip,hash",
    )
    args = parser.parse_args()

    include = {x.strip() for x in args.only.split(",") if x.strip()}
    repo_root = Path(__file__).resolve().parents[2]
    return run(args.base_url.rstrip("/"), args.timeout_sec, include, repo_root)


if __name__ == "__main__":
    raise SystemExit(main())

