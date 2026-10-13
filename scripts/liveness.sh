#!/usr/bin/env bash
# One line for the end of every report: tree state, and whether the running
# processes are on the code that was just committed.
#
# Why this exists. On 2026-10-13 the ThreatFox scoping fix was committed at
# 10:53 and produced a false malicious/high/block verdict on live.com at
# 12:05, because `analysis_task` runs in the Celery worker, the worker does
# not reload, and its process had started at 09:21:06. "Fixed" was true of
# the source and false of the running system for three hours.
#
# `code_version` and the worker-fingerprint-through-the-broker check both
# already existed that morning, built for exactly this, and neither was run
# after the commit that needed them. **A tool you have to remember to use is
# not a control.** So this folds the check into the sentence that already
# ends every report, where a stale process becomes visible in the habit
# rather than in a forensic reconstruction.
#
# The worker's fingerprint is read through the broker, never with
# `docker compose exec worker python`: that spawns a new interpreter which
# re-imports from the bind mount, so it reports the source and never the
# process — which is how a two-hour staleness stayed invisible on
# 2026-10-12.
#
# Usage:  scripts/liveness.sh
# Output: tree clean, pushed · api 6cdf5513 · worker 6cdf5513 · in sync
#     or: tree clean, pushed · api 6cdf5513 · worker 1a2b3c4d · SKEWED — restart worker

set -uo pipefail
cd "$(dirname "$0")/.."

# ── tree and push state ───────────────────────────────────────────────────
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    tree="tree DIRTY"
else
    tree="tree clean"
fi

branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")
upstream=$(git rev-parse --abbrev-ref "@{upstream}" 2>/dev/null || echo "")
if [[ -z "$upstream" ]]; then
    push="no upstream"
else
    ahead=$(git rev-list --count "$upstream..HEAD" 2>/dev/null || echo "?")
    if [[ "$ahead" == "0" ]]; then
        push="pushed"
    else
        push="$ahead UNPUSHED"
    fi
fi

# ── the running processes ─────────────────────────────────────────────────
# Both read at the same moment. `code_fingerprint` is a content hash of the
# loaded *.py taken at import time, so it identifies the process and not the
# file on disk.
api=$(docker compose exec -T -e PYTHONPATH=/app api python -c '
from app.code_version import code_version
print(code_version().get("code_fingerprint") or "none")
' 2>/dev/null | tr -d "\r" | grep -oE "^[0-9a-f]{64}$" || true)

worker=$(docker compose exec -T -e PYTHONPATH=/app api python -c '
from app.tasks.celery_app import celery_app
try:
    r = celery_app.send_task("app.tasks.pipeline_watch_task.code_version")
    print(r.get(timeout=45).get("code_fingerprint") or "none")
except Exception as exc:
    print(f"unreachable: {type(exc).__name__}")
' 2>/dev/null | tr -d "\r" | tail -1 || true)

short() { [[ -n "${1:-}" && "$1" != unreachable* ]] && echo "${1:0:8}" || echo "${1:-unknown}"; }

line="$tree, $push · api $(short "$api") · worker $(short "$worker")"

if [[ -z "$api" || -z "$worker" ]]; then
    line="$line · CANNOT VERIFY — a missing fingerprint is not a match"
elif [[ "$api" == "$worker" ]]; then
    line="$line · in sync"
else
    # The direction that bit: api reloaded, worker did not.
    line="$line · SKEWED — docker compose restart worker beat"
fi

# A commit that has not reached the running process is the case this exists
# for, so say it even when the fingerprints agree with each other.
if [[ "$push" != "pushed" || "$tree" != "tree clean" ]]; then
    line="$line · uncommitted or unpushed work is not running anywhere"
fi

echo "$line"

# Exit non-zero on skew or on a fingerprint we could not read, so this can
# gate something later. A check that cannot fail is decoration.
[[ -n "$api" && "$api" == "$worker" ]] || exit 1
