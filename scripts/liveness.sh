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
# It checks two kinds of drift, because both have bitten and both are
# invisible without asking:
#
#   CODE drift   the api reloads on a file change, the Celery worker does not.
#   ENV  drift   `env_file:` is read when a container is CREATED. `restart`
#                reuses the old environment, and `up -d` often sees no config
#                change and exits 0 having done nothing. Three variables have
#                now been in .env and in no container — SPAMHAUS_API_KEY on
#                2026-10-14 being the third. `docs/deploy/schema-changes.md`
#                has carried that row the whole time and prevented none of
#                them, because a row is something you have to remember.
#
# Usage:  scripts/liveness.sh
# Output: tree clean, pushed · api 6cdf5513 · worker 6cdf5513 · in sync · env ok
#     or: ... · worker 1a2b3c4d · SKEWED — restart worker
#     or: ... · in sync · ENV DRIFT: 1 var in .env not in api — recreate

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

# ── env drift ─────────────────────────────────────────────────────────────
# Compare the env NAMES each service is DECLARED to have against the names
# its container actually has.
#
# The expectation comes from `docker compose config`, which resolves
# `env_file:` plus each service's own `environment:` block — not from .env
# directly. That distinction matters: a variable deliberately given to one
# service and not another is not drift, and comparing against raw .env would
# report it as such on every run. A check that cries wolf is a check people
# stop reading, which is the failure the per-verdict coverage work already
# made once.
#
# Names only, throughout. No value is ever read, compared, printed or
# logged, so a credential cannot reach a terminal or a commit through this.
env_note=""
env_bad=0
_names_py='
import json,sys
cfg = json.load(sys.stdin)
env = (cfg.get("services", {}).get(sys.argv[1], {}) or {}).get("environment") or {}
names = sorted(env.keys()) if isinstance(env, dict) else sorted(
    str(e).split("=", 1)[0] for e in env)
print("\n".join(n for n in names if n))
'
_compose_json=$(docker compose config --format json 2>/dev/null || true)
if [[ -n "$_compose_json" ]]; then
    for svc in api worker beat; do
        want=$(printf '%s' "$_compose_json" \
               | python3 -c "$_names_py" "$svc" 2>/dev/null | sort -u)
        have=$(docker compose exec -T "$svc" sh -lc \
                 'env | grep -oE "^[A-Za-z_][A-Za-z0-9_]*="' 2>/dev/null \
               | tr -d '=' | sort -u)
        if [[ -z "$want" ]]; then
            continue                      # service not declared; nothing to check
        fi
        if [[ -z "$have" ]]; then
            # Not running, or unreachable. Absence is not agreement.
            env_note="$env_note ${svc}=unreachable"
            env_bad=1
            continue
        fi
        missing=$(comm -23 <(echo "$want") <(echo "$have"))
        n=$(echo "$missing" | grep -c . || true)
        if (( n > 0 )); then
            env_note="$env_note ${svc}=${n}"
            env_bad=1
        fi
    done
fi


# ── the frontend: a built image, so it does not reload ────────────────────
# Third deployment-liveness gap this week, after the api process and env
# drift. The integrations page, its nav entry and its API client were
# committed at 07:48 and `GET /integrations` returned 404 for three hours:
# `frontend` has a `build:` stanza with no volume mount, so the container
# serves whatever was compiled when it was built, and that one was 28 hours
# old. This script said `env ok · in sync` the whole time, because its only
# code check was the api/worker Python fingerprint.
#
# The pieces for the check already existed and asked a person to do it by
# hand: next.config.js hashes src/ at build time into
# NEXT_PUBLIC_BUILD_FINGERPRINT, the layout renders it as a meta tag, and
# BuildStampClient logs bundle-vs-html to the console with "compare with
# /health for the API". An instrument that tells you to run the comparison
# yourself is one check short, so the comparison is here.
#
# Reproduces sourceFingerprint() from next.config.js exactly: sha256 over
# src/**/*.{ts,tsx,js,jsx,css}, each file contributing its path relative to
# src, a NUL, then its bytes, with every directory entry visited in
# name-sorted order. Content, not mtimes.
_fe_fp_py='
import hashlib, os, re, sys
root = sys.argv[1]
EXT = re.compile(r"\.(ts|tsx|js|jsx|css)$")
d = hashlib.sha256()
n = 0
def walk(path):
    global n
    for entry in sorted(os.scandir(path), key=lambda e: e.name):
        if entry.is_dir():
            walk(entry.path)
        elif EXT.search(entry.name):
            d.update(os.path.relpath(entry.path, root).encode())
            d.update(b"\0")
            with open(entry.path, "rb") as fh:
                d.update(fh.read())
            n += 1
try:
    walk(root)
except OSError as err:
    # Named, not blank, for the same reason next.config.js names it: an empty
    # value renders as "unknown" and reads as "fine".
    print("unreadable", 0)
    raise SystemExit(0)
print(d.hexdigest(), n)
'
_fe_src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/frontend/src"
fe_expected=""
fe_files=""
if [[ -d "$_fe_src" ]]; then
    read -r fe_expected fe_files < <(python3 -c "$_fe_fp_py" "$_fe_src" 2>/dev/null || echo "")
fi

# The meta tag, not the bundle: it arrives with the HTML, which is not cached
# the way hashed JS is, so it describes the build this container is serving.
fe_html=$(curl -s --max-time 10 http://localhost:3000/ 2>/dev/null || true)
fe_served=$(printf '%s' "$fe_html" \
            | grep -oE 'name="x-build-fingerprint" content="[^"]*"' \
            | sed 's/.*content="//; s/"$//' | head -1)

fe_note=""
fe_bad=0
if [[ -z "$fe_expected" || "$fe_expected" == "unreadable" ]]; then
    fe_note="frontend src unreadable"
    fe_bad=1
elif [[ -z "$fe_html" ]]; then
    fe_note="frontend unreachable"
    fe_bad=1
elif [[ -z "$fe_served" ]]; then
    # A served page with no stamp is an old build from before the stamp
    # existed, which is itself staleness — not an inconclusive result.
    fe_note="frontend serves no build stamp"
    fe_bad=1
elif [[ "$fe_served" != "$fe_expected" ]]; then
    fe_note="frontend STALE — docker compose build frontend && docker compose up -d frontend"
    fe_bad=1
fi

line="$tree, $push · api $(short "$api") · worker $(short "$worker")"

if [[ -z "$api" || -z "$worker" ]]; then
    line="$line · CANNOT VERIFY — a missing fingerprint is not a match"
elif [[ "$api" == "$worker" ]]; then
    line="$line · in sync"
elif [[ "$tree" != "tree clean" ]]; then
    # Separated deliberately. `code_fingerprint` hashes every *.py under the
    # root at import time, and the api runs --reload, so ANY edit — including
    # a new file nothing imports — moves the api's hash and not the worker's.
    # On a box where someone is editing, an undifferentiated SKEWED is
    # therefore permanently red, which is how a monitor stops being read.
    # This case is implied by the dirty tree and is not independently
    # actionable; the next line says the edits are not running anywhere.
    line="$line · skew expected (tree dirty, api reloads)"
else
    # The dangerous case, and the one this exists for: the tree is clean, so
    # the api is running committed code and the worker is running something
    # older. This is the shape that left a pre-fix decision_engine serving
    # verdicts for 92 minutes after the fix was committed.
    line="$line · SKEWED — worker behind committed code — docker compose restart worker beat"
fi

if (( fe_bad )); then
    line="$line · fe $(short "${fe_served:-none}") · ${fe_note}"
else
    line="$line · fe $(short "$fe_served") in sync"
fi

if (( env_bad )); then
    # Counts on the line, names underneath — the line stays scannable and
    # the actionable detail is still right there, not in another command.
    line="$line · ENV DRIFT:${env_note} — docker compose up -d --force-recreate"
else
    line="$line · env ok"
fi

# A commit that has not reached the running process is the case this exists
# for, so say it even when the fingerprints agree with each other.
if [[ "$push" != "pushed" || "$tree" != "tree clean" ]]; then
    line="$line · uncommitted or unpushed work is not running anywhere"
fi

echo "$line"

if (( env_bad )) && [[ -n "$_compose_json" ]]; then
    for svc in api worker beat; do
        want=$(printf '%s' "$_compose_json" \
               | python3 -c "$_names_py" "$svc" 2>/dev/null | sort -u)
        have=$(docker compose exec -T "$svc" sh -lc \
                 'env | grep -oE "^[A-Za-z_][A-Za-z0-9_]*="' 2>/dev/null \
               | tr -d '=' | sort -u)
        [[ -n "$want" && -n "$have" ]] || continue
        missing=$(comm -23 <(echo "$want") <(echo "$have") | tr '\n' ' ')
        [[ -n "${missing// /}" ]] && echo "    $svc declared-but-absent: $missing"
    done
fi

# Exit non-zero on code skew, env drift, or a fingerprint we could not read,
# so this can gate something later. A check that cannot fail is decoration,
# and "could not read it" is not "it matches".
#
# A dirty tree is exempted from the skew exit for the reason given above — not
# to make the check quieter, but because that red could not be cleared while
# anyone was editing, and a signal that cannot go green is not a signal. Env
# drift and an unreadable fingerprint still fail, and so does skew on a clean
# tree, which is the condition this was built to catch.
if [[ -z "$api" || -z "$worker" ]]; then
    exit 1
elif [[ "$api" != "$worker" && "$tree" == "tree clean" ]]; then
    exit 1
fi

# The frontend is exempted while the tree is dirty, for the same reason the
# worker is: an edit moves the source hash and no rebuild has happened yet, so
# the red could not be cleared while anyone was working. On a clean tree a
# stale frontend is the three-hour 404 and fails.
if (( fe_bad )) && [[ "$tree" == "tree clean" ]]; then
    exit 1
fi
(( env_bad == 0 )) || exit 1
