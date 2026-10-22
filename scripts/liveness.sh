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
#
# The api fingerprint is read over HTTP, from the serving process, and NOT
# with `docker compose exec api python` — which is what this did until
# 2026-10-14 and is the very thing the worker comment below forbids. `exec
# python` spawns a fresh interpreter that imports whatever is on disk, so with
# the bind mount at ./backend:/app it always reported the files, never the
# process. The api runs WITHOUT `--reload` (decided 2026-10-13), so those two
# diverge the moment anybody edits backend code.
#
# Measured when this was fixed: the serving process was c94ab098 over 260
# files while `exec python` reported b018dd56 over 263 — and the script had
# been printing the second and calling it "in sync". The api had been serving
# code 3h11m older than the commit it was supposedly running, which is the
# same failure this script exists to catch, with the hole on the api side.
#
# The fingerprint lives behind the diagnostics header on /api/health. The
# token is read from .env into a variable and passed as a header; it is never
# echoed, and a missing one is reported rather than treated as agreement.
_diag_token=$(grep -E '^GRAPH_DEBUG_TOKEN=' "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env" 2>/dev/null \
              | cut -d= -f2- | tr -d '"' | tr -d "'" | tr -d '\r' | head -1)
api=""
api_why=""
if [[ -z "$_diag_token" ]]; then
    api_why="no GRAPH_DEBUG_TOKEN — cannot read the serving process"
else
    api=$(curl -s --max-time 10 -H "x-graph-debug: ${_diag_token}" \
              http://localhost:3000/api/health 2>/dev/null \
          | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
code = (d.get("diagnostics") or {}).get("code") or {}
print(code.get("code_fingerprint") or "")
' 2>/dev/null | grep -oE "^[0-9a-f]{64}$" || true)
    [[ -z "$api" ]] && api_why="api did not return a fingerprint"
fi
unset _diag_token

# ── the serving api against the FILES, which is a third comparison ────────
# The limbs above compare process to process. Neither answers the question
# that made a verification invalid on 2026-10-14: **is the serving api
# running the code that is on disk?**
#
# The api runs without `--reload`, so a backend edit moves the files and not
# the process. `docker compose exec api python` spawns a fresh interpreter and
# therefore reports the FILES — which is why reading the api's fingerprint
# that way was a bug, and is exactly why it is the right way to measure disk
# here. The serving value comes over the socket; the disk value comes from a
# fresh interpreter; the comparison is the point.
#
# This is reported as a control rather than written down as a rule, because a
# rule you have to remember to consult is not a control — the same argument
# that put the env-drift and frontend limbs here.
disk=$(docker compose exec -T -e PYTHONPATH=/app api python -c '
from app.code_version import code_version
print(code_version().get("code_fingerprint") or "")
' 2>/dev/null | tr -d "\r" | grep -oE "^[0-9a-f]{64}$" || true)

serve_note=""
serve_bad=0
if [[ -z "$api" || -z "$disk" ]]; then
    serve_note="serving-vs-disk unknown"
elif [[ "$api" != "$disk" ]]; then
    # On a dirty tree this is expected: an edit moves the files and the api
    # does not reload. Reported either way, because the INFORMATION is what
    # was missing — a claim about running behaviour made while this differs
    # is a claim about the files. Only failed on a clean tree, for the same
    # reason the frontend limb is exempted while dirty: this premise was
    # verified, by adding and removing a module and watching the serving
    # value hold.
    serve_note="api SERVING code older than the files — restart before trusting any live check"
    serve_bad=1
fi

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

# ── env lint: the faults the drift limb above cannot see ──────────────────
# The limb above starts from `docker compose config`, which hands back an
# already-normalised view: trimmed names, stripped quotes, no duplicates. So
# it is structurally unable to see a duplicate key (the last silently wins),
# an inline `#` that became part of a value, CRLF, or a tab.
#
# And it cannot see the backward direction at all. A `Settings` field with no
# env var behind it ANYWHERE is not "declared but absent" — it was never
# declared, so there is nothing for a drift comparison to find. That is
# exactly how `alert_callback_secret` sat empty while every outbound callback
# went unsigned, for an unknown length of time, with no error, no log line
# and no failed startup. Nothing in this script would have caught it.
#
# Deliberately NOT re-checking drift here: measured 2026-10-22, the limb above
# already names the missing variables individually and already exits 1. The
# Microsoft keys were never invisible to it. They were unread.
#
# Names only. The script it calls never prints a value.
lint_bad=0
lint_summary=""
_lint_out=$(backend/.venv/bin/python scripts/validate_env.py --strict 2>/dev/null)
_lint_rc=$?
if [[ -z "$_lint_out" ]]; then
    lint_bad=1
    lint_summary="could not run validate_env.py — absence is not agreement"
elif (( _lint_rc != 0 )); then
    lint_bad=1
    lint_summary=$(printf '%s' "$_lint_out" | sed -n 's/^SUMMARY: //p' | head -1)
    [[ -n "$lint_summary" ]] || lint_summary="exit ${_lint_rc}, no summary line"
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
    [[ -n "$api_why" ]] && line="$line ($api_why)"
elif [[ "$api" == "$worker" ]]; then
    line="$line · in sync"
else
    # No dirty-tree exemption, and the reason it was removed matters.
    #
    # This morning it read "skew expected (tree dirty, api reloads)", on the
    # premise that any edit moves the api's hash and not the worker's. That
    # premise was false, and it was false because of the bug fixed above: the
    # api fingerprint was being read with `exec python`, which DOES track the
    # files, so editing did move it. Both fingerprints now come from the
    # running processes, and neither moves when a file changes — measured by
    # adding and removing a module and watching the api's value stay at
    # c94ab098/260 across both.
    #
    # So a mismatch is never explained by a dirty tree. It means the two
    # processes started on different code, which is actionable whatever the
    # working tree looks like, and is the shape that left a pre-fix
    # decision_engine serving verdicts for 92 minutes.
    line="$line · SKEWED — processes on different code — docker compose restart api worker beat"
fi

if [[ -n "$serve_note" ]]; then
    line="$line · ${serve_note}"
fi

if (( fe_bad )); then
    line="$line · fe $(short "${fe_served:-none}") · ${fe_note}"
else
    line="$line · fe $(short "$fe_served") in sync"
fi

if (( env_bad )); then
    # Counts on the line, names underneath — the line stays scannable and
    # the actionable detail is still right there, not in another command.
    #
    # **"review the names first" is not politeness.** A recreate loads EVERY
    # declared-but-absent variable, not the one you were thinking of. On
    # 2026-10-22 the absent set included a Defender for Endpoint credential
    # holding `Machine.Isolate`, pending revocation, and this very line was
    # telling the reader to run the command that would load it into three
    # services. Remediation advice that is unsafe in a state the script
    # itself reports is worse than no advice.
    line="$line · ENV DRIFT:${env_note} — review the names below, then"
    line="$line docker compose up -d --force-recreate (loads ALL of them)"
else
    line="$line · env ok"
fi

if (( lint_bad )); then
    line="$line · ENV LINT: ${lint_summary}"
else
    line="$line · env lint ok"
fi

# A commit that has not reached the running process is the case this exists
# for, so say it even when the fingerprints agree with each other.
if [[ "$push" != "pushed" || "$tree" != "tree clean" ]]; then
    line="$line · uncommitted or unpushed work is not running anywhere"
fi

# ── Database privileges ──
#
# The application connects as `tip_app`, which must not be able to reach
# `investigation_token_maps` or do DDL, and the sanitizer must not be able to
# reach anything else. This is here, rather than in the test suite, because
# the suite cannot see it: measured on 2026-10-19, the full unit suite run
# against a database it could not connect to at all produced ONE extra failure
# out of 3,281 tests, and the integration suite skips when the server is
# unreachable. A grant regression is therefore invisible to `pytest` and
# visible here.
# Every database connection the code can read: present, reachable, and
# resolving to the role it is supposed to. Prints nothing when clean.
#
# `app.db.connection_check` derives the set from `Settings` rather than
# listing it, so a connection added without an entry saying who it opens as
# fails here instead of going unchecked.
_role_py='
from app.db.connection_check import check
for problem in check():
    print(problem)
'

priv_bad=0
priv_out="$(./scripts/check_db_privileges.sh 2>&1)"
case $? in
    0) line="$line · db privs ok" ;;
    1) priv_bad=1
       line="$line · DB PRIVILEGE DRIFT — scripts/provision_db_roles.sh" ;;
    # Exit 2 is "the check could not run", which is NOT "the privileges
    # match" — the distinction this script already makes for an unreadable
    # fingerprint.
    *) priv_bad=1
       line="$line · DB PRIVILEGES NOT CHECKED" ;;
esac

# ── Database connections: present, and opening as the right role ──
#
# The grants and the row-level policy are both properties of the ROLE a
# process connects as, so a correct database plus a misdirected URL is an
# unprotected deployment. Three faults of that shape in two days, and every
# one of them was a variable that was NOT SET falling back to a default:
# the host pointing at the owning superuser while the containers did not, a
# migration URL that existed nowhere, and a sanitizer URL missed when the
# other three were fixed.
#
# So presence is asserted separately from role — a variable that is absent
# and a variable that is wrong need different fixes, and only one of them is
# visible from the database.
#
# Checked in BOTH places, because "it works in the container" is exactly the
# wrong conclusion this class of divergence invites.
role_bad=0
role_note=""
# Initialised because `set -u` is on and the append below is in the failure
# branch — which had never run until the first control pointed a connection
# at the wrong role, and then died here instead of reporting it. The limb
# still exited non-zero, for the wrong reason and with nothing useful said.
role_detail=""
for where in host api; do
    if [[ "$where" == host ]]; then
        out=$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && \
              .venv/bin/python -c "$_role_py" 2>&1)
        status=$?
    else
        out=$(docker compose exec -T -e PYTHONPATH=/app api \
              python -c "$_role_py" 2>&1 | tr -d '\r')
        status=$?
    fi
    # Drop the config banner the app prints on import; a problem line never
    # starts with it.
    out=$(printf '%s\n' "$out" | grep -v '^\[config\]' | grep -v '^[[:space:]]*$' || true)
    if (( status != 0 )); then
        role_bad=1
        role_note="$role_note ${where}:could-not-check"
    elif [[ -n "$out" ]]; then
        role_bad=1
        # `printf '%s'` emits no trailing newline, so `wc -l` counted one
        # problem as zero. "0-problem(s)" beside a failure is the kind of
        # line that gets read as noise.
        role_note="$role_note ${where}:$(printf '%s\n' "$out" | wc -l | tr -d ' ')-problem(s)"
        role_detail="$role_detail
    ${where}: $(printf '%s' "$out" | tr '\n' '; ')"
    fi
done
if (( role_bad )); then
    line="$line · DB CONNECTIONS WRONG:${role_note}"
else
    line="$line · db connections ok"
fi

echo "$line"

if (( priv_bad )); then
    printf '%s\n' "$priv_out" | sed 's/^/    /'
fi
if (( role_bad )) && [[ -n "${role_detail:-}" ]]; then
    printf '%s\n' "$role_detail"
fi

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

# ── exit codes: THREE, not two ────────────────────────────────────────────
#
# **Why this changed on 2026-10-22.** This script exited 1 on every run for
# days. Every red was true — but a check that is always red is a check nobody
# reads, and that is not a theory here: the env-drift limb named
# `MicrosoftClientId MicrosoftClientSecret MicrosoftTenantId` individually, on
# every run, and exited 1, for two days, and the keys were found by auditing
# something else entirely. The limb worked. Its output was weather.
#
# The fix is NOT an exemption. A "known-ahead branch is green" carve-out was
# considered and rejected: it would have greened the ENV DRIFT line, which is
# the exact signal that proved the problem, and "the branch is ahead" is not a
# premise checkable independently of the check it exempts — see *Verify an
# exemption's premise* in the README, which already names this script.
#
# The fix is to stop conflating two different things that both used to exit 1:
#
#   exit 0  everything agrees. The normal state.
#   exit 2  the DEPLOYMENT is sound; you merely have local work in progress
#           (dirty tree, or commits not pushed). Nothing is misconfigured and
#           nothing is stale relative to what is deployed. Informational.
#   exit 1  a real fault: process skew, stale serving code on a clean tree, a
#           stale frontend, env drift, env lint, a wrong grant or role, or a
#           fingerprint that could not be read at all.
#
# So `exit 1` now means "something is wrong", and `exit 2` means "you are
# mid-flight". A caller that wants the old behaviour tests `-ne 0`.
#
# "Could not read it" is still a fault, not agreement.

fault=0

# Process-to-process skew fails regardless of the working tree, because an
# edit moves neither process's fingerprint. The earlier dirty-tree exemption
# existed only to mask the `exec python` misreading that is now fixed.
if [[ -z "$api" || -z "$worker" ]]; then
    fault=1
elif [[ "$api" != "$worker" ]]; then
    fault=1
fi

# The frontend exemption stays, and unlike the code one it is correctly
# premised: the expected value here IS recomputed from the working tree, so an
# edit genuinely does move it before any rebuild could. That red could not be
# cleared while anyone was working. On a clean tree a stale frontend is the
# three-hour 404 and fails.
if (( fe_bad )) && [[ "$tree" == "tree clean" ]]; then
    fault=1
fi

if (( serve_bad )) && [[ "$tree" == "tree clean" ]]; then
    fault=1
fi

# No dirty-tree exemption: a grant is a property of the database, not of the
# working tree, so an edit cannot move it and there is nothing to excuse.
(( priv_bad == 0 )) || fault=1
# Same reasoning as the privileges limb: the role a process connects as is not
# a property of the working tree, so there is no dirty-tree exemption.
(( role_bad == 0 )) || fault=1
(( env_bad == 0 )) || fault=1
# No dirty-tree exemption: .env is not under version control, so an edit to
# the working tree cannot move this and there is nothing to excuse.
(( lint_bad == 0 )) || fault=1

# A fault outranks work-in-progress: if something is actually wrong, say so
# even when the tree is also dirty.
if (( fault )); then
    exit 1
fi
if [[ "$push" != "pushed" || "$tree" != "tree clean" ]]; then
    exit 2
fi
exit 0
