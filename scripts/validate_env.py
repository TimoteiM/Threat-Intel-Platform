"""Validate every key in .env, in BOTH directions.

Prints KEY NAMES AND VERDICTS ONLY. No value, no fragment of a value, and no
value length is ever printed.

Two directions, because the Microsoft key was only one face of the bug:

  forward  — a key written in .env that does NOT reach the service.
             Silent: the parser drops it and the app falls back to a default.
  backward — a Settings field with no env var behind it in the running
             container, so the code's default is in force whether or not
             anyone intended it.

The forward direction is measured against the RUNNING CONTAINER rather than
reasoned about from the parser's documented behaviour. A declaration agreeing
with itself is not a measurement.
"""
from __future__ import annotations

import collections
import pathlib
import re
import subprocess
import sys

ENV = pathlib.Path("/home/expert/apps/Threat-Intel-Platform/.env")
VALID_NAME = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
SERVICES = ("api", "worker", "beat")


def parse_env_raw() -> list[tuple[int, str, str, str]]:
    """(lineno, raw_key, raw_value, raw_line) for every assignment line."""
    rows = []
    raw = ENV.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        rows.append((i, k, v, line))
    return rows


def container_env_keys(service: str) -> set[str] | None:
    try:
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", service,
             "sh", "-lc", "env | cut -d= -f1"],
            cwd=str(ENV.parent), capture_output=True, text=True, timeout=90)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return {ln.strip() for ln in out.stdout.splitlines() if ln.strip()}


def settings_fields() -> set[str]:
    try:
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "-e", "PYTHONPATH=/app", "worker",
             "python", "-c",
             "from app.config import Settings;"
             "print('\\n'.join(sorted(Settings.model_fields)))"],
            cwd=str(ENV.parent), capture_output=True, text=True, timeout=120)
    except Exception:
        return set()
    if out.returncode != 0:
        return set()
    # The config module prints a banner to stdout on import. Without this
    # filter it arrives as a "Settings field" — an instrument reporting its
    # own noise as data.
    return {ln.strip() for ln in out.stdout.splitlines()
            if ln.strip() and not ln.startswith("[config]")
            and VALID_NAME.match(ln.strip())}


def main() -> int:
    raw = ENV.read_bytes()
    rows = parse_env_raw()
    print(f"assignment lines in .env: {len(rows)}")
    print(f"file encoding sanity     : CRLF present={b'\\r\\n' in raw}, "
          f"BOM={raw[:3] == b'\\xef\\xbb\\xbf'}, "
          f"trailing newline={raw.endswith(b'\\n')}")
    print()

    # ---- structural lint -------------------------------------------------
    problems: dict[str, list[str]] = collections.defaultdict(list)
    seen: dict[str, list[int]] = collections.defaultdict(list)
    for lineno, k, v, line in rows:
        key = k.strip()
        seen[key].append(lineno)
        if k != k.strip():
            problems["key has surrounding whitespace -> INVALID env name, "
                     "silently dropped by the container runtime"].append(
                f"L{lineno} {key}")
        if not VALID_NAME.match(key):
            problems["key is not a valid env var name "
                     "([A-Za-z_][A-Za-z0-9_]*)"].append(f"L{lineno} {key}")
        if v != v.strip():
            problems["value has leading/trailing whitespace "
                     "(reaches the app verbatim; a space in a secret or URL "
                     "is a 401 that reads as a wrong credential)"].append(
                f"L{lineno} {key}")
        if v.strip()[:1] in ("'", '"') and v.strip()[-1:] == v.strip()[:1] and len(v.strip()) > 1:
            problems["value is quoted (compose env_file keeps the quotes as "
                     "part of the value; python-dotenv strips them — the two "
                     "layers disagree)"].append(f"L{lineno} {key}")
        if "$" in v:
            problems["value contains '$' (interpolation risk; compose may "
                     "substitute or warn)"].append(f"L{lineno} {key}")
        if re.search(r"\s#", v):
            problems["value contains ' #' (env_file does NOT strip inline "
                     "comments — the comment becomes part of the value)"].append(
                f"L{lineno} {key}")
        if "\t" in line:
            problems["line contains a TAB"].append(f"L{lineno} {key}")
    for key, lines in sorted(seen.items()):
        if len(lines) > 1:
            problems["DUPLICATE key — the last occurrence silently wins"].append(
                f"{key} at lines {lines}")

    if problems:
        print("STRUCTURAL PROBLEMS")
        print("=" * 72)
        for kind, items in problems.items():
            print(f"\n[{len(items)}] {kind}")
            for it in items:
                print(f"      {it}")
    else:
        print("STRUCTURAL PROBLEMS: none")
    print()

    # ---- forward direction: does each key REACH the services? -----------
    declared = {k.strip() for _, k, _, _ in rows if VALID_NAME.match(k.strip())}
    declared_malformed = {k.strip() for _, k, _, _ in rows
                          if not VALID_NAME.match(k.strip())}
    print("FORWARD — .env keys that do NOT reach the running container")
    print("=" * 72)
    any_container = False
    for svc in SERVICES:
        keys = container_env_keys(svc)
        if keys is None:
            print(f"  {svc:8s} UNREACHABLE (container not running?)")
            continue
        any_container = True
        missing = sorted(declared - keys)
        print(f"  {svc:8s} {len(keys)} env vars; "
              f"{len(declared)} well-formed keys in .env; "
              f"MISSING {len(missing)}")
        for m in missing:
            print(f"             - {m}")
        if declared_malformed:
            still = sorted(k for k in declared_malformed if k not in keys)
            for m in still:
                print(f"             - {m}  (malformed name, expected to be dropped)")
    print()

    # ---- backward direction: Settings fields running on defaults ---------
    if any_container:
        fields = settings_fields()
        keys = container_env_keys("worker") or set()
        upper = {k.upper() for k in keys}
        print("BACKWARD — Settings fields with NO env var behind them")
        print("=" * 72)
        if not fields:
            print("  (could not enumerate Settings fields)")
        else:
            unbacked = sorted(f for f in fields if f.upper() not in upper)
            print(f"  {len(fields)} Settings fields; "
                  f"{len(fields) - len(unbacked)} backed by an env var; "
                  f"{len(unbacked)} running on the code default.")
            print("  Most of those are deliberate tunables and are NOT listed.")
            # The actionable subset: a credential-shaped field with no env var
            # behind it means that integration cannot authenticate, and the
            # default is almost certainly an empty string.
            cred = re.compile(r"(key|secret|token|password|passwd|credential"
                              r"|client_id|tenant_id|dsn|_url|username|user)$"
                              r"|(^|_)(api_key|auth)(_|$)")
            flagged = [f for f in unbacked if cred.search(f)]
            print(f"\n  CREDENTIAL-SHAPED and unset ({len(flagged)}) — each means "
                  f"that integration cannot authenticate:")
            for f in flagged:
                print(f"      - {f}")

    # ---- declared-but-empty: intent recorded, value absent ---------------
    print()
    print("DECLARED BUT EMPTY in .env — someone meant to configure these")
    print("=" * 72)
    empties = [(lineno, k.strip()) for lineno, k, v, _ in rows if not v.strip()]
    if not empties:
        print("  none")
    for lineno, key in empties:
        print(f"      L{lineno} {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
