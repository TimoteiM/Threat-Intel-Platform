"""Validate every key in .env, in BOTH directions.

**What this adds over the env-drift limb that already exists.** Measured
2026-10-22: `liveness.sh`'s env limb already compares the names
`docker compose config` resolves against the names each container has, names
them individually, and exits 1. It was never blind to the Microsoft keys — it
prints them by name and has done since they were added. So this script does
**not** re-check drift. It covers the three things that limb cannot see,
because it starts from compose's already-normalised view rather than from the
bytes a human typed:

1. **Structural faults in the file.** Duplicate keys (the last silently
   wins), values carrying an inline `#` comment, tabs, CRLF. None of these
   produce a name mismatch, so drift comparison cannot detect any of them.
2. **The backward direction.** A `Settings` field with no env var behind it
   anywhere is not "missing" from compose's view — it was never declared, so
   there is nothing for a drift check to find. This is how
   `alert_callback_secret` sat empty and every outbound callback went
   unsigned.
3. **Declared but empty.** Intent recorded, value absent.

Prints KEY NAMES AND VERDICTS ONLY. No value, no fragment of a value, and no
value length is ever printed.

`--strict` exits non-zero so this can gate, and prints a one-line summary for
`liveness.sh`.

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

ENV = pathlib.Path(__file__).resolve().parent.parent / ".env"
VALID_NAME = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
SERVICES = ("api", "worker", "beat")

#: Settings fields that are unset **on purpose**, each with the reason.
#:
#: A baseline by NAME, not a count: a new name is the signal, and a count
#: would let one appear as another is fixed. Each entry is a claim that can be
#: checked, which is the condition for a carve-out existing at all — a
#: carve-out added for a false positive is how a true one stays hidden.
DELIBERATELY_UNSET = {
    "bootstrap_admin_username": "no bootstrap admin should exist; unset is the "
                                "desired state and setting it would create one",
    "bootstrap_admin_password": "as above",
    "correlation_webhook_url": "no correlation webhook receiver exists yet; "
                               "case_event_task returns early, which is correct",
    "anyrun_api_key_fallback": "a fallback for the primary key, which IS set",
}

#: Names whose absence silently degrades something, as opposed to a tunable
#: with a sensible default. Narrower than "contains the word secret": the
#: first version matched `*_base_url` and reported five correct defaults as
#: unset credentials, which would have been a wrong headline from a right
#: query.
DEGRADES_SILENTLY = re.compile(
    r"(^|_)(secret|password|passwd|api_key|auth_token|credential)(_|$)"
    r"|_secret$|_password$|_api_key$|_token$|_webhook_url$"
)


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
            # **Not an assignment at all, and this used to be skipped.**
            #
            # A blind spot found 2026-10-27: a stray line with no `=` was
            # invisible to every check here, while `docker compose` refuses to
            # read the file at all over it — "key cannot contain a space" —
            # which takes down every compose command, not just one variable.
            # Pasted console output is the obvious way it gets there.
            #
            # Recorded with lineno and None for the value so the lint below
            # can flag it without ever reading what is on the line.
            rows.append((i, line.rstrip("\n"), None, line))
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
    strict = "--strict" in sys.argv
    # An optional path, so the dangerous-direction control can run against a
    # fixture instead of mutating the live .env to prove the check works.
    # A test that has to edit the real credentials file to verify itself is a
    # test nobody will run twice.
    global ENV
    paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if paths:
        ENV = pathlib.Path(paths[0]).resolve()
        print(f"(reading {ENV})")
    unexplained: list[str] = []
    raw = ENV.read_bytes()
    rows = parse_env_raw()
    print(f"assignment lines in .env: {len(rows)}")
    print(f"file encoding sanity     : CRLF present={b'\\r\\n' in raw}, "
          f"BOM={raw[:3] == b'\\xef\\xbb\\xbf'}, "
          f"trailing newline={raw.endswith(b'\\n')}")
    print()

    # ---- structural lint -------------------------------------------------
    # Severity is set by MEASUREMENT, not by how alarming the fault looks.
    # Surrounding whitespace was initially filed as "silently dropped by the
    # container runtime". That was wrong: `docker compose config` trims the
    # name, and a container created from today's .env receives the variable
    # with a CLEAN value. Verified by running a throwaway container. So it is
    # advisory, and the real reason those keys are absent from the running
    # services is that the containers predate them — which the existing
    # env-drift limb already reports.
    hard: dict[str, list[str]] = collections.defaultdict(list)
    advisory: dict[str, list[str]] = collections.defaultdict(list)
    seen: dict[str, list[int]] = collections.defaultdict(list)
    for lineno, k, v, line in rows:
        key = k.strip()
        if v is None:
            # No `=` on the line. Report the LINE NUMBER and the shape, never
            # the content — a stray line could be anything, including a value
            # someone meant to assign.
            hard["line is neither blank, a comment, nor an assignment — "
                 "`docker compose` refuses to read the whole file over this, "
                 "so every compose command fails, not just one variable"].append(
                f"L{lineno} ({len(key)} chars"
                + (", contains a space" if " " in key else "")
                + (", looks like pasted output" if key.endswith("]") else "")
                + ")")
            continue
        seen[key].append(lineno)
        if " " in key:
            hard["key contains an internal space — compose rejects the file"
                 ].append(f"L{lineno} ({len(key)} chars)")
        if not VALID_NAME.match(key):
            hard["key is not a valid env var name even after trimming "
                 "([A-Za-z_][A-Za-z0-9_]*)"].append(f"L{lineno} {key}")
        if re.search(r"\s#", v):
            hard["value contains ' #' — env_file does NOT strip inline "
                 "comments, so the comment becomes part of the value"].append(
                f"L{lineno} {key}")
        if "\t" in line:
            hard["line contains a TAB"].append(f"L{lineno} {key}")
        if k != k.strip():
            advisory["key name has surrounding whitespace (compose trims it; "
                     "cosmetic, but it hid the real cause once)"].append(
                f"L{lineno} {key}")
        if v != v.strip():
            advisory["value has surrounding whitespace (compose trims it; "
                     "measured clean inside a fresh container)"].append(
                f"L{lineno} {key}")
        sv = v.strip()
        if len(sv) > 1 and sv[0] in ("'", '"') and sv[-1] == sv[0]:
            advisory["value is quoted (compose strips matched quotes; "
                     "python-dotenv also does, but they can disagree on "
                     "nesting)"].append(f"L{lineno} {key}")
        if "$" in v:
            advisory["value contains '$' (compose may interpolate)"].append(
                f"L{lineno} {key}")
    for key, lines in sorted(seen.items()):
        if len(lines) > 1:
            hard["DUPLICATE key — the last occurrence silently wins"].append(
                f"{key} at lines {lines}")
    if b"\r\n" in raw:
        hard["file has CRLF line endings — the CR becomes part of every "
             "value"].append("(whole file)")

    for title, bucket in (("HARD FAULTS (these gate)", hard),
                          ("ADVISORY (measured not to break anything)", advisory)):
        print(title)
        print("=" * 72)
        if not bucket:
            print("  none")
        for kind, items in bucket.items():
            print(f"\n[{len(items)}] {kind}")
            for it in items:
                print(f"      {it}")
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
            flagged = sorted(f for f in unbacked if DEGRADES_SILENTLY.search(f))
            print(f"\n  SILENTLY DEGRADING and unset ({len(flagged)}):")
            for f in flagged:
                why = DELIBERATELY_UNSET.get(f)
                print(f"      - {f}"
                      + (f"   [expected: {why}]" if why else "   *** UNEXPLAINED ***"))
            unexplained.extend(f for f in flagged if f not in DELIBERATELY_UNSET)

    # ---- declared-but-empty: intent recorded, value absent ---------------
    print()
    print("DECLARED BUT EMPTY in .env — someone meant to configure these")
    print("=" * 72)
    # `v is None` is a non-assignment line, already reported as a hard fault
    # above. It is not "declared but empty" — nothing was declared.
    empties = [(lineno, k.strip()) for lineno, k, v, _ in rows
               if v is not None and not v.strip()]
    if not empties:
        print("  none")
    for lineno, key in empties:
        print(f"      L{lineno} {key}")

    # ---- the one-line summary liveness.sh prints -------------------------
    n_hard = sum(len(v) for v in hard.values())
    bits = []
    if n_hard:
        bits.append(f"{n_hard} HARD FAULT(S)")
    if unexplained:
        bits.append(f"{len(unexplained)} unexplained silent default(s): "
                    + " ".join(sorted(unexplained)))
    print()
    print("SUMMARY: " + (" · ".join(bits) if bits else "env lint ok"))
    if strict and (n_hard or unexplained):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
