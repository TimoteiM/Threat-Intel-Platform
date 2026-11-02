"""Add a sender CIDR to INGEST_TRUSTED_CIDRS in .env, idempotently.

A script rather than a hand edit because `.env` holds live credentials and the
edit must touch exactly one line. It rewrites only the matched assignment,
preserves the rest of the file byte-for-byte, and prints nothing but key names
and the CIDR list — no other value is read or echoed.

Idempotent: an entry already present is reported and the file is left alone.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ENV = pathlib.Path(__file__).resolve().parent.parent / ".env"
KEY = "INGEST_TRUSTED_CIDRS"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cidr")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    lines = ENV.read_text().splitlines(keepends=True)
    index = None
    for i, line in enumerate(lines):
        if line.partition("=")[0].strip() == KEY:
            index = i
            break
    if index is None:
        print(f"{KEY} is not present in .env — refusing to invent it.")
        return 1

    current = lines[index].partition("=")[2].strip()
    entries = [e.strip() for e in current.split(",") if e.strip()]
    print(f"{KEY} currently: {entries}")
    if args.cidr in entries:
        print(f"{args.cidr} is already present — nothing to do.")
        return 0

    updated = entries + [args.cidr]
    print(f"{KEY} would become: {updated}")
    if not args.apply:
        print("\n(dry run — pass --apply to write)")
        return 0

    lines[index] = f"{KEY}={','.join(updated)}\n"
    ENV.write_text("".join(lines))

    check = [
        e.strip()
        for e in ENV.read_text().splitlines()
        if e.partition("=")[0].strip() == KEY
    ][0].partition("=")[2].strip()
    print(f"written. {KEY} is now: {[e for e in check.split(',') if e]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
