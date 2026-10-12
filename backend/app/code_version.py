"""Which code this process is actually running.

On 2026-10-12 seven backend commits sat on disk, committed and pushed, while
the live API served code it had imported hours earlier. `backend/` is
bind-mounted, so every filesystem check — `ls`, `grep`, `git log`, and a fresh
`docker compose exec api python` — reported them as deployed. Nothing could
report that the *process* had not loaded them.

So this is computed **at import time**, which is the only moment that
corresponds to "what this process loaded".

Three things it deliberately does not do.

**It does not shell `git rev-parse` at request time.** That would read the
bind mount and report the working tree, which is what every other check
already reported. It would have said "deployed" all afternoon and reproduced
the bug inside the fix for the bug. (It could not have worked here anyway:
there is no `/app/.git` — the mount is `backend/`, and `.git` is above it —
and no git binary in the image. That is the case the fingerprint exists for.)

**It does not use the container's start time.** With `--reload` enabled,
WatchFiles replaces the server child without restarting the container, so
container start and import time diverge by design, permanently. The container
start time is now a number that looks like an answer and is not one.

**It does not report an empty string when git is unavailable.** An empty
value renders as "unknown" and gets read as "fine". The absence is named.

The fingerprint, not the SHA, is the load-bearing value: it is computed from
the bytes of the source tree this process imported, so it covers uncommitted
edits — which, on a bind mount during development, is most of them.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Where the application's source lives, as this process sees it.
_ROOT = Path(__file__).resolve().parent

#: Named rather than blank. A reader seeing this knows the value is missing
#: and why; a reader seeing "" or "unknown" assumes it was checked.
GIT_UNAVAILABLE = (
    "unavailable: no .git inside the container (the mount is backend/, .git is "
    "above it) and GIT_SHA is unset — use code_fingerprint to compare processes"
)


def _fingerprint(root: Path) -> tuple[str, int]:
    """A hash over the bytes of every .py file beneath `root`.

    Content, not mtime: `touch` changes an mtime without changing the code,
    and a fingerprint that moves when nothing moved is a false alarm that
    trains people to ignore it. Paths are sorted so the result does not depend
    on directory iteration order.
    """
    digest = hashlib.sha256()
    counted = 0
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            # A file that cannot be read still changes the answer, and saying
            # so is better than silently hashing the rest as if it were whole.
            digest.update(b"UNREADABLE:" + str(path.relative_to(root)).encode())
            counted += 1
            continue
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(data)
        counted += 1
    return digest.hexdigest(), counted


def _git_sha() -> str:
    """The commit, if anything in this container can say what it is."""
    stamped = str(os.environ.get("GIT_SHA") or "").strip()
    if stamped:
        return stamped
    head = _ROOT.parent / ".git" / "HEAD"
    try:
        ref = head.read_text().strip()
    except OSError:
        return GIT_UNAVAILABLE
    if ref.startswith("ref: "):
        try:
            return (_ROOT.parent / ".git" / ref[5:]).read_text().strip()
        except OSError:
            return GIT_UNAVAILABLE
    return ref or GIT_UNAVAILABLE


#: Captured once, when this module is first imported by a process. With
#: `--reload` the child is replaced and this recomputes; without it, this is
#: the moment the running code was fixed.
IMPORTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")
CODE_FINGERPRINT, CODE_FILES = _fingerprint(_ROOT)
GIT_SHA = _git_sha()


def code_version() -> dict[str, Any]:
    """What this process is running, for /health and for the worker's task.

    Two processes are on the same code when their `code_fingerprint` matches.
    Comparing anything else — image tags, container start, the working tree —
    compares something other than what is loaded.
    """
    return {
        "code_fingerprint": CODE_FINGERPRINT,
        "code_files": CODE_FILES,
        "imported_at": IMPORTED_AT,
        "git_sha": GIT_SHA,
        "note": (
            "imported_at is when this process loaded its code, which is not "
            "the container's start time once --reload is on"
        ),
    }
