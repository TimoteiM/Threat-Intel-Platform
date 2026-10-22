"""When a sender tells us the body is not the real thing, keep the label.

One sender does this and does it well. Measured 2026-10-22, **69 alert
bodies** begin with:

    [SYNTHETIC - Exabeam raw log unavailable; derived from event metadata,
     not a verbatim log line] host=… user=… src_ip=…

64 on the unassigned tenant and 5 on `lin`. `external_ref` on those runs is a
SOC ticket — a workflow that tried to fetch the raw log, could not, and
declared the substitute **in band**. That is absence recorded as absence,
which is the opposite of the fault this codebase keeps finding.

**The fault was ours: nothing read it.** The derived `key=value` metadata was
parsed as though it were a log line — it is where `event_id=69903197010@s3`
came from, and why `lin` appeared to carry cloud-shaped event classes — the
body reached the model as evidence with no indication it was derived, and the
report gave a reader no way to tell. The sender's honesty was discarded at
our boundary.

**Why this is a narrow detector and not a heuristic.** A pattern that labels
bodies "derived" on a keyword alone would relabel the corpus: `confidence`
appears in 24.5% of bodies and `sample` in 15.2%, almost all of it prose or
HTTP trace headers (`x-b3-sampled`, `sentry-sample_rate`). And **6 bodies
begin `[ALERT]`**, which is a sender's subject prefix and not a declaration
about content. So the rule is: a **bracketed prefix at the very start**,
whose contents name a substitution. `[ALERT]` has no such word and is not
flagged — asserted directly, because a marker test that matches everything
is worse than no marker test.

What the sweep did **not** find, stated so nobody re-derives it: no
truncation marker and no partial-fetch indicator appears as a field anywhere
in 17,748 bodies — `truncat` and `partial` occur only as prose. The one other
dropped sender field is `confidence_level`, on 29 bodies (values 1 and 3, all
unassigned-tenant, no documented scale); it is recorded in the register
rather than read, because a number on an unknown scale is not usable.
"""

from __future__ import annotations

import re
from typing import Any

#: Words that mark a declaration ABOUT THE BODY rather than about the event.
#: Each one has to say "this is not the original", which is why `alert`,
#: `confidence` and `sample` are absent from the list.
SUBSTITUTION_WORDS = (
    "synthetic", "derived", "not a verbatim", "unavailable", "placeholder",
    "truncated", "redacted", "partial", "reconstructed", "best effort",
    "best-effort",
)

#: A bracketed prefix at the very start of the body. Anchored, because a
#: bracketed phrase mid-body is log content, not a declaration about it.
_PREFIX_RE = re.compile(r"\A\s*\[([^\]\n]{4,200})\]")

#: The field name recorded on the alert, and read by the report and the
#: model-facing path.
FIELD = "body_provenance"

#: What `FIELD` carries when the sender said nothing. A real value, not a
#: missing key: "the sender declared nothing" and "nobody looked" must not be
#: the same bytes.
VERBATIM = "verbatim_as_received"


def declared_substitution(body: str) -> dict[str, Any] | None:
    """The sender's own declaration that this body is a substitute, or None.

    Returns the declaration **text** as well as the flag, because "derived"
    without "derived from what, and why" is the same shape of loss one level
    down.
    """
    match = _PREFIX_RE.match(str(body or ""))
    if not match:
        return None
    declaration = match.group(1).strip()
    lowered = declaration.lower()
    hit = next((w for w in SUBSTITUTION_WORDS if w in lowered), None)
    if hit is None:
        # A bracketed prefix that is not a declaration — `[ALERT]` and the
        # like. Not flagged.
        return None
    return {
        "derived": True,
        "declared_by": "sender",
        "declaration": declaration[:200],
        "matched": hit,
    }


def provenance_of(body: str) -> dict[str, Any]:
    """Always a value. `VERBATIM` when the sender declared nothing."""
    declared = declared_substitution(body)
    if declared:
        return declared
    return {"derived": False, "declared_by": None, "declaration": VERBATIM}


def note_for_model(body: str) -> str:
    """One line to put in front of the evidence, or empty.

    The model is told plainly, because a derived summary read as a verbatim
    log is a confident conclusion about a log line that never existed.
    """
    declared = declared_substitution(body)
    if not declared:
        return ""
    return (
        "PROVENANCE: the sender declared this alert body is NOT a verbatim log "
        f"line — \"{declared['declaration']}\". Treat its fields as the "
        "sender's reconstruction from event metadata, not as observed log "
        "text, and say so in any conclusion that rests on them."
    )
