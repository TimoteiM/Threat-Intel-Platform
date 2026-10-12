"""What an ATT&CK id *is*, for everything that displays one.

A node labelled `T1098` tells an analyst nothing they did not already have to
look up. This resolves ids against the bundled catalogue — `attack_reference`,
generated from Enterprise ATT&CK 19.2 — and every surface that shows a
technique reads it here: the three graph layouts, the side panel, the
disagreements CLI, the outbound document, and the PNG and JSON exports. A name
in one place and a bare id in another is worse than ids throughout.

Three resolutions, kept distinct:

    parent          T1059 -> Command and Scripting Interpreter
    sub-technique   T1059.001 -> PowerShell on a node, and
                    "Command and Scripting Interpreter: PowerShell" in a panel
    retired         revoked or deprecated in 19.2 — said explicitly, with the
                    current equivalent, never by quietly showing the
                    superseding technique's name

An id that does not resolve is an **absence**, not a blank: the id renders
alone, typed `unrecognised_absence` with the raw value, exactly as everywhere
else. No guessed name, no falling back to the alert's own text, and the node is
not hidden. An id in this data that is not in ATT&CK is a finding, and 2 of 77
were — both `{0=T1489}`-shaped, now fixed at the extractor.

Wording, which matters at 273 nodes on a single case
----------------------------------------------------
`retired` is a fact about the id's status in ATT&CK, not a judgement on the
attribution. A rule that mapped to T1562.001 in 2024 mapped correctly for the
ATT&CK of its day; ATT&CK 19 reorganised Impair Defenses into the T1685 family
afterwards. The text therefore reads "retired in ATT&CK 19.2, current
equivalent T1685" — context that lets an analyst search the current matrix —
and never anything implying the detection got it wrong. An analyst who reads
"retired" 273 times and concludes their ruleset is broken has been misled by
us, not informed.

Why dated ids are expected rather than a defect
-----------------------------------------------
488 technique nodes in this estate carry an id 19.2 has retired, and 117 of
those were named by this platform's own attribution rather than by a rule. That
is not a bug to go hunting. The attribution service's ATT&CK knowledge has a
cutoff like any other knowledge, so whenever the bundled snapshot is newer than
what the model learned, some of its ids will be ones ATT&CK has since moved.
The expected outcome of pinning a current catalogue is that older attributions
look older — which is the catalogue doing its job. Do not read these 117 as the
model being wrong and go looking for a parsing fault; there isn't one.

The same holds in the other direction and is the stronger argument for pinning
a version at all: the Wazuh ruleset and the frontend's own former technique map
were both independently stuck on a pre-19 ATT&CK, and neither could have known.
A system with no versioned reference agrees with itself perfectly. The
catalogue being current is the only instrument that made either legible as
stale.
"""

from __future__ import annotations

from typing import Any

from app.analyst.attack_mapping import describe_technique
from app.analyst.attack_reference import ATTACK_VERSION, TACTIC_ORDER
from app.services.absence import UNRECOGNISED, absent


def is_absent_json(value: Any) -> bool:
    """An absence after `as_json()`. `absence.is_absent` checks the dataclass,
    and by the time it is on a graph node it is a plain dict."""
    return isinstance(value, dict) and value.get("absent") is True

#: Node kinds whose label is an ATT&CK id.
TECHNIQUE_KIND = "technique"


def name_technique(technique_id: Any) -> dict[str, Any]:
    """Everything a surface needs to render one id, or a named absence.

    Case is normalised here, so `t1098` and `T1098` are one technique. The
    stored data holds no lower-case ids today — measured, 0 of 77 — but an id
    arrives from a rule author's free text and the guarantee costs nothing.
    """
    raw = str(technique_id or "").strip()
    found = describe_technique(raw)
    if not found:
        # The absence rides on `name` itself, not on a side-channel key.
        # That is this platform's convention everywhere else — `abuse_score`
        # is a number or an Absent, `investigated` is a record or an Absent —
        # and a second shape for the same idea is the duplication defect in
        # miniature. `short_name` is omitted rather than also made absent:
        # one statement that the id cannot be named is enough.
        return {
            "id": raw.upper() or raw,
            "attack_version": ATTACK_VERSION,
            "name": absent(
                UNRECOGNISED,
                f"This id is not in the bundled ATT&CK catalogue "
                f"(Enterprise {ATTACK_VERSION}), so this platform cannot say "
                "what it is. The id is shown as it was recorded rather than "
                "guessed at or hidden: an id in our data that ATT&CK does not "
                "have is a finding about the data.",
                raw=raw,
            ).as_json(),
        }

    current = found.get("current_equivalent")
    out: dict[str, Any] = {
        "id": raw.upper(),
        # The full ATT&CK page title, for a panel with room for it.
        "name": found.get("name"),
        # The leaf alone, for a node label that has about 96px.
        "short_name": found.get("short_name") or found.get("name"),
        "tactic": found.get("tactic"),
        "tactics": list(found.get("tactics") or []),
        "url": found.get("url"),
        # Whether this platform could ever corroborate it — a separate claim
        # from whether a rule asserted it, and not merged with one.
        "evidenceable": bool(found.get("evidenceable")),
        "retired": bool(found.get("retired")),
        "revoked": bool(found.get("revoked")),
        "deprecated_without_replacement": bool(
            found.get("retired") and not found.get("revoked")
        ),
        # The single hop ATT&CK states, and the end of the chain. They differ
        # on three techniques in 19.2, and a reader told to search for an
        # intermediate has been given the answer as of an older release.
        "revoked_by": found.get("revoked_by"),
        "current_equivalent": current,
        "attack_version": ATTACK_VERSION,
    }
    if found.get("retired"):
        out["retirement"] = _retirement_sentence(found, current)
    return out


def _retirement_sentence(found: dict[str, Any], current: Any) -> str:
    """The panel's wording. Status, then what to search for instead."""
    if current:
        equivalent = describe_technique(str(current)) or {}
        name = equivalent.get("name") or ""
        tail = f"Current equivalent {current}" + (f" ({name})." if name else ".")
    elif found.get("revoked"):
        # Refused rather than guessed: the chain did not resolve. The generator
        # prints this loudly and a test fails on it, so it should not reach
        # here — but saying "no equivalent" beats naming an intermediate.
        tail = (
            "ATT&CK's replacement chain for this id does not resolve to a "
            "current technique, so there is nothing to point at."
        )
    else:
        tail = "ATT&CK retired it without a replacement."
    return (
        f"Retired in ATT&CK {ATTACK_VERSION}. {tail} A detection that mapped "
        "to this id mapped correctly for the ATT&CK of its day."
    )


def annotate(graph: dict[str, Any]) -> dict[str, Any]:
    """Resolve every technique node in a graph, in place, and say which ATT&CK.

    Called from `graph_for_runs` rather than from the endpoint, so the page,
    the acceptance CLI and the exports all read the same graph. Adding it at
    the endpoint alone is the entry-point divergence that let a severity bound
    be measured eleven times on a path no user was on.
    """
    retired = 0
    unresolved = 0
    for node in graph.get("nodes") or []:
        if node.get("kind") != TECHNIQUE_KIND:
            continue
        attrs = node.setdefault("attrs", {})
        resolved = name_technique(attrs.get("id") or node.get("label"))
        attrs.update(resolved)
        if is_absent_json(resolved.get("name")):
            unresolved += 1
        elif resolved.get("retired"):
            retired += 1

    attack = graph.setdefault("attack", {})
    # Surfaced wherever coverage is reported: names change and ids get revoked
    # between versions, so "which ATT&CK" is part of the answer.
    attack["version"] = ATTACK_VERSION
    #
    # `attack_version` is also on every technique node. That is redundant and
    # safe *only* because resolution happens at read time: one call, one
    # constant, so every node in a payload was named by one catalogue.
    #
    # The optimisation that breaks it is a reasonable one. Moving resolution
    # to materialise time — stamping names onto `alert_graph_entity` when the
    # sweep runs, to save this pass — would make the two versions different
    # facts rather than one fact twice: a node materialised under 19.2 inside
    # a payload assembled under 20.0. That is information, not a bug, but only
    # for a reader who has been told which one wins.
    #
    # If that move is ever made, decide and write down: the node's version is
    # when its name was resolved, the payload's is the catalogue currently
    # bundled, and a node whose version is older than the payload's should say
    # so rather than being silently re-read as current. Until then this
    # invariant holds and the redundancy is a convenience for a consumer
    # slicing out a single node.
    attack["retired_drawn"] = retired
    attack["unnameable_drawn"] = unresolved
    # The tactics this ATT&CK release actually has, in its own matrix order.
    #
    # Sent with the data rather than left for the renderer to know, because
    # that is the difference between a discovery problem and a reachability
    # one: the frontend kept 12 hand-written columns and 38 technique
    # mappings, three of them already stale, for no reason other than that
    # the catalogue was backend-only. A copy nobody can reach gets rewritten.
    attack["tactic_order"] = list(TACTIC_ORDER)
    return graph
