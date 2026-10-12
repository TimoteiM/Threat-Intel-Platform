"""
Regenerate `app/analyst/attack_reference.py` from the MITRE ATT&CK STIX bundle.

The reference catalog is not the whitelist. `TECHNIQUE_DB` says what this
platform can produce evidence for and therefore what it is willing to assert;
this catalog only says what a technique *is*, so a technique a detection claimed
can be named and placed on the matrix even when we can never corroborate it.
Without it every such claim lands in an "Unmapped" bucket that says nothing.

Generated rather than fetched at runtime: the catalog changes a few times a year,
and an offline deployment must not lose technique names because GitHub is
unreachable.

    curl -sSLO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python -m scripts.generate_attack_reference enterprise-attack.json

Revoked and deprecated techniques are kept: a rule written years ago still
claims them, and the honest answer to "what is T1064?" is its old name plus the
fact that ATT&CK retired it — not silence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

OUTPUT = Path(__file__).resolve().parent.parent / "app" / "analyst" / "attack_reference.py"

HEADER = '''"""
Every ATT&CK Enterprise technique, by id — name, tactics, URL.

GENERATED FILE. Do not edit by hand; see `scripts/generate_attack_reference.py`.

This is a *reference*, not a whitelist. `TECHNIQUE_DB` in `attack_mapping` is the
set of techniques this platform can evidence and is therefore willing to assert.
This catalog is what lets a technique some detection claimed — including ones we
could never corroborate — carry its real name and sit under its real tactic
instead of in an "Unmapped" bucket.

A technique can belong to several tactics; ATT&CK's own matrix lists it under
each. `tactics` holds them all in ATT&CK's kill-chain order and `tactic` is the
first, used wherever a single label is needed.

Source: MITRE ATT&CK Enterprise {version} (STIX 2.1 bundle).

Three retirement flags, because ATT&CK distinguishes two kinds of retirement
and the difference is what an analyst needs:

    revoked     ATT&CK replaced this technique with another one, named in
                `revoked_by`. 19.2 revokes 149, every one with a successor.
                Revocation chains: `revoked_by` is the single hop ATT&CK
                states, `current_equivalent` is the end of the chain. They
                differ on three techniques in 19.2 and a label that wants to
                tell an analyst what to search for wants the latter.
    deprecated  ATT&CK retired it with no replacement. 12 of them.
    retired     either of the above. This is the union the platform's older
                `deprecated` key always meant, and the one UI payloads keep
                carrying under that name — see `test_attack_reference.py`,
                which asserts the outbound key is wired to the union and not
                to the 12-entry precise field.

`name` is ATT&CK's own page title — `Phishing: Spearphishing Link`.
`short_name` is the leaf alone — `Spearphishing Link` — for places too narrow
for the full form, such as a graph node label.
"""

from __future__ import annotations

#: The ATT&CK release this file was generated from. Surfaced wherever
#: technique coverage is reported: names change and ids get revoked between
#: versions, so "which ATT&CK" is part of the answer rather than a footnote.
ATTACK_VERSION = "{version}"

# id -> {{name, short_name, tactic, tactics, url, revoked, revoked_by,
#         current_equivalent, deprecated, retired}}
TECHNIQUE_REFERENCE: dict[str, dict] = {{
'''

# ATT&CK's own ordering of the Enterprise kill chain. Used so a multi-tactic
# technique's primary tactic is stable and matches how the matrix reads, rather
# than depending on STIX object order.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="enterprise-attack.json (STIX 2.1)")
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text())
    objects: list[dict[str, Any]] = bundle.get("objects") or []

    version = _version(objects)
    tactic_names = _tactic_names(objects)
    techniques = _techniques(objects, tactic_names)

    lines = [HEADER.format(version=version)]
    for technique_id in sorted(techniques, key=_sort_key):
        entry = techniques[technique_id]
        lines.append(f"    {technique_id!r}: {_render(entry)},\n")
    lines.append("}\n")

    args.out.write_text("".join(lines))
    revoked = sum(1 for e in techniques.values() if e["revoked"])
    deprecated = sum(1 for e in techniques.values() if e["deprecated"])
    retired = sum(1 for e in techniques.values() if e["retired"])
    successor = sum(1 for e in techniques.values() if e["revoked_by"])
    chained = sum(1 for e in techniques.values()
                  if e["current_equivalent"] and e["current_equivalent"] != e["revoked_by"])
    print(
        f"wrote {args.out} — {len(techniques)} techniques, ATT&CK {version}\n"
        f"  chains resolved past an intermediate: {chained}\n"
        f"  revoked {revoked} ({successor} with a successor recorded), "
        f"deprecated {deprecated}, retired (union) {retired}"
    )
    return 0


def _version(objects: list[dict[str, Any]]) -> str:
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version") or "unknown")
    return "unknown"


def _tactic_names(objects: list[dict[str, Any]]) -> dict[str, str]:
    """`credential-access` -> `Credential Access`, from ATT&CK's own tactic objects."""
    names: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and obj.get("x_mitre_shortname"):
            names[str(obj["x_mitre_shortname"])] = str(obj.get("name") or "")
    return names


def _techniques(
    objects: list[dict[str, Any]], tactic_names: dict[str, str]
) -> dict[str, dict[str, Any]]:
    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _attack_id(obj)
        if not technique_id:
            continue
        phases = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases") or []
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        ordered = sorted(
            {phase for phase in phases if phase},
            key=lambda phase: TACTIC_ORDER.index(phase) if phase in TACTIC_ORDER else 99,
        )
        tactics = [tactic_names.get(phase) or _titleise(phase) for phase in ordered]
        techniques[technique_id] = {
            "name": str(obj.get("name") or ""),
            # Before the parent prefix is composed below, so the leaf survives.
            "short_name": str(obj.get("name") or ""),
            "tactics": tactics,
            "url": _url(obj),
            # Kept apart. The old single `deprecated` flag was the union of
            # these, which meant the catalogue could say a technique had been
            # retired but never which technique replaced it — and "retired,
            # current equivalent T1685" is the whole of what an analyst needs
            # in order to search current ATT&CK.
            "revoked": bool(obj.get("revoked")),
            "revoked_by": None,
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "stix_id": str(obj.get("id") or ""),
        }

    # STIX names a sub-technique by its leaf alone — "Spearphishing Link" — which
    # is ambiguous out of context. ATT&CK's own pages title it "Phishing:
    # Spearphishing Link", and so does this platform's whitelist, so compose the
    # same form rather than leaving two naming conventions in one UI.
    for technique_id, entry in techniques.items():
        if "." not in technique_id:
            continue
        parent = techniques.get(technique_id.split(".", 1)[0])
        if parent and not entry["name"].startswith(f"{parent['short_name']}:"):
            entry["name"] = f"{parent['short_name']}: {entry['name']}"

    # Which technique superseded a revoked one. ATT&CK states this as a
    # `revoked-by` relationship between STIX objects, so it needs a second
    # pass over the bundle and a map back to ATT&CK ids.
    by_stix = {e["stix_id"]: tid for tid, e in techniques.items() if e["stix_id"]}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "revoked-by":
            continue
        old = by_stix.get(str(obj.get("source_ref") or ""))
        new = by_stix.get(str(obj.get("target_ref") or ""))
        if old and new:
            techniques[old]["revoked_by"] = new

    # ATT&CK revocation can chain: T1073 -> T1574.002 -> T1574.001, and
    # T1150 and T1162 both run through T1547.011 to T1647. Three cases in
    # 19.2, no cycles. `revoked_by` stays faithful to the single relationship
    # ATT&CK states; `current_equivalent` walks to the end of the chain,
    # because naming a successor that is itself revoked would give an analyst
    # the equivalent as of some intermediate release rather than as of this
    # one. The `seen` guard is for a future release that does form a cycle —
    # it would otherwise be an infinite loop inside a build script.
    for technique_id, entry in techniques.items():
        current, seen = technique_id, {technique_id}
        while techniques[current].get("revoked_by"):
            nxt = techniques[current]["revoked_by"]
            if nxt in seen:
                current = technique_id      # cyclic: claim no equivalent
                break
            seen.add(nxt)
            current = nxt
        entry["current_equivalent"] = None if current == technique_id else current

    for entry in techniques.values():
        entry.pop("stix_id", None)
        # The union, named for what it is. Every consumer that wants "has
        # ATT&CK retired this" reads here; nothing has to remember to OR two
        # flags together, which is how the two would drift apart.
        entry["retired"] = bool(entry["revoked"] or entry["deprecated"])
    return techniques


def _attack_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return ""


def _url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return str(ref["url"])
    return ""


def _titleise(phase: str) -> str:
    return " ".join(word.capitalize() for word in phase.split("-"))


def _sort_key(technique_id: str) -> tuple[int, int]:
    base, _, sub = technique_id.partition(".")
    return int(base.lstrip("T") or 0), int(sub or 0)


def _render(entry: dict[str, Any]) -> str:
    tactics = ", ".join(repr(tactic) for tactic in entry["tactics"])
    return (
        "{"
        f"'name': {entry['name']!r}, "
        f"'tactic': {(entry['tactics'][0] if entry['tactics'] else 'Unmapped')!r}, "
        f"'tactics': [{tactics}], "
        f"'url': {entry['url']!r}, "
        f"'short_name': {entry['short_name']!r}, "
        f"'revoked': {entry['revoked']!r}, "
        f"'revoked_by': {entry['revoked_by']!r}, "
        f"'current_equivalent': {entry['current_equivalent']!r}, "
        f"'deprecated': {entry['deprecated']!r}, "
        f"'retired': {entry['retired']!r}"
        "}"
    )


if __name__ == "__main__":
    sys.exit(main())
