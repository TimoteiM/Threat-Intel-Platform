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
"""

from __future__ import annotations

# id -> {{name, tactic, tactics, url, deprecated}}
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
    deprecated = sum(1 for entry in techniques.values() if entry["deprecated"])
    print(
        f"wrote {args.out} — {len(techniques)} techniques "
        f"({deprecated} deprecated/revoked), ATT&CK {version}"
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
            "tactics": tactics,
            "url": _url(obj),
            "deprecated": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
        }

    # STIX names a sub-technique by its leaf alone — "Spearphishing Link" — which
    # is ambiguous out of context. ATT&CK's own pages title it "Phishing:
    # Spearphishing Link", and so does this platform's whitelist, so compose the
    # same form rather than leaving two naming conventions in one UI.
    for technique_id, entry in techniques.items():
        if "." not in technique_id:
            continue
        parent = techniques.get(technique_id.split(".", 1)[0])
        if parent and not entry["name"].startswith(f"{parent['name']}:"):
            entry["name"] = f"{parent['name']}: {entry['name']}"
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
        f"'deprecated': {entry['deprecated']!r}"
        "}"
    )


if __name__ == "__main__":
    sys.exit(main())
