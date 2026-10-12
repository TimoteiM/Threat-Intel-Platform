# The Narrative layout has no tactic columns

Recorded 2026-10-12, after building a module for columns that do not exist.

## What is actually drawn

`CaseGraph.tsx` lays Narrative out with **dagre, `rankDir: "LR"`**. The
left-to-right reading comes from the graph's own structure — who spawned what,
what reached which host — and not from ATT&CK at all. A technique's tactic
does exactly one thing: it tints the node.

The comments say otherwise. One reads *"ATT&CK tactics in kill-chain order. A
node sits in the column of the…"*, another *"anything unmapped lands in its own
column rather than being guessed into one"*. Neither describes behaviour. They
describe an intention nobody implemented, and they have outlived the moment
when that was obvious.

## Why this is written down

A `planTactics` module was built against those comments — 19 passing tests,
nothing calling it. It was deleted rather than left in place, because tests
passing on code nothing calls read as "this works" to the next person, and
apparent authority exceeding reality is the failure this whole file is about.
The model below is the part worth keeping.

## The model, if the axis is ever drawn

Three absences that look identical on a canvas and are not the same claim:

| state | drawn? | what it means |
|---|---|---|
| **empty** | yes, as an empty column | The tactic exists in the ATT&CK being resolved against, and this case has nothing in it. "Nothing in Exfiltration" is a statement about the incident. A graph that silently omits the column says instead that nobody looked. |
| **retired tactic** | no — but reported | The tactic does not exist in this ATT&CK release. There is nothing to say about `defense-evasion` in 19.2 except that it is not a tactic any more, and an empty column for it invites someone to ask why it is empty. Report it separately: it means the data and the catalogue disagree about what a tactic is, which is worth knowing without being worth a column. |
| **unplaced** | yes, in a gutter outside the sequence | A node whose technique id this platform cannot name, so it has no tactic. Never folded into a real column — putting it in Execution converts "we cannot say" into a claim. It belongs outside the axis, treated exactly as `timeline.ts` treats untimed nodes: a labelled gutter, visually separated, carrying its own count. A column appended at the end of a kill chain reads as a final stage. |

Two further properties the deleted module had, and a replacement should keep:

- **With no `tactic_order` in the payload**, draw only the populated columns
  and invent no empty ones. Without knowing which tactics exist you cannot
  tell "nothing in Exfiltration" from "Exfiltration is not a tactic any
  more", and declining to draw a distinction beats inventing one. The
  dangerous version of this bug is the opposite: treating a missing order as
  "no tactics exist" and reporting the entire matrix as retired.
- **Keep the gutter out of the column list structurally**, not just
  positionally, so a renderer cannot draw it inline by accident.

## What the exercise did earn

The two hand-written lists in `CaseGraph.tsx` are gone — twelve tactic columns
and 38 technique prefixes, both written against a pre-19 ATT&CK, three
mappings pointing at a tactic that no longer exists, and no entry at all for
Stealth, which 6,290 technique nodes in this estate resolve to. `attrs.tactic`
and `attack.tactic_order` now arrive with the graph from the bundled
catalogue. That was the point, and it stands.

## The lesson

A comment says what someone meant. Only the code says what happens. This was
the second instance the same day: the `GENERATED FILE. Do not edit by hand`
header on `attack_reference.py` read as a guarantee about every field in it,
while the generator that produced it carried a hand-written tactic ordering
that had gone stale. Both times documentation asserted something the
implementation did not do, and both times the documentation was believed.
