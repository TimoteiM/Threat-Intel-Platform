# Should a retired technique's successor be drawn as a node?

Raised 2026-10-13. **Not built, and deliberately so.** This records the
question and why it is not a small one.

## What prompted it

Of 76 materialised case graphs that draw any ATT&CK technique, 8 draw nothing
but retired ids. On those cases the retirement note and the named current
equivalent are the only valid ATT&CK framing on the page — everything drawn as
a node is withdrawn guidance. The obvious next step is to draw the successor
too, so the graph itself shows something current.

## Why it is not obvious

**The detection never claimed T1685.** A technique node asserts that something
named this technique. Today every technique node carries `named_by`, which is
one of three measured states:

| state | meaning | nodes |
|---|---|---|
| `rule_only` | the rule's author mapped it in advance | 29,570 |
| `model_only` | our analysis supports it, no rule claimed it | 4,308 |
| `both` | both | 12 |

A successor node fits none of those. The rule did not claim it; our telemetry
did not support it; it is an *equivalence asserted by MITRE between two ids*,
which is a fourth kind of claim. Letting it join `rule_only` would be
inventing a mapping and attributing it to a detection author who never made
it — the exact conflation this platform spent 2026-10-12 removing in four
other places.

## What it would need

A fourth provenance state, named for what it is — the catalogue says this id
replaces one the rule claimed — carried through `technique_naming_service`,
the node attrs, the panel, the CLI, the outbound document and the exports,
the same five surfaces as the others. Plus an answer to what the edge means:
the successor was not evidenced by the alert, so an `evidenced_by` edge would
be false, and a node with no edge is unplaced.

## The cheaper thing, which is done

The panel names and links the current equivalent — `T1685 — Disable or Modify
Tools`, pointing at its own ATT&CK page — rather than showing a bare id the
analyst has to look up. That invents nothing: the catalogue already carries
the name, and the claim being made is MITRE's, stated as MITRE's.

Whoever picks this up should decide the provenance question before writing
any rendering code. The rendering is the easy half.
