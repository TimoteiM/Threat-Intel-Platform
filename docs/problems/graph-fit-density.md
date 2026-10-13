# A fitted graph can still be unreadable

**Status** Open. Seen in Narrative; it is not a Timeline problem and must not
be fixed inside one layout.

`cy.fit()` scales a drawing to whichever dimension binds first. Case #71 — 22
nodes over 14 rules — lays out tall and narrow under `dagre rankDir: LR`, so
fitting scales to the height and the nodes render at thumbnail scale on a
1440×900 frame. The fit is working; the result is unreadable.

Measured by rendering the real component against the endpoint's own JSON in
headless Chromium: #1849 (3 nodes) fills the frame, #1440 (33 nodes) is
comfortable, **#71 (22 nodes) is not**, and the difference is the aspect ratio
of the layout rather than the node count.

Why it belongs on its own
-------------------------
It is a property of fit-against-layout-aspect, so it will reappear in Timeline,
in Topology, and in whatever is added next. Fixing it inside the Timeline work
would fix it for one layout and leave it in the others — the same mistake as
one implementation per emitter grouping.

What a fix has to decide
------------------------
- whether to cap how far `fit` may zoom out, and read the overflow as
  pannable rather than shrinking past legibility
- whether a tall-narrow dagre result should become multi-column before
  fitting, rather than after
- what "readable" means as a number, so this can be measured rather than
  judged by eye: a minimum rendered node height is the obvious candidate and
  has not been agreed

Fullscreen now exists, so the symptom is reviewable; it is not a reason to
leave it.

---

## A claim drawn twice: 2,783 technique nodes that could go

Measured 2026-10-13, while adding the `refines` edge. **8.7% of all technique
nodes are a parent whose own sub-technique is drawn beside it** — 2,964 of
33,909. The `refines` edge makes the relation legible but adds a third
element, so one claim now occupies two nodes and an edge. That is worse for
density than before, not better.

The pairs split cleanly, and the split decides what may be done:

| parent / child provenance | pairs | what a collapse would merge |
|---|---:|---|
| `rule_only` / `rule_only` | 2,603 | nothing |
| `model_only` / `model_only` | 180 | nothing |
| **same on both sides** | **2,783 (92.9%)** | **nothing — pure redundancy** |
| `rule_only` / `model_only` | 202 | two different namers |
| `rule_confirmed` / `model_only` | 10 | two different namers |

### The proposed rule

**Collapse the parent into the child when both carry the same `named_by`;
keep both nodes and the edge when they differ.**

In the 2,783 same-provenance pairs one namer asserted the same thing at two
depths. The parent node carries no information the child does not, so folding
it removes a duplicate rather than a claim — and the existing absorb machinery
in `alert_graph_assembly_service` already records what was folded in
`absorbed`, merges witnesses and redirects edges, so nothing is lost and the
fold is inspectable.

In the 212 mixed pairs the two nodes are two namers. Collapsing them would
put one `named_by` on a node that two different sources named at two
different depths — the collapse of two statements into one that this codebase
removes everywhere else. Those keep both nodes, and the `refines` edge is
exactly what makes them readable.

### Why this is not built yet

It changes what an analyst sees on a large number of cases, and the rule —
collapse iff the provenance matches — is a product judgement rather than a
correctness fix. The measurement is here so the decision is cheap; the
machinery exists; the work is an hour.

Expected effect: **2,783 fewer nodes across the estate, 8.2% of all technique
nodes**, concentrated in exactly the graphs that have the most techniques and
are therefore the densest.
