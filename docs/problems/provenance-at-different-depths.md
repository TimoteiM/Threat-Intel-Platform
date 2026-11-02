# `both: 12` — what the four provenance states actually measure

Raised 2026-10-13, after `both: 12` against `rule_only: 29,570` and
`model_only: 4,308` was read as a smell about the comparison rather than a
finding about detection quality. Two hypotheses were tested. One is refuted,
one is real, and the real one does **not** contaminate the figure in
`docs/outbound/technique-disagreements.md`.

## Measured

Over every stored technique node, grouped by run:

    runs where both a rule id and a model id were drawn : 1,583
      share an id exactly                               : 12
      share a parent technique                          : 214
      parent-only agreements, invisible to exact match  : 202

    runs with rule ids but no model id                  : 13,099
    runs with model ids but no rule id                  : 590

## Grain — refuted

Both sides are recorded per **run**, against the same runs, from the same
alert. There is no denominator mismatch and the two can collide.

The 7:1 ratio has a different cause: a model technique exists only where the
investigation found supporting evidence, and that is rare — 770 of 16,564
assessments. 13,099 runs carry a rule mapping with no model technique to
compare it against, because nothing corroborated anything on those alerts.

## Specificity — real, 202 runs

Rules skew to parents (4,676 parents against 1,287 sub-techniques on these
runs); the model emits both (1,101 parents, 600 subs). So `T1071` from the
rule and `T1071.001` from the telemetry are the same claim at two depths, and
exact string equality scores them as two unrelated statements.

**202 runs agree at the parent and not exactly.** Arrived at independently and
confirmed against `app.cli.technique_disagreements`, which reports 199
refinements plus 3 parent-level agreements — the same 202.

## What this does and does not affect

**Does not affect the outbound figure.** The disagreement CLI already
normalises to parent and separates those 202 before counting genuine
conflicts, so the 1,399 going to detection owners are conflicts with no shared
parent. That number is safe, and it was safe before this check — but it is
safe by construction rather than by luck, which is worth knowing.

**Does affect the graph.** The four provenance states are assigned by exact
id. On those 202 runs the case graph draws two technique nodes — `T1071`
marked `rule_only` and `T1071.001` marked `model_only` — which reads to an
analyst as the rule and the telemetry disagreeing, when they agree and the
telemetry is more precise. That is the opposite of what happened.

**And it explains `both: 12`, partly.** `both` is not "rule and model agree".
It is "the rule claimed this id *and* the assessment marked that id
`confirmed`" — corroboration, which is rare by construction: 41 alerts
estate-wide carry a confirmed technique. Exact matching then costs it the 202
parent-level cases on top. Twelve is low because corroboration is rare, not
because the comparison is broken.

## The open question

A fifth provenance state, or a refinement relationship between two nodes,
would let the graph say "the rule claimed the parent and the telemetry refined
it" instead of drawing a contradiction. That is the same class of decision as
[drawing a successor technique](drawing-a-successor-technique.md): it needs a
provenance answer before any rendering, and `refined_by` is a different claim
from `both`. Not built.
