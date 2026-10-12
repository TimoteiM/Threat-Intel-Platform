# Every ATT&CK mapping we show is an assertion

**Status** Determination complete. Two defects found and not yet fixed; the
product claim is settled and is the headline.

Every figure names its table.

---

## The claim, stated plainly

Measured 2026-10-12 across all 16,574 stored alerts, reading
`rule.mitre.id` from `alert_body_investigation_runs.alert_body` for the
mappings and `result_attack_assessment.techniques[]` for the verdicts:

|                      | all hosts | test rig excluded |
|---|---|---|
| ATT&CK mappings asserted by rules | 26,843 | 22,077 |
| assessment technique entries | 32,574 | 27,749 |
| **`status = confirmed`** | **42** | **4** |
| `status = not_corroborated` | 32,532 | 27,745 |
| confirmed share of mappings | 0.156% | **0.018%** |

**Ninety percent of all ATT&CK corroboration in this platform is on one test
machine.** With `windows-test-device` excluded, four confirmations remain
across the entire estate.

So the honest product statement is: **every ATT&CK technique this platform
displays is an assertion by the rule that fired, not a finding.** That is
already how the graph draws them — `inferred` renders as *claimed*, and only
`observed` renders as *corroborated* — but the ratio was not known.

## Could a production host be corroborated at all?

Yes, and the question was worth asking rather than assuming the telemetry was
incapable. Three runs outside the rig carry a confirmed technique:

    exp-4lwk334   T1036.008   confirmed, and the rule asserted T1036.008
    exp-4lwk334   T1036.008   same
    alpha-uma     T1566, T1566.002   confirmed, the rule asserted nothing

So this is not "production telemetry lacks the artifacts". Corroboration
happens on ordinary hosts. It is simply very rare — 42 of 32,574 entries — and
then two separate defects destroy most of what little there is.

## Defect 1: the graph keeps only corroborations the rule guessed first

A technique node is created **only** from `rule.mitre.id`, and marked
`observed` only if the assessment confirmed that same id. Corroboration is an
intersection of the rule's claim and the model's finding.

Of the 41 runs carrying a confirmed technique, **29 are discarded** because the
confirmed id is not one the rule asserted:

    22 runs   model confirmed T1036        rule claimed T1129
     4 runs   model confirmed T1036        rule claimed T1218, T1574.001
     2 runs   model confirmed T1003.001…   rule claimed T1218.011
     1 run    model confirmed T1566        rule claimed nothing
     1 run    model confirmed T1566.002    rule claimed nothing

The model confirming *Masquerading* where the rule claimed *Shared Modules* is
not a disagreement to discard — it is the finding. The rule's mapping is the
weaker of the two statements, and the graph keeps it while dropping the
stronger one.

`additional_techniques` is where a technique the rule never claimed belongs,
and the store holds **4,350** such entries. `confirmed_ids` in
`alert_graph_store_service` does not read it. `alert_correlation_service` does.
**Two consumers of the same column disagree about what counts as corroborated**,
which is the silent-registry shape again.

## Defect 2: the two production corroborations are not in the graph at all

Both `exp-4lwk334` runs carry `graph_source_type = NULL` — they have never been
materialised, because they arrived after the last backfill. So
`alert_graph_entity` holds 10 `observed` technique nodes, all on the rig, while
the source data holds 12 intersecting runs, two of them on a production host.

The graph tables are a cache that nothing keeps warm. The overnight handover
recorded the same shape independently: a re-run of `graph_backfill` grew
registry values from 2 to 74,649 and every other kind with them, so the tables
were already stale against the extractor before this.

## What this does and does not change

**Does not change:** how the graph renders. A rule-asserted technique has
always drawn as `claimed`, dashed, and only a corroborated one draws solid.
Nothing on screen has been overstating itself.

**Does change:** any statement of the form "we map N techniques". The right
statement is "we show N assertions, of which 4 have been independently
corroborated outside the lab". That belongs on a board slide in those words.

**Unfixed, and in this order:**

1. Read `additional_techniques`, and draw a confirmed technique the rule never
   claimed. Both halves are needed: reading it without drawing the node still
   loses the finding.
2. Decide what a disagreement means — the model confirming T1036 where the
   rule claimed T1129 is a *correction*, and the graph currently shows the
   rule's version alone. It should probably show both, attributed, the way a
   prior case's judgement is shown on a continuation.
3. Keep the graph tables warm, or state their staleness on the page. A cache
   nothing refreshes is a figure nobody can trust.
