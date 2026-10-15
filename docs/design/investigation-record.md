# The investigation record

An ordered list of steps, each a claim with its evidence, plus an origin, a
verdict and a summary. **An object three surfaces produce, not a feature of a
page.**

## Origins

| origin | produces a record | why |
|---|---|---|
| email investigation | **always** | the pipeline is already a fixed chain; it just does not write it down |
| alert investigation | **when the gate opens** | log context and the Falcon panel are already two steps nobody recorded |
| indicator lookup | **only on escalation** | the lookup is a fan-out, not a chain |

The lookup stays what it is: every source asked about one value in parallel,
fast and cheap. A benign lookup must never grow a second page. On a
`suspicious` or `malicious` verdict a record opens and the lookup gains **one
line** linking to it.

**That rule is also the cost gate.** The follow-up questions — did it run
here, what did the host do next, who used that host, did it spread — are the
expensive half, and they must not fire on a domain that turns out to be
`aka.ms`. 48 hosts resolved `aka.ms` last week; the follow-up chain on that is
pure waste and the gate is what prevents it.

## The email pipeline's existing steps

Read from the code rather than assumed — this is what slice 1 records, and the
list should be corrected against intent rather than the reverse:

| # | step | source |
|---|---|---|
| 1 | extract indicators from the message | `extract_email_iocs` — local |
| 2 | inspect attachment structure (real type, macros) | `inspect_attachments` — local |
| 3 | read attachment content | `file_content_service` — local |
| 4 | triage URLs to the ones worth paying for | `triage_email_urls` — local; 1,251 → 107 over the 87-email corpus |
| 5 | enrich sender domain, sender IP, URLs, hashes | parallel external I/O |
| 6 | sandbox the message | AnyRun, conditional on `run_anyrun` |
| 7 | aggregate risk | `_aggregate_email_risk` — local |
| 8 | interpret | **the one model call** |

Steps 1–4 and 7 cost nothing external. Step 5 is the quota spend, step 6 a
sandbox credit, step 8 the model call.

## How a step reads

**Every sentence comes from a template over structured fields.** One model
call, at the very end, for the summary only.

- The template set is a **table**, with a test that every step kind has one.
  A kind without a template renders raw JSON — the silent-registry shape.
- **No conditional *claims* in a template**, and the line matters or the rule
  gets routed around on the first real case:
  - **Allowed:** declared formatting helpers — pluralisation, number
    agreement, date formatting. "1 host" and "2 hosts" is formatting, and a
    rule that blocks it is a rule nobody keeps.
  - **Banned:** branching in the template body that adds or removes a clause
    carrying a claim. "No detections" and "no detections, and one of the hosts
    has no sensor" are different claims and get different templates. A clause
    bolted onto a sentence reads as a footnote; it was the finding.
  - **Enforced** by a test that parses each template for branching
    constructs and permits only calls into the declared helper set.
- A step that **could not be asked** — 403, `no_field_map`, `out_of_scope` —
  renders in the chain as **No claim**, with its reason. Dropping it silently
  shortens the investigation and nobody can tell.

## The summary, and how the constraint is enforced

The summary call receives **the step records only**, never the raw responses.
Three mechanisms, because intent is not enforcement:

1. **Structural.** The prompt is built by `project_for_summary(steps:
   list[StepRecord]) -> dict`, which takes the records and has no parameter
   through which a raw response could arrive. A test asserts that no step's
   `response_excerpt` substring appears in the outgoing payload — the same
   shape as the existing AI-payload sanitisation test, which inspects the
   actual outgoing request rather than the UI.
2. **Post-hoc, names.** `unverified_entities(summary, steps)` extracts every
   domain, IP, hash and hostname from the summary text (reusing the existing
   extractors, not a second parser) and returns those appearing in no step's
   `observables_found`. Stored as `summary_unverified_entities`.
3. **Post-hoc, quantities — because names were not enough.** "Executed on
   five hosts" when the step recorded two introduces no new *entity* and is
   exactly what a reader acts on. So **the summary carries no quantities at
   all**: it says what happened, the steps carry the counts, and they render
   immediately below it.

   `unverified_numerals(summary, steps)` returns every numeral in the summary
   — digits, and small spelled-out numbers (`one`–`twelve`, `dozen`) — that
   does not appear in some step's structured fields. Non-empty is a failure
   of the summary, not a note on it.

   This may prove too strict: a model writing prose will reach for "a handful"
   or "several", and may use a number that is correct but not literally
   present in a field. **If it does, it gets reported rather than relaxed
   quietly** — the figure to bring back is how often it fires and on what.
4. **Rendering.** The steps are the page. The summary is shown above them,
   labelled as derived, and **any unverified entity is marked in place**. A
   summary naming something no step recorded therefore cannot be read as
   evidence — and where summary and steps disagree, the steps are what is
   shown because they are what is rendered from.

## The record

**Per step:** ordinal · question in plain words · source · endpoint or index ·
the literal query · the response (bounded, below) · verdict · observables
found · observables selected · the warrant (field-control state, observation
floor, window) · absence kind where nothing was asked or the source refused ·
duration · cost.

**Per record:** origin (which surface, which alert/run/lookup) · actor ·
tenant · verdict · summary · and the gate counters — steps run, steps
escalated, observables stopped, model calls.

## Three constraints from today

### The actor is the submitter attribution column

One column, two features. It takes the shape `docs/design/submitter-attribution.md`
already specifies — a `kind` plus an optional user id, where `kind` is one of
`human`, `service_account`, `automated_ingest`, `predates_attribution`,
`recorded_unresolvable` — not a free string. A single `NULL` or
`"unidentified"` collapses four conditions that mean different things.

**And `indicator_lookups.actor`, shipped earlier today, is a `String(255)`
with `"unidentified"` for absent — i.e. exactly that collapse.** It is now the
weaker of two implementations of one idea. It converges on this shape in the
same change, rather than becoming the stale second copy.

### Storing literal responses stores customer data

These rows fall under the evidence-handling rules, so:

- **Bounded excerpt.** `response_excerpt`, capped at 4 KB per step, with
  truncation recorded as a flag rather than silently — a truncated response
  read as the whole response is the floor-as-fact shape.
- **What is kept:** the query verbatim (ours, not the customer's), the
  excerpt, and the derived fields. Not raw attachment bytes, not full message
  bodies, not credentials — the existing log sanitiser runs on the excerpt
  before it is stored.
- **For how long:** the record's lifetime is its parent run's. It inherits
  whatever retention the run has and is deleted with it; it does not become a
  second, longer-lived copy of evidence.
- **Inventory:** one entry in `~/evidence/INVENTORY.md` naming the table, what
  it holds, the question it answers and its deletion trigger.

### Fail-open in the pipeline, fail-loud in the record

A recording bug must never take an investigation down. But a recorder that
drops three of eight steps and then renders as a complete five-step chain is
the defect this record exists to close, one level up.

So the record carries an explicit **`incomplete`** flag with
**`incomplete_steps`** — which steps failed to record and why — the page
states it **above** the chain, and **a chain that did not record fully is
never presented as the investigation.** A silent short chain is worse than a
visible gap.

### The summary checks ship with the first summary, not after it

`unverified_entities` and `unverified_numerals` are **specified and not
built**, because slice 1 writes no summary — the email pipeline's existing
model call produces the resolution and no second call was added.

**The condition, so slice 2 cannot skip it:** the first change that writes a
`summary` to a record is the change that implements both checks and renders
their output. Not the next one.

Deferring them while no summary exists is correct. Deferring them *past* the
first summary makes the check a retrofit against something already on a page —
and a check added after the thing it constrains is already rendering is a
check argued against live output rather than one the output had to satisfy.
That is how `out_of_scope` acquired a test defending it.

So: a record with a non-null `summary` and empty
`summary_unverified_entities`/`summary_unverified_numerals` is only valid if
the checks ran and found nothing. If they have not been implemented, the
summary is not written.

## Build order

1. **Now — slice 1.** The record schema, the email pipeline writing to it, and
   the page rendering it. No new queries, no decision graph, no extra model
   call. This is the whole visible result and needs no new intelligence.
2. **Next.** The alert surface writing to the same record.
3. **Then.** The escalation rule on the lookup, and the follow-up questions it
   triggers.
4. **Last.** The decision graph, as **declarative data** — nodes are
   questions, edges are conditions on the prior verdict, and each node declares
   the source it needs and what the call costs, so the gate is evaluated
   *before* the call. Including the prevalence shortcut: an observable on more
   than N hosts whose first-seen predates the trigger **stops there and is
   counted, not queried**.
