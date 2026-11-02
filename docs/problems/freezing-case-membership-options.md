# Freezing case membership: migration options

**Decision already taken** (yours): a case is a query until a judgement is
attached to it, and a record from that moment on. Membership freezes on the
first durable write. Re-correlation after a freeze writes a new version
linked to the prior one, and never mutates a frozen set.

**This document does not choose.** It sets out what has to be built, the
options at each decision point, and what each one costs — including the ones I
think are wrong, with the reason.

Every figure below names the table it came from, because two sizing errors
this session came from correct queries against the wrong source.

---

## Part 1 — What has to exist regardless of the options chosen

### A single derivation path (condition 1)

Nine consumers compute membership four ways today, listed in
`derived-case-membership.md`. The one that must go first is
`app/cli/case_graph.py`'s own SQL: host plus `[opened_at, closed_at]`, which
over-counts because several cases on one host overlap in time. Measured by
running that join across `alert_case_spine` × `alert_body_investigation_runs`:
**359,023 memberships for 15,255 alerts, about 23 cases per alert.** That is
the query, not the data.

Condition 3 says fix or delete it before migrating, and I'd delete it. It
exists only so the CLI could read a case without going through correlation;
once membership is a table, the CLI reads the table like everything else.

After that, `correlate_alerts` becomes the only function that computes
membership, and every other consumer reads. Making the four-ways situation
impossible to recreate needs one of these:

| | how | cost |
|---|---|---|
| **A1** | A single `membership_for(case_key)` function; all consumers call it | Cheap. Nothing stops a tenth consumer writing its own SQL. |
| **A2** | A1, plus a test that fails if any file outside the derivation module contains SQL naming both `alert_case_spine` and `alert_body_investigation_runs` | Cheap, and it catches the recurrence. Brittle against legitimate joins. |
| **A3** | A database view, so "membership" is a single object the DB enforces | Cleanest conceptually. A view over a frozen table plus a live derivation is awkward; the two have different shapes. |

### The window stops being part of identity (condition 2)

This falls out of freezing, but only for frozen cases. An **open** case still
re-derives, so it still has a window — and the question becomes what window an
open case uses. That is a real decision, not a detail:

| | open-case window | consequence |
|---|---|---|
| **B1** | A single constant (e.g. the existing 720h `CASE_LOOKUP_HOURS`) | The 48-vs-720 bug cannot recur. A genuinely long incident spanning more than the constant cannot form at all. |
| **B2** | From the case's own `opened_at` to now | Identity no longer depends on a caller's window, and a long incident still forms. Cost grows with case age; a case open for a month scans a month. |
| **B3** | Caller-supplied, as today, for open cases only | Keeps today's flexibility, keeps today's bug for every open case. |

B2 is the one that actually removes the window from identity. It is also the
one whose cost I cannot predict without measuring, because 59.1% of cases hold
one alert and the auto-close quiet period is 10 minutes — so most cases are
open for minutes, not months. Worth measuring the distribution of open
duration from `alert_case_spine.opened_at` and `closed_at` before choosing.

---

## Part 2 — What "the first durable write" means

The freeze trigger has to be unambiguous, because it decides when a case stops
reflecting new evidence. Candidates, from the writes that exist today:

- a resolution (`alert_case_spine.resolution`)
- a narrative (`narrative_markdown`)
- a close (`closed_at`, by the job or by an analyst)
- a supersession pointer (`superseded_by_case_key`)
- an exported graph

| | trigger | consequence |
|---|---|---|
| **C1** | Close only | Simplest and latest. A case analysed but not yet closed still re-derives, so a narrative can come to describe a set that changed under it — the exact failure the decision exists to prevent. |
| **C2** | Any of the five | Matches the stated principle. Earliest freeze, so a case freezes while still open and visibly stops absorbing related alerts — which may surprise an analyst watching a live incident. |
| **C3** | Analysis or close (narrative, resolution, close), not export | A judgement freezes; a read does not. An exported graph then shows a set that can still change, so the export is a snapshot of something mutable. |

Measured from `alert_case_spine`: **of 1,909 rows, 1,811 carry a
`narrative_fingerprint` and 1,884 carry a `closed_at`** — so under C1 and C2
nearly the whole estate is frozen immediately, and the difference between them
is small in practice. It matters for *new* cases, where C2 freezes about ten
minutes earlier than C1.

A consequence worth stating plainly for C2 and C3: an alert arriving after the
freeze does not join the case. It either forms a new case (today's quiet-period
behaviour, which you already chose) or produces a successor version. Those are
different, and which one happens is Part 3.

---

## Part 3 — Re-correlation after a freeze

Your rule: a new version with a `derivation_version`, linked to the prior one,
never mutating the frozen set.

The open question is **what triggers a new version**, because "re-correlation"
is not one event:

| | trigger | consequence |
|---|---|---|
| **D1** | Only an explicit operator action | Nothing changes on its own. A case that grew after being resolved stays wrong until someone looks. |
| **D2** | A late alert that would have joined the frozen set | Matches "an incident that grows after being resolved should produce a visible successor". Needs a definition of "would have joined", which is the derivation running against a frozen case — affordable only if it is cheap. |
| **D3** | A change to the derivation logic itself | Catches the 2026-10-07 class of event: the formula changed and 881 rows orphaned. Produces a new version for every case at once, which is 1,909 successors in one go. |

D2 and D3 answer different questions and are not alternatives. D3 is what the
`CASE_KEY_VERSION` guard already anticipates.

---

## Part 4 — The backfill (condition 4)

Freezes come from evidence, never from re-derivation. Re-deriving a 2026-09
case under today's logic and calling the result its membership is rewriting
history — the same thing I declined to do with the resolutions on the dead
keys.

What evidence exists, measured on `alert_case_spine` (1,909 rows):

| evidence available | rows | what it supports |
|---|---|---|
| `alerts_at_close` > 0 | 1,720 | a **count**, not a set — proves how many, not which |
| `alerts_at_close` = 0 or NULL | 189 | nothing; and 0 means "never counted" (all are `expired`/`unreadable`) |
| `narrative_fingerprint` present | 1,811 | the narrative was computed over *some* set; the fingerprint may identify it |
| key still derives today | 1,009 | today's derivation agrees, which is weak evidence about the past |
| key does not derive | 900 | nothing from derivation at all |

**The hard problem: no stored evidence names the alerts.** `alerts_at_close`
is a count. So for a closed case there are these options and they differ a lot:

| | backfill source | cost / risk |
|---|---|---|
| **E1** | Re-derive and freeze the result | Cheapest. Explicitly forbidden by condition 4, and rightly: it writes today's answer as yesterday's history. |
| **E2** | Freeze only where the narrative or analysis names its alerts | Honest. Needs checking whether `result_json` on the runs, or the narrative's own text, identifies the member alerts. **I have not checked this yet and it is the single thing that decides whether a faithful backfill is possible at all.** |
| **E3** | Freeze nothing historical; frozen sets exist only for cases closed after the migration | Perfectly honest and loses nothing that exists. 1,884 closed cases keep deriving as today, with the window bug, forever. |
| **E4** | E3, plus an explicit `membership_unknown` state on historical cases | Honest *and* visible: a historical case says its membership was never recorded, which is the absence convention again. Costs a state to render in six places. |

E2's feasibility is a measurement I should take before you choose, and I will
if you want it: whether `alert_body_investigation_runs.result_json` or
`alert_case_spine.narrative_markdown` identifies the specific alerts each
narrative was written over.

**Ambiguous stays ambiguous.** Where the evidence supports more than one set,
or none, the row gets the unknown state and surfaces — the same discipline as
the 9 ambiguous supersession rows that kept every candidate.

---

## Part 5 — What I would want to measure before you choose

1. **Open-case duration** from `alert_case_spine.opened_at`/`closed_at`, which
   decides whether B2's cost is real or theoretical.
2. **Whether any stored artefact names a closed case's alerts** — decides
   between E2 and E3/E4, and therefore whether history can be recovered.
3. **How often a late alert would have joined a frozen case**, from event-time
   gaps, which sizes D2.

None of these is a long job. All three are measurements against named tables,
and each one removes a guess from a decision above.

## What I am not proposing

No schema and no chosen path. The three choices that change the shape of
everything else are: **B** (the open-case window), **C** (the freeze trigger),
and **E** (what to do about history). The rest follows from those.
