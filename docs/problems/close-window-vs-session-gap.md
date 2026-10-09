# The close window and the session gap

**Status** Measurement complete for the ordering question. The two re-derivation
measurements (what each `SESSION_GAP` value does to case count and to the three
true positives) are running separately and will be appended.

**The question** 57.9% of alert memberships arrive after a case has been frozen
by the close rule, and 95.5% of cases holding 21 or more alerts accrete after
one. That is not incidents resuming. It is two constants disagreeing:

    SESSION_GAP   6 hours    app/services/alert_session_service.py
                             a gap wider than this starts a new case
    CASE_WINDOW   10 minutes app/services/alert_case_closure_service.py
                             a case closes this long after it OPENS

So a case closes at ten minutes while alerts can legitimately keep joining it
for six hours.

---

## The finding: the rule's *shape* matters more than its value

Measured by simulating each candidate rule against the real alert stream over
1,015 derived cases, with membership from the derivation so each case's alerts
are its own. 5,523 alert memberships in total.

**Today's rule — the window runs from the case's opening:**

| close window | cases that accrete after it | memberships arriving late |
|---|---|---|
| **10 min (today)** | **236 (23.3%)** | **3,198 (57.9%)** |
| 1 h | 174 (17.1%) | 2,317 (41.9%) |
| 6 h (= `SESSION_GAP`) | 61 (6.0%) | 967 (17.5%) |
| 12 h | 29 (2.9%) | 408 (7.4%) |
| 72 h | 0 | 0 |

**The same windows, but the rule lags the last alert instead of the opening:**

| close window | cases that accrete after it | memberships arriving late |
|---|---|---|
| 10 min | 226 (22.3%) | **641 (11.6%)** |
| 1 h | 155 (15.3%) | 274 (5.0%) |
| **6 h (= `SESSION_GAP`)** | **27 (2.7%)** | **28 (0.5%)** |
| 12 h | 10 (1.0%) | 11 (0.2%) |
| 72 h | 0 | 0 |

Two things fall out:

**1. At the same ten-minute value, changing the rule from "since opening" to
"since the last alert" takes late memberships from 57.9% to 11.6%** — a
five-fold reduction with no change to either constant. The dominant defect is
not the value of the window; it is that the window runs from a moment the case
has no further control over. A case that is still receiving alerts is not
quiet, and the present rule closes it anyway.

**2. The ordering rule works.** With the trailing rule and the close window set
to `SESSION_GAP`, late arrival falls to **2.7% of cases and 0.5% of
memberships**. That is the condition a successor path needs in order to mean
anything: at 95.5% on large cases it is the normal path wearing a safety
label; at 0.5% it is a correctness guarantee.

## Why the ordering rule does not reach exactly zero

It should, by construction: if any gap wider than `SESSION_GAP` starts a new
case, no alert can join a case more than `SESSION_GAP` after its predecessor.
27 cases violate that. The reason is structural rather than a flaw in the rule:

**26 of the 27 (96%) are explained by sibling cases interleaving.** A session
now yields several cases — alerts are grouped by what ties them together, not
merely by sharing a device and an afternoon — so consecutive alerts *within one
case* can be more than six hours apart when alerts belonging to a sibling case
fell in between. The host stream had no gap; this case did.

The one unexplained case is #91 on Windows-Test-Device, 100 alerts with a
6.5-hour internal gap, which is at the member-list cap of 100 and so is
probably an artefact of the cap rather than of the gap.

So the honest statement of the rule is: **the close window must be at least
`SESSION_GAP`, and that makes late arrival exceptional rather than
impossible**, with the residue coming from sessions holding multiple cases.

## What this costs, and what it does not

Raising the close window to six hours changes when a case closes, and that
touches anything measuring resolution time. It does not change membership,
scoring, or the graph. The separate question — whether `SESSION_GAP` itself is
too wide, i.e. whether six hours sweeps unrelated activity into one case — is
the subject of the re-derivation measurements, because that one *does* change
membership and therefore every case number in the estate.

## A related defect already paid for

`opened_at` was the session's start rather than the case's own first alert, so
**205 of 1,014 cases (20.2%) were born with an opening time earlier than their
first alert** — median 2.4 hours, max 2.3 days — and **172 were already past
the ten-minute close window at creation**, closing on the first pass of the
job with no quiet period at all. Fixed, but the consequence is recorded here
because it compounded with the rule above:

Of those 172, **169 carry a close count, and 13 hold more alerts today than
the verdict was formed on — every one of the 13 resolved `false_positive`**.
The worst is #464: judged on 5 alerts, now holds 20. So a verdict was formed
on a quarter of the evidence its own case now contains.

None of the three live true positives is affected: #1106, #1440 and #1833 all
have zero drift between their stored opening and their own first alert. #9 does
not re-derive so its drift is unmeasurable, but #9 is the superseded twin of
#1440, which is clean.
