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

## A correction first: the measurement had to be redone

The first version of these figures read the `alerts` payload returned by
`correlate_alerts`. That list **caps at 100 per case and keeps the earliest**,
because `ordered` is sorted ascending by event time and the slice takes the
front. 24 cases are over the cap and **6,533 of 12,064 memberships (54.2%)
sit in the discarded tail** — which is precisely the late arrivals being
counted. `#1849` showed the first 100 of 1,889 alerts; `#71` the first 100 of
1,217.

`alert_count` already differed from `len(alerts)`, so the truncation was
detectable and nothing detected it. The cap is now a parameter and every case
carries `alerts_truncated`. Every figure below is the full membership.

## The finding: the rule's *shape* matters more than its value

Measured by simulating each candidate rule against the real alert stream over
1,015 derived cases and **12,064 alert memberships**, with membership from the
derivation so each case's alerts are its own.

**Today's rule — the window runs from the case's opening:**

| close window | cases that accrete after it | memberships arriving late |
|---|---|---|
| **10 min (the rule that stood)** | **236 (23.3%)** | **9,731 (80.7%)** |
| 1 h | 178 (17.5%) | 8,381 (69.5%) |
| 6 h (= `SESSION_GAP`) | 71 (7.0%) | 5,514 (45.7%) |
| 12 h | 37 (3.6%) | 2,947 (24.4%) |

**The same windows, but the rule lags the last alert instead of the opening:**

| close window | cases that accrete after it | memberships arriving late |
|---|---|---|
| 10 min | 231 (22.8%) | **897 (7.4%)** |
| 1 h | 160 (15.8%) | 319 (2.6%) |
| **6 h (= `SESSION_GAP`)** | **29 (2.9%)** | **31 (0.3%)** |
| 12 h | 10 (1.0%) | 11 (0.1%) |

Two things fall out:

**1. At the same ten-minute value, changing the rule from "since opening" to
"since the last alert" takes late memberships from 80.7% to 7.4%** — an
eleven-fold reduction with no change to either constant.

And this is not a new discovery. The closure module's own test header records
the measurement taken before the feature was built: *"closing ten minutes
after a case opens strands 9,244 alerts outside their own case (81% of
everything); ten minutes after its last alert strands 821. The clock runs on
last activity, and that is an 11x difference, not a preference."* On a
different corpus — 11,376 alerts then, 12,064 now — I measure 9,731 against
9,244 and 897 against 821. The rule was changed away from what that
measurement chose, the header was left in place as the evidence against the
change, and changing it back recovers the same factor. The dominant defect is
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
29 cases violate that. The reason is structural rather than a flaw in the rule:

**26 of the 27 measured before the cap was lifted (96%) were explained by
sibling cases interleaving.** A session
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
