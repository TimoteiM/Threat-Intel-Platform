# ATT&CK mappings: one question and one maintenance item

**To:** the detection-engineering owners of the Wazuh ruleset
**From:** Threat Intel Platform, measured 2026-10-12

---

## If you read one paragraph

**Two rules account for most of both findings, and they need two different
actions from two different owners.**

| rule | where it lives | what it accounts for | what would resolve it |
|---:|---|---|---|
| **81640** | **stock** Wazuh ruleset | 824 of 1,395 mapping conflicts — **59%** | a report upstream, not a change here |
| **103026** | **local** content | 312 of 371 retired-id mappings — **84%** | two id changes next time it is touched |

Everything below is the evidence for those two lines and the long tail behind
them. If the tail never gets looked at, these two still carry most of the
value — and neither is a backlog item: one is a report, one is a two-line
remap.

**Two things, deliberately separate.** Part one is a question about mappings that conflict with telemetry. Part two is a small maintenance item about ATT&CK versions — different problem, different fix, and it is not evidence for part one.

**Ask (part one):** a verdict on the twenty shapes below — for each, is the rule's
mapping right, is ours, or is neither? We are not proposing to change
anything on your side. We need to know which of the two answers to believe
before we decide what our platform shows.

---

# Part one — where our telemetry disagrees with the rule's mapping

## What this is

For every alert, two things name an ATT&CK technique: your rule, which names
it in advance from what the rule is looking for, and our analysis, which names
it afterwards from the telemetry the alert actually carried. Until last week
our platform displayed only the first and silently discarded the second.

Now it keeps both, attributed. On most alerts they agree. On 1,395 they name
techniques with no parent in common, which means one of them is wrong about
what happened — and if it is the rule, the wrong mapping is applied to every
future alert it fires.

Excluded from that 1,395, deliberately:

- 199 alerts where we agree with you and were simply more specific, e.g. your
  T1071 and our T1071.001. That is not a disagreement, and we are not asking
  you to look at it. We mention it because it is also the evidence that our
  attribution is competent at sub-technique depth, which is the reason to take
  the conflicts seriously.
- 3 alerts agreeing at the parent technique.
- Everything from hosts classified as test rigs.

## The split that decides who this is for

Wazuh reserves rule IDs of 100000 and above for local rules; below that is the
distributed ruleset. On that basis:

- **849 of the conflicts are on stock ruleset rules.** Those are not yours to
  fix and not ours.
- **528 are on local rules**, which is the part this estate controls.
- 18 carry a rule id we could not parse, which is ours to look at.

That first number changes what this document is. A mapping error in local
content is a configuration problem in one estate. A mapping error in the
distributed ruleset is wrong in **every deployment that uses it**, and nobody
running Wazuh has any particular reason to notice, because the rule fires
correctly — it is only the ATT&CK technique attached to it that is wrong, and
almost nothing downstream checks that against the telemetry.

So if you agree with our reading of 81640, the useful destination is not this
estate's configuration but an upstream report to the Wazuh ruleset's own
issue tracker. We are not in a position to file that credibly; you are. One
rule carrying 59% of the technique conflicts in a single estate is worth the
ten minutes it would take.

## The twenty shapes, 1,326 alerts (95.1% of all conflicts)

### On stock ruleset rules

| rule | rule name | techniques the rule claims | technique the telemetry supports | alerts |
|---:|---|---|---|---:|
| 81640 | Shell Execution Of Process Located In Tmp Directory | T1046,T1071,T1082,T1218,T1218.011 | T1059 | 824 |
| 1002 | Disable Or Stop Services | T1489 | T1071.001 | 8 |
| 81640 | Shell Execution Of Process Located In Tmp Directory | T1046,T1071,T1082,T1218,T1218.011 | T1105 | 5 |
| 1002 | Shell Execution Of Process Located In Tmp Directory | T1046,T1071,T1082,T1218,T1218.011 | T1059 | 3 |

Rule 81640 is the single biggest item in this entire measurement: 824 alerts,
59% of all conflicts. The rule is named *Shell Execution Of Process Located In
Tmp Directory* and maps to five techniques — Network Service Discovery,
Application Layer Protocol, System Information Discovery, System Binary Proxy
Execution and its MSIEXEC sub-technique — none of which is command execution.
Our analysis of the telemetry says T1059, Command and Scripting Interpreter.
For a rule whose own name is "shell execution", we think T1059 is very likely
right and the five claimed are very likely wrong. That is the conclusion we
would like checked rather than assumed.

### On local rules

| rule | rule name | techniques the rule claims | technique the telemetry supports | alerts |
|---:|---|---|---|---:|
| 103013 | EXP-4LWK334 - Shellcode/BOF-style process access from proc | T1055.001,T1106 | T1059.001 | 179 |
| 101703 | EXP-D0MY264 - Offensive Tool Execution | T1046 | T1059.001 | 47 |
| 103208 | Suspicious Legacy or Anonymous Named Pipe | T1559 | T1036 | 44 |
| 103223 | Named Pipe from Suspicious Execution Location | T1559 | T1036 | 35 |
| 101216 | EXP-22MY264 - Multi-Stage Execution by Host | T1078 | T1059,T1059.001,T1562.001,T1620 | 34 |
| 110158 | EXP-D0MY264 - Multi-Stage Execution by Host | T1078 | T1027,T1059,T1059.001,T1562.001 | 30 |
| 103224 | High-Frequency Named-Pipe Activity from Single Process | T1559 | T1059.001 | 25 |
| 101216 | EXP-22MY264 - Multi-Stage Execution by Host | T1078 | T1059,T1059.001,T1059.003,T1562.001,T1620 | 22 |
| 101210 | EXP-D0MY264 - Possible Remote Lateral Movement Activity | T1021.006 | T1059 | 16 |
| 101216 | EXP-22MY264 - Multi-Stage Execution by Host | T1078 | T1059,T1059.001,T1620 | 13 |
| 110145 | EXP-D0MY264 - Possible Remote Lateral Movement Activity | T1021.006 | T1059 | 10 |
| 103208 | Suspicious Legacy or Anonymous Named Pipe | T1559 | T1059.001 | 9 |
| 101216 | EXP-22MY264 - Multi-Stage Execution by Host | T1078 | T1059,T1059.001,T1105,T1562.001,T1620 | 8 |
| 101216 | EXP-22MY264 - Multi-Stage Execution by Host | T1078 | T1059,T1059.001,T1059.003,T1620 | 6 |
| 110145 | EXP-JFW2P34 - Possible Remote Lateral Movement Activity | T1021.006 | T1059 | 4 |
| 110172 | EXP-D0MY264 - Multi-Stage Execution by Host | T1078 | T1059 | 4 |

The *Multi-Stage Execution by Host* family (101216, 110158, 110172) maps to
T1078, Valid Accounts, and our telemetry consistently supports execution
techniques instead — T1059 and its sub-techniques, often with T1562.001 and
T1620. The named-pipe family (103208, 103223, 103224) maps to T1559,
Inter-Process Communication, where we read T1036 Masquerading or T1059.001.

## One caveat on the rule names, which is our problem

Rule id 1002 appears twice below with two different names. We have an unsettled
question about which column in our own schema holds the rule's name versus the
Wazuh rule *description*, and 1002 may be a case where we have attached the
wrong label. Please go by the rule id rather than the name if the two look
inconsistent, and tell us if a name here does not match the rule you know.

## What happens with your answer

Whichever way each verdict goes, we keep both attributions and show who said
what — we are not going to overwrite your mapping with ours. What your answer
changes is which one we present first and what we tell an analyst to trust.
If the answer is that our reading is wrong, that is the more useful result,
because it tells us our attribution needs work before anyone leans on it.


---

# Part two — four ATT&CK ids that 19.2 has retired

**This is a maintenance item, not an error, and it is much smaller than part
one.** It is in the same document only because it reaches the same people. If
part one is the one you have time for, do that one.

## What changed, and why nothing was wrong before

ATT&CK 19 reorganised Impair Defenses into a new T1685 family. Four ids your
rules map to were retired in that reorganisation. **A rule that mapped to
T1562.001 mapped correctly for the ATT&CK of its day** — this is a catalogue
moving underneath a correct mapping, which is the normal cost of ATT&CK
versioning and happens to everyone on every major release.

We only noticed because we pinned a current catalogue. Before that our
platform agreed with your ruleset perfectly, because neither of us had a
versioned reference to disagree with.

## The four, and what replaced them

| retired id | name at the time | current equivalent |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | **T1685** |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | **T1685.001** |
| T1562 | Impair Defenses | **T1685** |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | **T1685.005** |

## How much of this is actually yours

488 technique nodes in this estate carry one of those four ids. Of those:

- **371 come from a rule's mapping** — the part below
- **117 come from our own analysis**, and are ours to deal with, not yours.
  Our attribution has an ATT&CK knowledge cutoff like any other model, so it
  names ids from a pre-19 matrix too. We are not asking you about those and we
  mention them so the 488 is not read as 488 of your problems.

Of the 371, **one rule is 84% of it**:

| rule | nodes | claims |
|---:|---:|---|
| **103026** | **312** | T1562.001, T1562.002 |
| 62123 | 23 | T1562 |
| 103016 | 16 | T1562.002 |
| 102250 | 8 | T1562.001, T1562.002 |
| 61112 | 8 | T1562 |
| 62152 | 2 | T1562.001 |
| 100420 | 1 | T1562.001 |
| 60602 | 1 | T1562 |

337 of the 371 are on local rules (id >= 100000) and 34 on the stock ruleset.
So this is almost entirely local content, and almost entirely one rule.

## The ask

Nothing urgent. When rule 103026 is next touched, consider remapping
T1562.001 to T1685 and T1562.002 to T1685.001. That one change covers 84% of
this. The other seven are a handful of alerts between them.

Nothing breaks if this is never done — the rules fire identically either way,
and our platform displays the retired id with its current equivalent beside
it, so an analyst can always search the current matrix. The only cost of
leaving it is that the mapping drifts further from ATT&CK with each release.

## What we display in the meantime

Every one of those ids renders with its own name and this note:

> Retired in ATT&CK 19.2. Current equivalent T1685 (Disable or Modify Tools).
> A detection that mapped to this id mapped correctly for the ATT&CK of its
> day.

We do not show the successor's name in place of the id's own, and we do not
present the retirement as a detection being wrong, because it is not one.
