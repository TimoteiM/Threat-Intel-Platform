# Where our telemetry disagrees with the rule's ATT&CK mapping

**To:** the detection-engineering owners of the Wazuh ruleset
**From:** Threat Intel Platform, measured 2026-10-12
**Ask:** a verdict on the twenty shapes below — for each, is the rule's
mapping right, is ours, or is neither? We are not proposing to change
anything on your side. We need to know which of the two answers to believe
before we decide what our platform shows.

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
  fix and not ours. If our reading is right, the right destination is upstream.
- **528 are on local rules**, which is the part this estate controls.
- 18 carry a rule id we could not parse, which is ours to look at.

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
