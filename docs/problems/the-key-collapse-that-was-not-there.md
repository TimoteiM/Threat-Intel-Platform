# The key collapse that was not there, and the one I introduced fixing it

A control test demonstrated that a naive `Label: value` parse merges
`Account Name`, `SAM Account Name`, `Display Name` and `User Principal Name`
into one key, `name`, with last-writer-wins deciding which identity survived.
The reasonable inference: every Windows authentication event in the corpus has
yielded one identity field where four existed, so the attack graph's Account
nodes, the `ran_as` edges and the whole identity layer rest on it — and
re-materialising with a correct parser would be a **supersession event**,
because analysts have looked at those graphs.

It isn't, and the chain of measurement that establishes why also found a worse
defect in the fix itself.

## 1. The collapse was never in live code

The control simulated a naive parser. The live one is `read_fields()` in
`alert_graph_extraction_service`, and it is **line-anchored with a full
multi-word label capture**:

```python
_LINE = re.compile(r"^[ \t]*([A-Za-z][\w.\- ]{0,64}?)[ \t]*:[ \t]*(.*)$", re.MULTILINE)
```

The space inside `[\w.\- ]` is the whole difference: the label is captured
whole, so `Account Name` never becomes `name`. Over the 315 bodies carrying
two or more of the four identity labels, the keys it actually produces are:

| key produced | bodies |
|---|---|
| `Account Name` | 305 |
| `SAM Account Name` | 145 |
| `Display Name` | 116 |
| `User Principal Name` | 3 |

Four distinct keys, not one. **The failure mode I demonstrated in a test has
never run against this corpus**, and reading a control test's simulation as a
description of production is its own small version of believing the comment
over the code.

## 2. The fix was worse than what it replaced, on four fifths of the rows

The first version of `label_value_service` bounded a value by the **next
label** and nothing else. That makes a newline invisible: a value runs on
until the next thing that looks like a label, swallowing whole following
lines. Against the 25,186 materialised account nodes it disagreed with the
live parser on 12,421, and the direction is the finding:

| direction | rows | share |
|---|---|---|
| **mine over-extends** (live value is a prefix of mine) | 9,963 | **80.2%** |
| genuinely different | 2,456 | 19.8% |
| live over-extends | 2 | 0.0% |

```
live : 'WINDOWS-TEST-DE\Attck_User'
mine : 'WINDOWS-TEST-DE\Attck_User\n\nMitre.Sub_technique.'
```

The line-anchored parser was right. **That is the twelfth delimiter-boundary
instance in this codebase and it was inside the fix for the eleventh** — the
sixth time in three days a defect has gone into its own fix. A difference is
not an improvement, and had this been reported as "12,421 account nodes
change under the corrected parse" it would have read as damage found rather
than damage introduced.

The bound is now **the next label or the end of the line, whichever comes
first.** Both halves are needed and neither is sufficient: the line bound
alone is the live parser, which cannot split the 63.8% of bodies carrying
several pairs on one line; the label bound alone is what shipped first. After
the fix, on identity labels both parsers produce: **68.1% identical and zero
boundary disagreements** — no `mine longer`, no `live longer`, no `different`.

## 3. Three comparison errors, each inflating the apparent damage

Worth recording as a set, because all three produced a *larger* number and a
more alarming story, and none was caught by the code being wrong:

1. **JSON bodies in a text comparison.** `read_fields()` returns flattened
   JSON keys for the 36 bodies that parse, so diffing those against a text
   parse of the raw JSON compared two unrelated things. This is what made
   `id` look like `1790075106.306451307` vs `T1559`.
2. **Different fields compared as the same field.** The live Account node
   reads `data.win.eventdata.user`; my precedence list read `account name`
   first. Comparing them produced 2,456 "genuinely different values" that
   were two different fields, not one field parsed two ways.
3. **Count reported before mass.** 6,507 identity fields exist in the
   corrected parse and not the live one — which sounds like 6,507 lost
   identities. **91.5% of them are `-`**, Windows' spelling for an absent
   field. The substantive recovery is **554 values over 346 bodies (1.4%)**:
   343 Security IDs, 106 account names, 105 account domains.

## 4. The layer question, which settles it

Only fields `_ALIASES` maps can reach a node, and it maps exactly one
identity label:

```python
"User": "data.win.eventdata.user",
```

There is **no alias** for `Account Name`, `SAM Account Name`, `Display Name`,
`User Principal Name` or `Security ID`. So those labels are not read by the
graph whether a parser produces them or not — including the 343 recovered
SIDs, which cannot reach `targetUserSid` because `Security ID` has no entry.
Asking whether the parse changes them was asking a layer where the value
never arrives.

On the one field that *is* read, across all 25,186 account nodes:

| | rows | share |
|---|---|---|
| aliased `user` value identical | 25,176 | **100.0%** |
| live only (JSON body) | 8 | 0.0% |
| mine only | 2 | 0.0% |
| **value differs** | **0** | **0.0%** |

**No Account node's identity changes under the corrected parse, so
re-materialising is not a supersession event and the withdrawal machinery is
not needed here.** 78.3% of those nodes are keyed on a SID rather than a
label value, so their identity is value-independent in any case.

## 5. What is actually wrong, and it is not the parser

`_ALIASES` is a hand-maintained list, and it is the **eighth** silent registry
in this codebase. The graph's identity layer reads one identity field where
the corpus carries six, and **4,805 account nodes (19.1%) sit on a body
carrying an identity label that nothing maps.** No error is raised; the field
is simply never read, which is the failure shape every entry on that list has.

That is a real finding and a different piece of work from the parser. It was
filed rather than done, and then the before/after was predicted rather than
discovered — which killed the design.

**Correction to the number above.** The "343 Security IDs" counted as
substantive recovery was absence-as-value in my own measurement: the filter
excluded `-` and the empty string, and **234 of the 343 are `S-1-0-0`**, the
NULL SID, which is precisely how Windows writes *no principal*. A further 49
are `S-1-5-18` (LOCAL SYSTEM), a role true of every actor operating through
the machine. **Only 24 are individual domain principals.** I offered the
inflated figure as the reason to do the work, in the same report that named
mass-before-count as the error to avoid.

**And the predicted node count moves the wrong way.** Distinct account merge
keys now 756, projected under the alias **763** — it rises by 7. Of the 24
re-keyed rows, 12 merge and 12 **split**: `account:povgrp\did24` holds 7 rows,
one moves to a SID key, 6 stay, and one human becomes two nodes. Whether a row
gets a SID key depends on whether its own body carried the SID, not on who the
account is, so a partial SID source fragments identity rather than
consolidating it. The first version of the prediction, excluding only NULL and
ANONYMOUS, produced `account:sid:s-1-5-18` absorbing five distinct human
accounts — a tautological discriminator used as an identity.

The work is therefore a SID↔username resolution table, not an alias. Full
reasoning and the exclusion set in [backlog 11](../BACKLOG.md).

## What this cost and what it bought

The parser is correct now and was not before, and it was measured against
25,186 live rows rather than against my own expectation of it. The
supersession alarm was false, and the machinery stays unused — which is the
right outcome for a day on which the fix needed fixing.
