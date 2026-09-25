# Why the assistant session list was slow, and what it cost

Removing the incident graph helped and did not fix it. Three separate things
were making a session list of 21,568 rows feel heavy, and only one of them was
the graph.

## 1. The list returned the whole analysis of every row

`AssistantSessionListItem` carried `result_json`, `report_markdown` and the
sanitisation summary. A list row shows a title, a status and a date.

```
GET /sessions?limit=5    165 ms    108.5 KB     (20.8 KB per row)
```

Those fields moved to the detail response, and the query uses `load_only` so
Postgres never detoasts them for a page.

```
GET /sessions?limit=5    138 ms      2.0 KB     (0.4 KB per row)
GET /sessions?limit=25     7 ms      9.8 KB
```

## 2. Opening a session could ship 20 MB

An entry holds what was pasted **and** what was sent. Measured across 21,568
entries the pair averages 28 kB and reaches 20 MB; eleven exceed 200 kB.

Entry text is now capped at 100,000 characters per field, with `truncated: true`
and the real lengths alongside — so a reader is never quietly shown a fraction
as though it were the whole. Nothing is lost; it is simply not shipped.

```
the largest session      141 ms    199.3 KB    truncated=true, original 11,000,448 chars
```

## 3. Search read 201 MB of log text on every keystroke

The query joined sessions to entries with an `ILIKE` on both sides and ran
`count(DISTINCT id)` beside it. The page cost 61 ms and **the count 6,153 ms**,
because a count has to evaluate the predicate over every entry.

Two changes, and the second is the one that matters:

**Trigram indexes** (migration 034, `pg_trgm`, 55 MB for entries and 3.6 MB for
titles) make a *selective* search fast — a hostname, a hash, `kerberoast`:

```
page, rare term     61 ms ->     5 ms
count, rare term  6,153 ms ->   174 ms
```

**Content search is opt-in.** No index fixes a common term: `process` appears in
83% of the entry text, so the index returns most of the table and Postgres
rechecks each candidate against a TOASTed 14 kB average. That is real work.

So the default searches titles, and "Also search log content" is a checkbox
labelled *(slower)*:

```
title search 'process'            51 ms
title search 'EXP-4LWK334'        44 ms
content search 'kerberoast'      322 ms
```

Which matches how the search is actually used: you look for a host, an account
or a hash — all rare by nature. Searching every log for "process" was never a
question worth 6 seconds.

## What the graph removal was worth

It was not nothing — 437 MB of `result_json`, and a repair path that could
rebuild a 1.8 MB payload on *every* session read. It just was not the whole
story, and the list would have stayed slow without the three above.

Twenty-eight sessions written in the gap between migration 033 and its deploy
still carried a graph and were cleared by hand.

## What the assistant's list is for

The table had 22,675 sessions and the analyst had written 627 of them. The rest
were other features using the assistant as an engine:

```
alert_body          14,345   Alert Body Investigation
correlated_case      7,703   case narratives
manual                 618   someone pasted a log here
from_investigation       9   someone sent one here from an investigation
```

Both generated kinds already display their result on the page that produced
them, so the assistant's list was showing 97% rows that belonged somewhere
else. It now lists the two analyst source types, and `include_generated=true`
brings the others back for anyone who needs them.

Nothing is deleted and nothing stops being written. `get_session` was never
filtered, which matters more than it sounds: an alert investigation and a case
narrative both link to `/assistant?session=<id>`, and those ids are exactly the
rows the list now hides. A filter applied one layer too deep would have turned
every one of those links into a 404. A test pins that.

```
list page      1.20 ms ->  0.85 ms    Index Scan, migration 036
total count    2.42 ms ->  0.60 ms
rows listed     22,675 ->      627
```

**Content search did not improve, and this is worth saying plainly.** Narrowing
to 627 sessions does not narrow the work: Postgres hoists the `EXISTS` into a
hashed subplan and filters all 22,675 entries by `ILIKE` before any session
restriction applies. Rewriting it as a materialised CTE, a correlated `EXISTS`
with a `LIMIT` barrier, and a join with the filter pushed inside the subquery
all produced the same plan.

```
'process'      7,395 ms -> 7,456 ms
```

Making it fast needs the candidate ids resolved in a separate statement, which
is a real change to a feature nobody has asked about — content search is still
opt-in and still labelled *(slower)*. Left as it is, on purpose.
