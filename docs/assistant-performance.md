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
