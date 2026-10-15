# A field name is not a question

**Worked example.** Two rules wrote the same field and meant opposite things,
for four months, and the discriminator built on it would have reported failed
DNS lookups as evidence of contact.

This is not "check your field names". The field name was correct, the mapping
was correct, the aggregation was complete, and the value in every document was
a real domain that a real host had really submitted to DNS. The field was
still the wrong answer, because **a field holds values; a question needs a
value *and* the circumstances under which it was written.** Nothing in a field
name carries the second half.

## The case

`data.win.eventdata.queryName` is the field an estate asks "did any host look
up this domain?". It is a Wazuh decoding of a Windows event, and two different
Windows events populate it.

| period | rule | eventID | what the document records | docs |
|---|---|---|---|---|
| 2026-06-17 → 2026-09-27 | 61109 | **1014** | DNS name resolution **timed out** | 1,966 |
| 2026-09-29 → 2026-10-15 | 103700… | **22** | Sysmon **DnsQuery** — a host asked | 4,468,578 |

Event 1014 is a *failure*. The host tried to resolve the name and could not.
Event 22 is the lookup itself.

So for the first four months of the retention window the field was fully
populated and meant the opposite of what the lookup asked. A domain that
nothing in the estate could reach would have been reported as a domain a host
contacted — and in a phishing panel, "a host in your estate contacted this"
is the sentence that escalates a ticket.

Before 2026-10-02 there were **2** event-22 documents in four months. Not a
minority contamination: for that period the field meant "failed" almost
exclusively.

## Why every obvious check passed

Each of these was true, and none of them touched the problem:

- the field exists and is mapped as `keyword`
- it is populated — 4,470,660 documents over the window
- the values are well-formed domain names
- the aggregation completed: `timed_out: false`, 360 of 360 shards, 0 failed
- host coverage is broad: 175 of 180 agents
- the field name is literally the Microsoft field name for a DNS query name

The last one is the trap. The name `queryName` is Microsoft's, and in event 22
it does mean the name a process queried. In event 1014 it means the name that
failed to resolve. **Both are honest uses of the same name.** The field's
documentation, had anyone written it, would have been right either way.

## What the generalisation is

A field's meaning is a function of the **rule or decoder that wrote the row**,
not of the field. So a query that selects on a field alone has not asked a
question yet — it has asked for a column.

Three consequences worth keeping:

1. **Pin the producer, not just the field.** The fix is one clause:
   `data.win.system.eventID: 22`, applied to the DNS question only. It belongs
   beside the field in the code, not in a comment — `_SEMANTIC_FILTERS` in
   `estate_lookup_service` maps field → the clauses that make it mean what the
   caller thinks it means.

2. **The producer mix changes over time, so a one-off check expires.** This
   field's mix inverted on a single day. A test asserting "queryName means a
   DNS query" would have passed on data gathered after 2026-10-02 and been
   wrong about everything before it. The durable check is the pin, not a
   measurement of today's mix.

3. **Not every field wants the same pin.** `data.dstip` comes from a network
   appliance that writes no Windows event id at all, so applying the same
   clause would silently return zero — a different instance of the same
   mistake, in the other direction. The pin is per field *because* the
   producer is per field.

## The second instance, found the same day

Hours after the above, in a different product entirely. CrowdStrike Falcon's
alert record carries a field called **`data_domains`**, populated on 193 of
200 sampled alerts. The Falcon panel needed to ask "has the EDR seen an alert
mentioning this domain", and `data_domains` is the only field in 73 whose name
contains the word.

Its value is `['Endpoint']`.

It is a **data classification** — which data estate the alert concerns — and
has nothing to do with DNS names. Filtering it with a domain returns 200 and
zero rows, like every other guess at that API.

| | `data.win.eventdata.queryName` | `data_domains` |
|---|---|---|
| product | Wazuh / Sysmon | CrowdStrike Falcon |
| the name suggests | the DNS name a host queried | domains in the alert |
| it actually holds | that, **or** the name a lookup failed to resolve | a data classification, `Endpoint` |
| why the name is honest | event 1014 really does carry a query name | a "data domain" really is a domain of data |
| what reading it wrong produces | failed lookups reported as contact | an empty result reported as "the EDR has nothing" |

The same shape and a different mechanism. In the first case one field name
covered two *producers* with opposite meanings. In the second, one English
word covers two *domains of discourse* — DNS and data governance — and the API
picked the other one.

Which is the generalisation getting broader, not weaker: **a field name is a
label somebody else chose for their own question.** It is not evidence about
yours. The check is the same either way — ask the store to break the field
down, and look at the values before building on them. Here one sample value
would have done it: nobody reads `['Endpoint']` and thinks "domain name".

Two more from the same API, worth keeping as the pattern rather than as
trivia:

- **`source_ips`** is populated and holds `['10.66.66.12']` — *internal*
  source addresses. A field that accepts a valid IP, validates it, and can
  never match a remote one. Not a wrong name; a right name for a question
  nobody here was asking.
- **`behaviors.sha256`**, which does not exist at all, and whose non-existence
  the API reports as HTTP 200 with zero results. The name was *plausible from
  the vendor's older API*, which is the worst case: a name that was once
  right.

## How to find this class of thing

The query that settles it is a breakdown of the field's own documents by
producer:

```
GET /<pattern>/_search
{"size":0,
 "query":{"bool":{"filter":[{"exists":{"field":"<the field>"}},
                            {"range":{"<ts>":{"gte":"now-120d"}}},
                            {"terms":{"<tenant pin>":["…"]}}]}},
 "aggs":{"rule":{"terms":{"field":"rule.id","size":10}},
         "eid":{"terms":{"field":"data.win.system.eventID","size":10}},
         "dec":{"terms":{"field":"decoder.name","size":10}},
         "by_week":{"date_histogram":{"field":"<ts>","calendar_interval":"week"}}}}
```

Two producers in the `rule`/`eid` buckets is the signal. A step in `by_week`
says the mix changed, and the two have to be read together: here the step at
2026-09-28 and the 1014/22 split were the same fact seen twice, and either one
alone was ambiguous.

**Ask it before building on a field, not after a number looks wrong.** The
number here did not look wrong. It looked like infrastructure.

## Where it bit twice

The same field's two producers also broke the *bound* on the answer, not only
its meaning. Collection of event 22 began 2026-10-02, 107 days inside a
120-day retention window, so every `first_seen` was biased recent while
reporting itself as a fact. That half is written up separately in
`a-first-seen-that-is-really-a-collection-start.md`; the shared root is this
one. A field that two rules write has two histories, and both the value and
its limits come from whichever rule was running.

## Related

- `docs/problems/a-first-seen-that-is-really-a-collection-start.md` — the
  bound, and the anchor that was the upload time.
- README rule 16 (name the other world that produces the same observation).
  The two worlds here: "this domain is new to the estate" and "this telemetry
  is new to the estate". A complete aggregation does not distinguish them.
