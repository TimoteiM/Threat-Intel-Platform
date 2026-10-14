# Stored values that do not parse as the type they claim

Built 2026-10-14, after the tenth delimiter-and-shape defect was found by
accident. `app/services/ioc_conformance_service.py`.

## Why one check instead of an eleventh fix

Ten such defects have been found in this corpus one at a time, each after it
had already distorted something. Four of them looked like one assertion
failing — *a stored value does not parse as the type it claims to be* — and
that is checkable in a single pass.

It is also **not the quarantine**. A check at extraction says what arrives
wrong from now on; this says what is **already stored wrong**, which is the
larger question and the one nothing could answer. Same predicate, two
consumers, so the two can never disagree about what a valid value is.

## What it found

### `iocs` — the typed store, where the claim is explicit

5,448 distinct (type, value) pairs, 16,983 rows.
**103 nonconforming values (1.9%), carrying 160 occurrences (0.9% of mass).**

| kind | values | occurrences | example |
|---|---|---|---|
| `domain:single_label` | 75 | 129 | `2a02:2350:6::fb15:59af` — an **IPv6 address stored as a domain** |
| | | | `cert_sha256:9fde822f7a2e...` — a **prefixed value**, the label kept |
| `domain:no_public_suffix` | 13 | 14 | `CN=evantage.eu (TLS subject)` — a **certificate subject DN** |
| | | | `accrt-coastnorth-5.amazonaws.com-we-hospital` |
| `domain:not_a_domain` | 7 | 7 | `cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js` |
| `url:no_scheme` | 4 | 4 | `olx.ro-confirm.site/v5BclV` |
| `ip:unroutable_as_indicator` | 1 | 3 | `127.0.0.1` |
| `hash:not_hex` | 2 | 2 | `224.0.0.251` — an **mDNS address stored as a hash** |
| `domain:address_as_domain` | 1 | 1 | `192.168.21.18` |

**Four defect classes nobody had named** are in there: IPv6 addresses stored
as domains, values carrying their own field prefix (`cert_sha256:`,
`tls.cert_sha256:`), a TLS subject DN stored as a domain, and an mDNS
multicast address stored as a hash. None was going to be found by looking.

### `ioc_values` — untyped, so the claim is inferred from shape

5,343 distinct values, 34,930 occurrences. 5 values had no inferable type and
were **skipped rather than guessed**, so these counts are a floor.
**17 nonconforming values (0.3%), carrying 219 occurrences (0.6% of mass).**

| kind | values | occurrences |
|---|---|---|
| `hash:degenerate` | 1 | **111** — the all-zero hash |
| `ip:mapped_ipv4_truncated` | 4 | **96** |
| `domain:no_public_suffix` | 11 | 11 |
| `url:non_web_scheme` | 1 | 1 — `ldap://...` |

## `::ffff:N` is a silent-negative generator, not a storage bug

`::ffff:192` **parses as a valid IPv6 address** — `::ffff:0.0.0.192`. So it
is not the address it came from, and every enrichment lookup, every
prevalence query and every estate question about an IPv4-mapped address has
been asking about a value that does not exist, and getting back *nothing
found*.

Which reads as clean. **The seven-month feed shape, one layer down, at the
observable itself.**

That is also why it survived ten rounds of finding the others: a value that
fails to parse is loud, and a value that parses as something else is silent.
The conformance check tests this case *before* `ip_address()`, because
otherwise it passes.

### The 96 is a count of survivors, not of occurrences

There are **zero** full IPv4-mapped IPv6 addresses anywhere in the corpus. So
the failure is **total** for that address family: nobody can say how often
such an address actually occurred, only how often a truncated remnant was
kept.

`sweep()` reports that as an `Absent`, not a number. **The true exposure is
unknown and the direction is upward.**

## What this check cannot catch, and why that is the finding

Two of the four cited classes **pass**, and asserting otherwise would have
been the more expensive error:

| value | verdict | why |
|---|---|---|
| `6.0.4.27` | **conforms** | `6.0.0.0/8` is allocated and routable, so this is a syntactically *and* semantically valid public IPv4 address. Nothing structural distinguishes it from a real one — the evidence that it is a version string is contextual, beside a product name in the alert body |
| `http://schemas.microsoft.com/win/2004/08/events/event` | **conforms** | a well-formed `http` URL with a host under a real public suffix. It is simply never fetched |

So the four classes were not one assertion. **Two are type-conformance
failures** — a value that is not of its type. **Two are semantic
misclassification** — a valid value of its type that is not an *observable*.
Those need different evidence: context from the alert body, or
non-resolvability, and a list of namespace hosts would be the ninth
hand-maintained list.

The split is worth keeping because it says where the remaining work is. The
structural half is now one test. The semantic half is still per-case, and
`6.0.4.27` at 75 cases and the schema URL at 85 are both in the prevalence
head where a threshold would hide them.

## The statistic, and a prediction that failed informatively

The expectation was that removing the defects would move a percentile. It
did not — p99 went 17 → 16.

**Percentiles exist to ignore outliers**, so predicting one would move
*because* of outliers was the wrong statistic for the claim. The figure that
demonstrates it is the mass: **15 values carrying 23.8% of all case-pairs.**
A quarter of every co-occurrence in the corpus coming from fifteen broken
values is more damning than any percentile shift, and no percentile was ever
going to show it.

**The general form: when the claim is "a few bad values are distorting
this", measure the mass they carry, not where the distribution bends.**

`sweep()` reports mass beside count for exactly that reason — 103 values at
1.9% of the population carrying 0.9% of occurrences is a different finding
from 1 value carrying 111.
