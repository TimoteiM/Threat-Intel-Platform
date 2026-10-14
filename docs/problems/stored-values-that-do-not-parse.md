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

### The 96 is a count of survivors — and the exposure is measurable after all

There are **zero** full IPv4-mapped IPv6 addresses in the stored IOCs, so the
failure is **total** for that address family: the 96 remnants are survivors,
not occurrences.

**Correction to an earlier claim of mine.** I wrote that the true exposure
was unknown. It is unknown *from the stored IOCs* — but the alert bodies are
retained, and they still have the originals:

| | |
|---|---|
| alert bodies containing a full `::ffff:a.b.c.d` | **93** |
| full mapped addresses in stored `ioc_values` | **0** |

So the loss is bounded below by 93 bodies rather than unknowable, and the
truncation happens **at extraction**, not at the source. That is a better
finding than the one it replaces: the direction is still upward (93 bodies is
a floor on bodies, not on occurrences), but "unknown" was the wrong word
when the evidence was one table over.

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
structural half is now one test. The semantic half needs different evidence —
and that evidence turns out to exist.

## The semantic half: field provenance, per format

The proposal was to record which alert field each observable came from, so
"a valid value of its type that is not an observable" becomes a lookup. The
premise needed checking, and it was half right in an instructive way.

### What does not work: one positional heuristic

`extract_alert_indicators` takes the alert body as a **string**, and
`mask_structured_keys`' own docstring already said `json.loads` "fails on the
majority of real deliveries". Measured over the 400 most recent bodies:
**0 of 400 parse as JSON.**

Keys *are* identified positionally by `_STRUCTURED_KEY_RE`, so the nearest
preceding quoted key is recoverable without parsing. Measured over 1,552
indicator occurrences:

| | |
|---|---|
| with a recoverable preceding key | **323 (20.8%)** |
| none — free text | 1,229 (79.2%) |

**And it misattributes both motivating cases.** `6.0.4.27` came back as
`detailEntry` and the schema URL as `errorNumber` / `entityName` — adjacent
keys from a *different* log line in the same body, not the owning field. A
false attribution is worse than none, because it asserts a field that does
not own the value. **The heuristic must refuse rather than guess.**

### What does work: the format's own structure

The bodies are not unstructured — they are in **several different formats**,
and each defines field position in its own terms. Of 16,969 stored bodies
(overlapping, since one body can carry several):

| shape | bodies | share |
|---|---|---|
| quoted JSON keys | 5,647 | 33.3% |
| `Label:  value` prose (Windows event text) | 1,240 | 7.3% |
| Windows Event **XML** (`<Data Name="…">`) | 392 | 2.3% |
| **CEF** (`CEF:0|vendor|product|version|…`) | 257 | 1.5% |

And in those terms both motivating cases are **definitional, not heuristic**:

```
6.0.4.27      97 bodies contain it — 97 of 97 in CEF field 4
              CEF:0|Silverfort|Admin Console|6.0.4.27|Authentication|...
              Field 4 of a CEF header IS Device Version, by the format's
              own definition. Not a judgement. 100%.

schemas...    392 bodies contain it — 391 of 392 inside an xmlns= attribute
              <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              An XML namespace declaration. 99.7%.
```

So the answer is **per-format field extraction**, not one nearest-key rule:
CEF by position, Windows Event XML by `Data Name=`, JSON by key, label prose
by label. Each is a parser for a named format rather than a list of bad
values, and each generalises — a new CEF source gets Device Version right on
arrival with nothing added.

### The limit I wrote first was wrong, and by a wide margin

I wrote that the uncovered bodies are "free text, and never will have field
provenance". **Nothing had established that.** The four formats summed to
44.4% and I reported the other 55.6% as a known negative when it was
*unclassified* — an absence presented as a measurement, which is the exact
shape this platform exists to avoid.

So it was censused. Every body classified once, most-specific shape first,
so the shares sum to 100% — unlike the earlier overlapping counts, which is
what made 44.4% look like coverage:

| shape | bodies | share |
|---|---|---|
| `Label: value`, single space | 7,386 | **43.5%** |
| embedded JSON keys | 5,270 | 31.1% |
| bare `key=value` pairs | 2,704 | **15.9%** |
| `Label:  value` prose | 813 | 4.8% |
| Windows Event XML | 283 | 1.7% |
| **CEF** | 257 | 1.5% |
| JSON object | 178 | 1.0% |
| syslog RFC3164 | 54 | 0.3% |
| syslog RFC5424 | 14 | 0.1% |
| **unclassified** | **10** | **0.1%** |

**99.9% of bodies have a parseable shape.** The "55.6% of free text" was
overwhelmingly two shapes I had not tested for — label-value with a single
space (43.5%) and bare `key=value` pairs (15.9%).

One caveat belongs on this table rather than further down, because the
headline figure rests on it: **the `embedded JSON keys` row over-matches.**
Measured afterwards (below), only 394 of the 5,666 bodies carrying a quoted
key hold an object that actually parses; the rest read as label-value prose
in which a quoted word before a colon is punctuation, not a key. Ordering the
classifiers made the shares sum, which was the defect being fixed, and it did
nothing to make each classifier *correct* — so 31.1% is an upper bound on that
row and most of its mass likely belongs to the label-value rows above it. The
99.9% survives either way, since both candidate shapes are parseable; the
per-shape split does not.

And the 10 that remain are not free text either. Six of the first six
sampled are **double-escaped JSON** — `"{\"approxLogTime\":...}"` — which
my own key regex missed because the quotes arrive as `\"`. Two are genuine
prose. So the floor for "no field provenance possible" is nearer **2 bodies
than 9,000**.

The real limit is therefore much narrower and worth stating accurately:
field provenance needs a parser per shape, and there are nine shapes rather
than four. Nothing in this corpus is beyond reach for want of structure;
what is outstanding is parser work, which is a different and much better
problem than the one I described.

What it buys is unchanged: the two classes this sweep could not catch become
answerable for the sources where they occur, and each occurs almost entirely
in one format.

### The CEF parser, and the eleventh instance caught before it was live

`app/services/cef_header_service.py`. Field 4 is Device Version by
specification, so the attribution is definitional.

**CEF escapes a literal pipe inside a header field as `\|`.** A naive
`split("|")` on such a body shifts every later field by one and reads Device
Event Class ID as the Device Version — no exception, no empty value, just the
wrong field under the right name. That is the eleventh delimiter-boundary
instance in this codebase, and it would have been **latent inside the parser
written to fix the tenth**.

Measured: **0 of 257 CEF bodies in the corpus contain an escaped pipe.** So
it is not live — which is why it had to be written now rather than after a
new CEF source arrived with a product name like `Firewall \| Edge`. The
parser hand-scans for unescaped separators, and
`test_an_escaped_pipe_in_field_3_does_not_shift_field_4` asserts both that
the parser is right *and* that `split("|")` is wrong, so the test is not
passing for want of a failure mode.

### What "0 of 400 parse as JSON" actually measured

That figure justified the whole regex approach, so it was worth asking what
the instrument could and could not return. The check was `json.loads(raw)` in
a `try/except`, counting the non-raising cases — and a **double-escaped body**
`"{\"approxLogTime\":...}"` does not raise. `json.loads` returns a `str`. Such
a body would have counted as *parseable* while yielding no fields at all:
`::ffff:192` one level up, a value that parses as something else and is
therefore silent.

Classified by what `json.loads` actually returns, over all 16,969 bodies:

| outcome | bodies | share |
|---|---|---|
| `raises` | 16,908 | 99.6% |
| `returns dict` | 61 | 0.4% |
| **`returns str`** | **0** | **0.0%** |

So the original measurement was right — but nothing in it established *why*,
and it would have read identically if it had been wrong. The methodological
point stands independently of the result: an instrument that cannot
distinguish "parsed to nothing useful" from "parsed" is not measuring what it
is quoted for.

### The balanced-object upgrade, which is much smaller than hoped

The follow-up was worth running for what it could buy: a complete object —
balanced from the first `{` to its match — needs **no key regex at all**, and
would move the second-largest shape from heuristic to definitional. Bracket
matching has to be quote- and escape-aware, because a brace inside a string
literal is not a brace; the same class of mistake as splitting CEF on an
escaped pipe.

Of the **5,666 bodies carrying a quoted JSON key**:

| outcome | bodies | share of keyed |
|---|---|---|
| balanced but unparseable | 5,261 | 92.9% |
| **balanced and parses to a dict** | **394** | **7.0%** |
| never balanced | 11 | 0.2% |

**394 bodies — 2.3% of the corpus** — yield definitional field names, 349
distinct ones (`detectionTime`, `endpoint`, `productName`, `entityName`,
`severity`, `actor`, `client`…). Worth having, and far short of the 31.1% the
census put in `json_keys_embedded`.

Which is the finding, and it points back at the census rather than forward at
the parser: **samples of the 92.9% read as label-value prose**, where a quoted
word followed by a colon is ordinary punctuation and not a JSON key. So the
`json_keys_embedded` bucket over-matches, and the census shares in the section
above need the same scepticism as the 44.4% they replaced. An ordered
classifier makes shares sum; it does not make each classifier correct.

### `Label: value` — the eleventh instance, in the largest format

`app/services/label_value_service.py`. **7,386 of 16,969 bodies (43.5%)**, the
biggest shape there is, parsed by a rule that cannot tell where a value ends
once the value contains a space — a file path, a command line, a display name,
a process argument:

    Account Name:  adm_lbyfszaa   Display Name:  Zakaria El Bouyafsakh adm

"Value is everything up to the next whitespace" returns `Zakaria`. The
discarded tail is then available to be read as the *next label*, so
`El Bouyafsakh adm   Home Directory:  -` can yield a field named after the
wreckage with the real label swallowed into it.

**The fix: a value ends where the next label begins, never at a space.**
Labels are located first and each value is the text between its own colon and
the start of the next label — so nothing is split on a character, and a value
carrying spaces, a Windows path, or a time like `09:38:44` survives whole. A
label is deliberately narrow (one to four capitalised words, colon, then
whitespace), which is what excludes `C:\Windows` and the `https:` in a URL.

Its test was written before the parser, and the control that asserts the naive
reading fails is where the real severity showed up. On the sample body the
naive parse does not merely truncate: multi-word labels collapse to their last
word, so `Account Name`, `SAM Account Name`, `Display Name` and `User
Principal Name` all become `name` and overwrite each other. **Eight fields
recovered from a body carrying twelve, and `Zakaria El Bouyafsakh adm` absent
from the output entirely** — not truncated, gone. A delimiter bug in the
largest format does not produce visibly bad values; it produces fewer values.

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
