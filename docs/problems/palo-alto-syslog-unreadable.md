# Palo Alto syslog: one source, four defects

**Status** Field map built (`app/services/panos_field_map.py`), wired into the
graph extractor, backfilled. Defects 1 and 2 are closed. Defect 3 is fixed
forward with 223 historical rows still cut. Defect 4 turned out not to be
about this source at all, and is now its own item.

**Four of this document's original figures were wrong.** They are corrected in
place below, with what they were and why they were wrong, because the error
was the same one three times: a filter that already assumed the answer.

Every figure names its table.

---

## What the source is

Comma-positional PAN-OS syslog, arriving outside Wazuh, plus a CEF key=value
form from the same firewall. One line, abbreviated:

```
<12>Sep 14 08:21:27 172.16.23.1 1,2026/09/14 08:21:26,013101014199,THREAT,spyware,2818,...
```

From `alert_body_investigation_runs`, matching the record's own two-timestamp
shape rather than the absence of a decoder:

    224 runs        1.5% of the 15,357 stored alerts
    734 records     a run holds 1 to 14 of them, median 2
    718 THREAT      vulnerability 619, spyware 62, wildfire-virus 34, virus 3
     95 CEF          cef:url 91, cef:end 4
     16 GLOBALPROTECT

> **Correction.** This document previously said **852 runs, 5.6% of the
> store**. That figure counted every run with no `decoder.name` and attributed
> all of them to PAN-OS. The no-field-map population is **945 runs**, and
> PAN-OS is 224 of them — 23.7%. The rest are Exabeam, Office 365 and
> Cloudflare CEF, SentinelOne JSON, RFC5424 syslog and Wazuh text. The
> original filter could not tell those apart from PAN-OS because *none* of
> them carries a decoder, which is the property the filter tested.

## The four defects, each measured

**1. No field map, so nothing was extracted.** Measured on
`alert_graph_entity`: **0 entities** from any of the 224 runs. Now, from the
same table after the backfill:

    860 ip      440 account   257 url   130 domain   37 file   16 unparsed
    637 connected_to   552 requested   450 attributed_to   294 hosted_on

The consequence was not an empty page — it was an empty page on a **true
positive**. Case #1106 is one of four cases in `alert_case_spine` resolved
`true_positive`; both its alerts are PAN-OS, and its graph drew nothing.

A second consequence, not noticed when this document was written: **168 of the
224 runs have `entity_host = NULL`**, and 48 of the remaining 56 are keyed to
`Alpha-UMa` — the firewall. So three quarters of these alerts had no subject at
all, and most of the rest were attributed to the device that reported them.
The source address and the User-ID principal are the subject, and the map is
the only way to reach them.

**2. No severity, so it could not be ranked.** Measured on
`alert_body_investigation_runs.source_severity`: **224 of 224 unrated**.

PAN-OS states a named grade at position 35 of a THREAT record, and it is
readable on **718 of 718**: high 455, low 167, medium 96. Normalised onto the
same 1-100 scale as FortiGuard IPS so the two firewalls rank together, and
resolved with the same LOUDEST WINS rule — which matters more here than for
FortiOS, because one body holds up to 14 records and 34 runs carry records
that disagree with each other.

13 runs remain unrated. Every one is GLOBALPROTECT-only, and they say so.

**3. Truncated titles, feeding truncated case names.** Measured before
migration 057: **774 rows stored a `title` of exactly 255 characters**. The
syslog line is long and lands in `title`, and the case label derives from the
first alert's title, so a truncated title became a truncated case name. The
column is now `text`, which stops new truncation; the already-cut values
cannot be recovered from the title column, though `alert_body` still holds the
full line.

> **Correction.** This document previously said **771 rows, and all 771 are
> this source**, on the evidence that all 771 had `source_severity = NULL`.
> That inference does not hold: *every* unmapped source is unrated, so a NULL
> severity cannot distinguish one unmapped source from another. It is a fact
> true of the whole population being partitioned, which cannot partition it —
> the fourth time that shape has shipped in this codebase.
>
> Measured directly instead, by testing each cut title's body for a PAN-OS
> record: **223 of the 774 are this source (28.8%)**. The rest are Wazuh
> `Error unknown error <Event xmlns=...` (51), Office 365 CEF (45), Cloudflare
> CEF (33), Windows logon text (19), SentinelOne JSON (19) and RFC5424 syslog
> (36). So this is a general problem with long bodies, and PAN-OS is its
> largest single contributor rather than its only one.

**4. It scores near zero — and that is not this source's defect.** 140 live
cases have this as their dominant source, with a median `peak_score` of 0.

> **Correction.** This document previously explained the 38.6% that earn the
> 30-point indicator bonus by saying "PAN-OS alerts do carry external
> addresses, which is the one part of the phishing-shaped
> `indicator_risk_score` they can reach". That explanation is wrong, and the
> measurement that disproves it is: across all 718 THREAT records, the source
> and destination addresses contain **2 distinct non-RFC1918 addresses**. The
> traffic is internal — `user-wired -> SERVER` on 515 records, 351 source
> addresses against 21 destinations, 492 of them to one server.
>
> So the bonus is not being earned on PAN-OS addresses. Of the 70 distinct
> public addresses in `ioc_values` on these runs, **2 appear anywhere in the
> PAN-OS record**. The other 68 are scraped from elsewhere in the body:
> `::ffff:10`, the `/8` network bases `154.0.0.0`, `152.0.0.0`, `106.12.0.0`,
> Cloudflare's `1.1.1.1`, and alongside them `http://schemas.microsoft.com/
> win/2004/08/events/event` — an XML namespace — and a certificate revocation
> URL.
>
> That is an indicator-extraction defect, not a PAN-OS one, and it is not
> confined to this source. Estate-wide, the most common value in `ioc_values`
> is **`expertware.net` on 5,619 runs across 138 hosts** — the customer's own
> domain. Then `microsoft.net` (1,067), the XML namespace (350),
> `onenet.be` (194), `oost-vlaanderen.be` (229). Each earns the same 30 points
> as a genuine match.
>
> **This now has its own item**, because it is larger than PAN-OS and it
> directly determines whether Phase 3's cross-case pivots mean anything: an
> indicator present on a third of the estate is the top shared pivot between
> every pair of cases, and links nothing. It is the same defect as a
> discriminator true of every row, measured here on the column that feeds the
> score.

## What the record actually looks like, since the positions are the map

Three things bite, and all three are the delimiter-boundary shape this
codebase keeps hitting:

**Commas inside quoted fields.** 197 of the first 199 records sampled carry
one — `"used-by-malware,has-known-vulnerability,pervasive-use"`,
`"Microsoft Windows 11 Enterprise , 64-bit"`. `split(",")` is wrong on 99% of
real records and does not fail; it returns a different field. The parse goes
through `csv.reader`, which is what the quoting is for. This would have been
the ninth delimiter bug of this shape.

**A variable-width day in the BSD timestamp.** `Sep 17` has one space,
`Sep  8` has two, so `line.split(" ", 4)` puts the relay address inside field
1. Here it is harmless only because the whole header precedes the first comma
and lands inside FUTURE_USE either way. The header is stripped by pattern.

**A JSON envelope, escaped twice.** 733 of 734 records sit in the body as
plain text. One arrives inside `{"rawLogs": ["..."]}`, itself serialised into
a JSON string, so the record's own quoting is escaped twice. Unescaping once
left `povgrp\\did24`, which the account shape guard then quarantined as a
path — the guard was right and the parse was wrong, which is the argument for
having the guard.

### The THREAT positions, read off the data

    1  future_use      12 rule name       25 src port      34 category
    2  receive time    13 source user     26 dst port      35 SEVERITY
    3  serial          14 dest user       30 protocol      36 direction
    4  type (THREAT)   15 application     31 action        59 vsys name
    5  subtype         17 src zone        32 url/filename  60 device name
    8  source address  18 dst zone        33 threat name
    9  dest address

A THREAT record has 131 fields and a GLOBALPROTECT record has 51. A record of
any other width is quarantined rather than read at the positions it happens to
have, because a positional map against the wrong layout returns the wrong
field instead of failing.

### Position 32 is three different things

The field is documented as "URL/Filename" and means something different per
subtype, so the subtype is the only non-guessing way to read it:

    spyware          a hostname            "www.darmika.be"      -> domain
    vulnerability    a URI on the server   showPresenceWSW.cfm   -> url
    wildfire-virus   a filename                                  -> file
    cef:url          a full request        "qvdt3feo.com/"       -> domain

Sniffing the extension instead reads `showPresenceWSW.cfm` as a file, which
puts a web page on the graph as something on an endpoint's disk. The extension
says what served the page, not where it lives. 138 vulnerability records leave
the field empty, which is an absence and is reported as one.

A URI is keyed with the server that served it, because `showPresenceWSW.cfm`
appears on 249 records and the same page name on two servers is two
resources.

## What is modelled, and what is deliberately not

PAN-OS witnesses a session between two addresses, so the subject is an address
and not a process. Nothing in this map claims a parent, a hash or a command
line.

**The firewall is not a node.** It reported 718 of the 734 records, so a node
for it would join every node in every PAN-OS case to a single hub — the
host-wide bucket shape — while telling an analyst nothing the case's source
did not already say. It is the `reported_by` attribute of the session.

**The threat name is not a technique.** `HTTP Unauthorized Brute Force
Attack(40031)` is a Palo Alto signature, and minting an ATT&CK `technique`
node from it would claim a mapping that does not exist. The signature's id is
split from its wording — the id is stable across firmware and the wording is
not — and both ride on the session edge.

**GLOBALPROTECT is quarantined by name.** 16 records against 718, on a
different 51-field layout where position 35 is not a severity. Reading it
there would invent one.

## It is a live feed, so the map earns forward

Measured by testing each body for a PAN-OS record — **not** by reading
`graph_source_type`, which is written when a run is materialised, so a run that
arrived after the last backfill has none and the column reports a live source
as stopped. Reading the column gave 0 runs in the last 7 days; reading the
bodies gives 20.

    span              2026-08-12 .. 2026-10-09
    last 7 days       20 runs
    by week (newest)  40, 25, 31, 42, 15, 44

So 15-45 a week, arriving now. A smaller forward rate than this document first
claimed — that claim measured the whole 859-run unmapped population rather
than PAN-OS — but a live one. The map repairs a true positive's graph, gives
168 alerts a subject they did not have, and takes 224 runs from unrated to
rated.

## Two sources next to this one have stopped, and nothing said so

Found while measuring the above, from the same table:

    windows_eventchannel    9,102 runs   last seen 2026-10-09   762 in 7 days
    appsec-agent            2,685 runs   last seen 2026-09-22     0 in 7 days
    fortigate-firewall-v5   2,533 runs   last seen 2026-09-17     0 in 7 days
    palo_alto_panos           224 runs   last seen 2026-10-09    20 in 7 days

Confirmed from the bodies, not the column: of 857 runs created in the last
seven days, **none** is appsec-agent or Fortigate. Two sources worth 5,218
stored alerts have delivered nothing for 17 and 22 days.

This is the failure shape the pipeline watchdog was written for, one level up:
a source that stops looks exactly like a source that is quiet, and the platform
has no measurement that can tell them apart. It also bears directly on
sequencing — Fortigate was the next field map in line, and it has had no
traffic for three weeks.

Its own item. Not fixed here.
