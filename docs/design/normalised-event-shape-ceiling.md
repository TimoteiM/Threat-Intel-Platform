# The normalised log-event shape: what it bounds, and where the real ceiling is

> **Population: Expertware's own estate.** Measured over 107,668 stored
> normalised events from the 200 most recent collections. See
> [POPULATION.md](../measurements/POPULATION.md).

Written 2026-10-22 to answer whether the template vocabulary is capped by a
normalisation decision made for a different purpose.

**Short answer: no. The shape is not the ceiling.** I said the opposite a
few hours earlier and it was wrong — see the corrections at the end.

---

## 1. What the shape keeps, and what it bounds

`normalise_hit` produces a fixed set of keys **plus an open-ended one**:

| key | source | note |
|---|---|---|
| `key`, `index`, `id` | `_index`, `_id` | **the document's address** — see §2 |
| `timestamp` | `timestamp` \| `@timestamp` | |
| `agent.{id,name,ip}` | `agent.*` | `agent.name` on 100% |
| `manager` | `manager.name` | the tenant pin |
| `rule.{id,level,description,groups,mitre_technique}` | `rule.*` | |
| `event_id` | `data.win.system.eventID` | |
| `channel` | `data.win.system.channel` \| `decoder.name` | |
| `domain` | `targetDomainName` \| `subjectDomainName` | |
| `users` | 94.5% | **capped at 4**, machine accounts sorted last |
| `process.{image,command_line,parent_image}` | Sysmon **and** Security spellings | both, so links work either way |
| **`fields`** | **`data.win.eventdata` then `data.win.system`** | **the open one — 323 distinct names seen** |
| `network.{src_ip,dst_ip}` | `data.srcip`, `data.dstip` | **0% populated on this estate** |
| `decoder`, `location` | | |
| `full_log` | raw event text | truncated |
| `matched_on` | computed | device \| user \| window |

### The bounds, and how often each actually bites

| bound | value | measured effect |
|---|---|---|
| `_MAX_FIELDS` | 40 per event | **19 of 107,668 events hit it — 0.0%** |
| `_MAX_FIELD_CHARS` | 400 per value | truncates long command lines |
| `users[:4]` | 4 | |
| `_SUMMARY_SKIP` | 4 names | `eventID`, `channel`, `computer` are skipped **because they are already their own keys**; only `data.win.system.message` is genuinely dropped, and it restates the fields below it |
| sections read | **`data.win.eventdata` and `data.win.system` only** | a non-Windows source contributes **nothing** to `fields` |

So the only bound that removes information a template might want is the last
one: **this is a Windows-shaped projection.** For Wazuh Windows events it is
close to lossless; for syslog, cloud or Office 365 events, `fields` is empty
and the projection keeps only the envelope.

`fields` is present on **92.7%** of events (76,915 of 83,010 in the first
sample; 107,668 scanned in the second).

---

## 2. Is the raw document still retrievable? Yes — we store its address

We do **not** store the whole vendor document, and we do not need to:
`key` is `"{_index}:{_id}"`, so every normalised event carries the address of
the original. The cluster holds **120 concrete daily indices**
(`wazuh-alerts-4.x-*`), so within retention any event can be re-read in full
by index and id.

`full_log` is also kept, truncated — a partial raw copy for a reader rather
than a machine.

**So nothing is discarded at write in the sense that matters.** The
projection is lossy; the loss is recoverable while the index lives.

---

## 3. What it would take to read a field outside the shape

Three tiers, and only the third is real work:

### Tier 1 — the field is already in `fields`: nothing new

323 distinct names are carried. A template reads one by name from the
`fields` list. **No new call, no new source, no schema change.** This covers
most of what a Windows template would want:

| field | events | what it unblocks |
|---|---|---|
| `image`, `processGuid` | 46,097 | process identity |
| `parentImage`, `parentCommandLine`, `parentProcessGuid` | 711 | **parent/child linking** |
| `commandLine` | 1,351 | |
| `targetUserName` | 10,862 | |
| `logonType` | 7,420 | logon classification |
| `pipeName` | **965** | **named-pipe questions** |
| `hashes` | 1,146 | a combined field — **not** `sha256`/`md5` separately |
| `serviceName` | **207** | service identity |
| `shareName`, `shareLocalPath` | **2**, **1** | effectively nothing |

### Tier 2 — beyond the 40-field cap, or outside `data.win`: re-fetch

Re-read the document by `key` from OpenSearch. One new helper, small. Worth
building only when something needs it: the cap bites on 0.0% of events, so
this tier is nearly empty in practice.

### Tier 3 — a **prevalence** question: a genuinely new call. **This is the ceiling.**

"Where else has this value appeared?" cannot be answered by reading a
retrieved event at all, however complete. `SiemSource` delegates to
`collect_for_alert`, whose only inputs are `entity_host` and `entity_user` —
it answers *"what happened around this alert"*, never *"where else does this
value occur"*.

An arbitrary-field search against the index is a different call and does not
exist. **That is the real cap on the template vocabulary, and it is about the
query interface, not the normalisation.** It is also the one that matters:
every estate-wide question — hash prevalence, service prevalence, pipe
prevalence — needs it, and on Falcon those questions work only because the
alerts API happens to accept a filter on those fields.

---

## 4. Which templates are blocked by what

**None is blocked by the shape.** The guess was `process_tree` and
`pipe_creator`, and those are indeed the two blocked templates — but by a
missing source, not by normalisation:

| template | fields it needs | in the shape? | blocked by |
|---|---|---|---|
| `process_tree` | image, parentImage, commandLine, GUIDs | **all present** | **no source implements it.** `FalconSource` declines it (the alerts API holds detections, not raw process events); `SiemSource` does not offer it, though it could — the parent/child fields are right there |
| `pipe_creator` | pipeName | **present, 965 events** | same — **no source implements it** |
| `source_address_logons` | a routable source address | present as `ipAddress`, **0% routable** | **the data**, not the shape and not the source |
| `host_logons`, `user_sessions`, `user_risk_timeline` | — | — | nothing; `SiemSource` answers them |
| `hash_prevalence`, `ip_seen_anywhere`, `file_name_prevalence` | — | — | nothing; Falcon answers them |
| `host_threat_state`, `host_detections_window` | — | — | nothing |

So `process_tree` and `pipe_creator` are the **cheapest two templates
available**: everything they need is already stored, and what is missing is a
`SiemSource` method that reads `fields` by name and links parent to child.
That is a day's work with no vendor, no credential and no scope.

---

## Corrections to what I said earlier today

**1. "The normalised shape drops all vendor eventdata." Wrong.** It carries
up to 40 eventdata and system fields per event as a name/value list, present
on 92.7% of events with 323 distinct names. I reached the wrong conclusion
because the walker I used to inspect stored events was depth-limited
(`p.count(".") < 2`) and `fields` is a **list of dicts** — so it never
descended into the one key that answers the question. The normaliser's own
docstring says what it does: *"The event's own fields, whatever they are for
this event id… what the enumerated projection could never carry for a type
nobody had listed."* I should have read it.

**2. "Service and share data does not exist." Partly wrong, and I checked
the wrong store.** I searched **alert bodies** and found 0; the log-context
**events** carry `serviceName` on 207 and `shareName` on 2. So service
prevalence has a small real population — 207 events — and share prevalence
effectively none. The conclusion not to build them stands on the population
and on Tier 3, not on the field being absent.

**3. "`source_address_logons` is undeliverable because `network.src_ip` is
absent." Conclusion right, reason wrong.** `network.src_ip` is indeed 0%,
but the Windows field is present: `data.win.eventdata.ipAddress` on 1,354
events. **0% of those are routable** — 485 are `::1` and the rest `fe80::`
link-local. So the template is undeliverable because every value is
loopback or link-local, which is a stronger and more useful statement than
"the field is missing".

All three errors are the same shape: **I checked one key, found nothing, and
reported absence** — when the value was one name over, in a different store,
or present and unusable. The rule that covers it is already written down
(*state the stores an absence was sought in*), and the walker that caused the
first one is a reminder that an instrument's own bounds are part of its
answer.
