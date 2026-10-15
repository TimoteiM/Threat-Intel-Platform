# Falcon: what it answers, demonstrated by hand

**Everything here was run against tenant `c00`'s real credential on
2026-10-15**, `https://api.eu-1.crowdstrike.com`. Nothing is quoted from a
code comment. This replaces an earlier version of this file that was written
from the module's own notes; three of its conclusions were wrong and are
corrected below.

**Falcon has real data: 182 managed devices, 2,048 alerts.** It was not
producing nothing because it has nothing.

## 1. The positive control

The Alerts API returns HTTP 200 with zero resources for field names that do
not exist, so an empty result and a typo are the same response. Before any
figure below means anything:

| probe | result |
|---|---|
| `GET /devices/queries/devices/v1` unfiltered | 200, **182 total** |
| `GET /alerts/queries/alerts/v2` unfiltered | 200, **2,048 total** |

Then the field-level control — filter on a value *read back* from a real
record, which is the only version that tests the field name:

| probe | result | |
|---|---|---|
| `hostname:'DESKTOP-AIIJNU8'` (read back from the device record) | 200, **1 row**, same device id | control passes |
| `hostname:'definitely-not-a-host-xyz'` | 200, 0 rows | a true empty |
| `invented_field_xyz:'DESKTOP-AIIJNU8'` | **400 "Invalid filter expression supplied"** | Devices *validates* |

**So the hazard is Alerts-only.** On Devices an empty result is interpretable,
because an invented field is rejected. On Alerts it is not:

| alert filter, on values read back from a real alert | result |
|---|---|
| `device.hostname:'EXP-6FSKJR3'` | 200, 3 rows |
| `hostname:'EXP-6FSKJR3'` | 200, **0 rows** |
| `sha256:'<read back>'` | 200, 17 rows |
| `behaviors.sha256:'<the same value>'` | 200, **0 rows** |
| `filename:'Install_Waves_Central.exe'` | 200, 1 row |
| `invented_field_xyz:'…'` | 200, **0 rows** |

## 2. The live defect this found

```python
ALERT_FILTER_FIELDS = {          # app/integrations/falcon_client.py
    "domain": "behaviors.domain",
    "url":    "behaviors.domain",
    "ip":     "behaviors.ioc_value",
    "hash":   "behaviors.sha256",
}
```

**The alert record has no `behaviors` key at all.** The Alerts v2 record is
flat — 73 fields including `sha256`, `md5`, `sha1`, `filename`, `device`,
`tactic`, `technique`. Every field in that map is invented, and every one
returns 200 with zero resources.

So **every hash lookup this collector has ever performed returned "the EDR has
nothing", and the hash field works perfectly under its real name**: the same
value returns 17 rows as `sha256` and 0 as `behaviors.sha256`. This is the
absence-as-answer shape, except we wrote it ourselves, and the module's own
docstring predicted it two paragraphs above the broken map.

Field population across a 200-alert sample, which is how the real names were
found:

| field | populated |
|---|---|
| `sha256`, `filename`, `data_domains`, `indicator_id`, `source_ips`, `source_hosts` | 193/200 |
| `md5` | 188/200 |
| `sha1` | 186/200 |
| `ioc_context` | 12/200 |
| `behaviors` | **0/200** |

## 3. What Falcon can and cannot answer

| question | endpoint | field | works? | an empty result means |
|---|---|---|---|---|
| is this host managed? | `/devices/queries/devices/v1` | `hostname` | **yes** | `never_observed` — the field validates, so empty is a real negative |
| OS, build, sensor version, policy, first/last seen | `/devices/entities/devices/v2` | — | **yes** | n/a, 62 fields returned |
| detections on this host | `/alerts/queries/alerts/v2` | `device.hostname` | **yes** | `never_observed`, *once the control passes* |
| has the EDR seen this file hash? | `/alerts/queries/alerts/v2` | `sha256` / `md5` / `sha1` | **yes** | `never_observed`, control-gated |
| detections by **domain** | — | — | **no field exists** | `no_field_map` — not an absence of contact |
| detections by **IP** | `/alerts/queries/alerts/v2` | `source_ips` | **no, in practice** | `no_field_map` for a remote address |
| is this indicator known-bad? | `/intel/*`, `/iocs/*` | — | **no — 403** | `check_failed` (scope), never "clean" |
| sandbox report for an attachment | `/falconx/*` | — | **no — 403** | `check_failed` (scope) |

### Domain search does not exist

Every domain-shaped filter returns 200/0: `behaviors.domain`, `domain`,
`data_domains`, `ioc_context.domain`, `ioc_value`, `behaviors.ioc_value`.

`data_domains` is the trap — the name promises domains and the value is
`['Endpoint']`, a data *classification*. `ioc_context` exists on 12 of 200
alerts and its `ioc_value` holds hashes and file paths
(`ioc_type: 'hash_sha256'`), not names.

### IP search is structurally wrong, not merely unsupported

`source_ips` is populated — with `['10.66.66.12']`. These are internal source
addresses. An email's sender IP is a remote public address and will never
appear there, and the Devices API's `local_ip` is the device's own LAN
address. Both accept a valid IP and return a true empty for a reason that has
nothing to do with the estate.

### The scope wall, re-measured today

`403 access denied, scope not permitted` on `/intel/queries/indicators/v1`,
`/iocs/queries/indicators/v1`, `/intel/combined/indicators/v1`,
`/intel/queries/actors/v1`, `/intel/queries/reports/v1`,
`/falconx/queries/reports/v1`, `/scanner/queries/scans/v1`.

**Falcon cannot be asked whether an indicator is known-bad.** It can only be
asked what this estate has done and seen. That is a capability absence of the
credential, not of the product, and it is the single fact that decides where
the panel goes.

(Incidentally the token's `scopes` comes back `[]`, which is our parser
storing `()` when Falcon says nothing — not Falcon reporting no scopes. Scope
coverage has to be inferred from endpoint behaviour.)

## 4. The worked example

A host named in a recent tenant alert, asked of Falcon by hand:

```
=== EXP-22MY264 ===
  Wazuh alerts, 7d      : 59,716
  Falcon managed        : yes
  platform / os         : Windows / Windows 11 build 26200
  sensor version        : 7.40.21309.0
  sensor status         : normal, reduced_functionality = no
  first / last seen     : 2025-08-20T08:13:22Z / 2026-10-15T09:42:59Z
  type / site / domain  : Workstation / EXPERTWARE / int.expertware.net
  prevention policy     : applied = True
```

Detections, last 30 days — and the number that must not be the headline:

| measure | value |
|---|---|
| raw alert rows | **1,432** |
| distinct `aggregate_id` | 546 |
| distinct (name, filename) | **12** |
| `status = closed` | 996 of 1,000 sampled |
| `status = new` | **4** |

| detection | file | rows |
|---|---|---|
| TestingActivity | wsl.exe | 936 |
| WSLProcessExecution | wsl.exe | 37 |
| CredentialsInWindowsRegistryAccessedViaAttackerTooling | wsl.exe | 10 |
| CredDumpTool | git.exe | 6 |
| PShellExploitKit2 / PShellKerberroasting | powershell.exe | 2 + 2 |

"1,432 detections" would read as a compromised machine. It is one developer
running WSL, 996 of them already closed, and 56 rows where prevention actually
blocked a process. **The panel's headline must be distinct and open, not
counted and raw** — otherwise it is a ranking number read as a verdict, which
is a mistake this platform has already made once.

## 5. Coverage: the finding nobody asked for

Joining Wazuh `agent.name` (179 hosts in alerts over 7 days) to Falcon
`hostname` (182 device records, **175 distinct hostnames** — the difference is
5 hostnames re-enrolled, not 7 missing names; see the correction in §8):

| | |
|---|---|
| exact match, case-insensitive | **160 / 179 (89.4%)** |
| matched only after dropping a DNS suffix | 0 |
| no match | **19** |
| Falcon hosts absent from 7d Wazuh alerts | 15 |

The join is good enough to build on, which I did not expect — I flagged it as
needing measurement first, and the measurement says a plain case-insensitive
hostname match is sufficient. No suffix normalisation is needed on this estate.

The 19 unmanaged hosts, by Wazuh alert volume:

| host | alerts / 7d |
|---|---|
| `wm-c00.siembiot.int` | 122,878,197 |
| `DC` | 753,898 |
| `EXP-044036414857` | 140,583 |
| `EXP-3BRRPB4` | 83,300 |
| `EXPM365Analytics401` | 59,521 |
| `WIN11-MSSQL01` | 33,485 |
| `EXP-OPS-46807` | 33,176 |
| `Windows-Test-Device` | 32,848 |
| `ASIEM-VICTIM` | 28,330 |
| `WIN10-MSSQL02` | 27,138 |
| `CPC-alexa-GTFXM` | 24,458 |
| `expgrafana001.int.expertware.net` | 23,905 |
| `EXP-OPS-58255` | 17,900 |
| `STANDALONE02` | 15,587 |
| `SERVER01` | 11,672 |
| `EXP-OPS-81958` | 5,097 |
| `LABORATORVM001` | 4,459 |
| `EXP-OPS-66927` | 4,339 |
| `dns1.expertware.net` | 1,814 |

`wm-c00.siembiot.int` is the Wazuh manager itself and should not be expected
in an EDR. The rest are a genuine EDR coverage gap: a domain controller, two
SQL servers, a Grafana host, a DNS server. **A domain controller generating
753,898 alerts a week with no EDR sensor is a finding on its own**, and it
needed no new code — only the join.

This is also the one number that is *not* a per-alert question, so it belongs
on a coverage view rather than in the panel.

## 6. Proposed panel: on the alert surface

A tenant alert names a host. That is the key Falcon's device endpoint takes,
it validates, and 89.4% of them resolve. One query with a real answer.

**Placement:** the alert / case detail view, beside the existing enrichment.
Not the email investigation — an email has no host, and everything Falcon
could be asked about an email's indicators is either a 403 or a field that
does not exist. The one exception is attachment hashes, which is item 4 below.

**Section A — EDR coverage for this host.** One `devices` query on
`hostname`, case-insensitive.

- Managed: yes → sensor version, OS and build, `status`,
  `reduced_functionality_mode`, prevention policy applied, first/last seen.
- Managed: **no** → this is the finding, not an empty panel. "Falcon has no
  sensor on this host" is a real negative here, because the Devices API
  validates the field and the control proved the filter works. Render it as a
  coverage gap with the host's Wazuh alert volume beside it.
- `last_seen` older than ~7 days gets its own line: a sensor that has not
  reported is not a sensor that saw nothing. (Measured distribution: 153 of
  182 devices within a day, 10 within a week, 10 within a month, 9 beyond 31
  days.)

**Section B — detections on this host.** One `alerts` query,
`device.hostname:'<host>'+created_timestamp:>'<30d>'`.

- Headline: **distinct open detections**, grouped by detection name, each with
  a row count and the most recent timestamp. Never the raw row total.
- Each group: name, tactic, technique, file, user, disposition
  (`Prevention, process was blocked` vs `Detection, standard detection`
  matters more than severity here), status.
- Closed detections collapsed behind a count. 996 of 1,000 were closed; a
  panel that shows them all shows nothing.
- Empty → `never_observed`, **only if the control passed this process**;
  otherwise `check_failed` naming the field.

**Section C — the control's own state.** One line, not hidden: when the
field-level control last passed. The whole panel's negatives are worthless
without it, so it is not a debug detail.

**Section D (email only, separate work) — attachment hashes.** `sha256`,
`md5` or `sha1` against the alerts corpus. This is the *only* Falcon question
an email can ask, and it now works because the field name is corrected. Not
domains, not the sender IP.

## 7. Order of work

1. **Fix `ALERT_FILTER_FIELDS`** — `behaviors.sha256` → `sha256`, and remove
   the `domain`/`url`/`ip` entries entirely in favour of a named
   `no_field_map` absence, because there is no field to map them to. This is
   a live false negative in shipped code and the smallest change here.
2. **The field-level positive control**, in `falcon_client`, cached per
   process: fetch one alert, read back the value at the field the query will
   use, re-filter on it, require a hit. Failure makes every Falcon negative
   `check_failed`. Nothing that renders a Falcon negative should ship first.
3. **Section A + B** on the alert view — the panel above.
4. **The coverage view** — 19 unmanaged hosts, on a plain case-insensitive
   hostname join, which the measurement says is sufficient.
5. **Section D** on email, last.

## 8. Still needing a fact, not a decision

- ~~Falcon's alert retention is unmeasured~~ — **measured 2026-10-15.** The
  oldest alert this subscription returns is **2026-07-17T06:49:10Z, exactly 90
  days** before the measurement, and asking `created_timestamp > '2024-01-01'`
  returns the same 2,048 total as `> '2026-06-01'`, so the API is not clamping
  a wider request silently. Community sources agree on 90 days for detections
  and alerts independent of subscription tier (raw telemetry is the part that
  varies, commonly 7 days); no official CrowdStrike page said so in the search
  results, so the measurement is the authority and 90 is only a sanity bound.

  It is re-derived per request (cached an hour) rather than hardcoded, because
  it is a rolling window and a tier change could put it under 30 days. The
  panel now reports the **covered** window, not the requested one, bounded by
  the later of: what was asked, retention, and **this host's sensor
  enrolment** — 18 of 182 devices were enrolled inside 30 days. Verified live:
  `EXP-26ML4Y2` reports "Covers 4 days, not 30: this host's sensor was
  enrolled 2026-10-11". For a re-enrolled hostname the *earliest* enrolment
  binds, since detections from the retired enrolment still carry the hostname.

- Whether this API client can be granted the **intel** scope. If yes,
  "what does CrowdStrike know about this indicator" becomes answerable and
  the email panel grows a real question. If no, the 403 should be recorded
  once as a capability absence rather than retried per investigation.
- ~~The 7 Falcon device records with no hostname~~ — **corrected 2026-10-15.**
  There are none. 182 records collapse to 175 *distinct lowercased* hostnames,
  so the difference was 7 duplicate hostnames, not 7 absent ones. The cause is
  sensor re-enrolment: 5 hostnames carry 2-3 records each, and in every case
  the retired record's last check-in hands straight off to the next record's
  first check-in. Those hosts are covered.

  The error mattered, because it was load-bearing for code: `lookup_host`
  took `ids[0]` from the device query, which is an arbitrary choice between
  enrolments. Picking a retired one reports a host that checked in this
  morning as a stale sensor — and the stale warning then discredits a
  detection list that was complete. It now sorts by `last_seen` and reports
  the rest as `superseded_devices`.
- Whether `DC`, `WIN11-MSSQL01`, `WIN10-MSSQL02`, `SERVER01` and
  `dns1.expertware.net` are deliberately out of EDR scope or an oversight.
  That is a question for whoever owns the Falcon licence count.
