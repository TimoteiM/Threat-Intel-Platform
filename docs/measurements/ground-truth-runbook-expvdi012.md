# Runbook: ground-truth exercise on `expvdi012`

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`. `expvdi012` is a QEMU VM in
> `Computers,ExpertWare`, `ExpAdmin` the only human account ever seen on it.
> Nothing here touches a customer estate.

**Consolidated 2026-10-22.** This replaces the version amended across four
messages: Step 0's `sysmon -c` dump, the 1 / 2 / 3 / 3b / 4 order, 3b as a
full item, the representativeness note, and the post-backlog-54 recording
changes in §5. Follow this document only.

Order fixed as **1, 2, 3, 3b, then 4**, ten minutes between each. Item 4
last, because it is the one most likely to draw a real response and response
activity would contaminate the rest. 3b immediately before it, so the
sequence is not "Security log cleared, then dump library loaded".

**Five items.** Item 3 (`version.dll`) is a known-null control and 3b
(`dbghelp.dll`) is the only one that genuinely exercises class 7.

---

## ⚠ Read this before booking the window

**Items 1, 2, 3 and 3b are Sysmon classes (15, 11, 7). `expvdi012` has never
produced a Sysmon alert.** Its entire history is two alerts, both class
**4738** (User account changed, Windows Security), both `ExpAdmin`, both
benign — on 2026-09-20 and 2026-10-20.

That is **not proof Sysmon is absent**: Wazuh only raises an alert when a
rule matches, so a host can run Sysmon for months and produce no Sysmon
alert. But there is no positive evidence either, and if Sysmon is not
installed or not forwarded, items 1–3b cannot produce their classes at all —
and the result would look like a detection gap when it is a telemetry gap. A
third way to waste the window, after #61's missing sensor.

**There is a second, quieter version of the same risk:** Sysmon running and
unfiltered, but the Wazuh agent not subscribed to its channel — perfect local
telemetry that never reaches us. §2f is the gate for that one, and it is the
only Step 0 check with no symptom until the items have already run.

**Step 0 resolves both on the VM.** If Sysmon is not there, stop and tell me:
`expvdi008` is the only other VDI-family host with a Sysmon alert in 90 days
(3 × class 12), and switching is cheaper than guessing.

Across the family: **2 of 16 hosts have any Sysmon alert in 90 days.**

## ⚠ All five items will land in ONE case, and it will probably score high

`SESSION_GAP_HOURS = 6` in `alert_session_service`: a case ends after a
**six-hour** quiet stretch. Ten-minute gaps are far inside that, so the five
items will correlate into **a single case**, in whatever order they run.

Two consequences, and the first is the one the reorder cannot fix:

* **The responder sees one case containing all five.** "Stream written, exe
  dropped, debug library loaded, Security log cleared" inside ~50 minutes is
  a textbook intrusion narrative read end to end, and reordering 3b before 4
  changes the order within that case rather than separating the stories. The
  heads-up to whoever watches the console is therefore doing the real work,
  not the ordering. For genuinely separate cases the items need to be **more
  than six hours apart** — see §7.
* **It will likely be a high-scoring case.** `score_case` gives
  `30 × min(distinct_rules − 1, 3)` for rule agreement, so **four or more
  distinct rules on linked activity earns the full 90** before anything else
  is counted. Measured on this estate: only **1% of closed cases score ≥90**,
  and only 8% reach four distinct rules. This exercise is designed to fire
  four or five distinct rules on one host inside an hour, so expect it to
  produce one of the highest-scoring cases of the month.

Tell the console watcher **that** specifically — not "I'm running tests", but
"expect one case on `expvdi012` scoring 90+, and here is the window". A high
score on our own estate that nobody was warned about is how a measurement
becomes an incident.

Attribution for the comparison is **by timestamp, not by case**, so one
shared case costs the measurement nothing.

---

## 1. What I have already measured — you do not need to collect this

**24-hour baseline for `expvdi012`:**

| window | alerts |
|---|---|
| last 24h | **1** |
| last 7d | 1 |
| last 30d | 1 |
| ever | **2** |

Both are class 4738, account `ExpAdmin`, verdict benign. **This host is
effectively silent**, which is exactly what makes attribution trivial:
anything that arrives during your window is yours.

Record it as `baseline_24h: 1` — you do not need to re-derive it, but record
it, because the reader of the results needs to know attribution was easy
rather than assume it.

---

## 2. Step 0 — pre-flight, on the VM, before anything else

### 2a. Identity and clock

```bat
whoami
hostname
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

**Check `whoami` is not `NT AUTHORITY\SYSTEM`.** If you are SYSTEM, the
user-side templates cannot fire — the collector refuses to query a built-in
principal, returning `skipped`, and you would measure that instead of the
loop. Expect `ExpAdmin` or a domain form of it.

Record it **exactly** as printed: the platform stored it as bare `ExpAdmin`
on the two historical alerts, not `INT\ExpAdmin`. The comparison names
`account` specifically and will not start without it.

### 2b. Is Sysmon running, and is its log live?

```powershell
Get-Service -Name Sysmon*,SysmonDrv -ErrorAction SilentlyContinue |
  Format-Table Name,Status,StartType

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 `
  -ErrorAction SilentlyContinue |
  Format-Table TimeCreated,Id,ProviderName
```

* **Service running and recent events** → proceed.
* **No service, or no such log** → **STOP.** Items 1–3b cannot produce their
  classes. Tell me and we switch host or get Sysmon enabled first.

### 2c. The effective Sysmon config — not just that Sysmon runs

```powershell
sysmon -c
```

If `sysmon -c` is not on the path, the binary is usually
`C:\Windows\Sysmon64.exe -c` or `C:\Windows\Sysmon.exe -c`.

Event 7 (ImageLoad) is very commonly excluded outright for volume, so "class
7 did not alert" could be a **Sysmon config** finding rather than a **Wazuh
rule** finding — and those are different answers with different fixes. Same
for 15, also a common exclusion.

Read the dump and record, per event id, whether it is **enabled** and what
filters apply:

| event | name | needed by | enabled? | filters? |
|---|---|---|---|---|
| **15** | FileCreateStreamHash | item 1 | | |
| **11** | FileCreate | item 2 | | |
| **7** | ImageLoad | items 3 and 3b | | |

Record as `sysmon_events: {"15": true, "11": true, "7": false}` or whatever
it says. **If an event is excluded, the items that need it cannot alert and
that is established before you run them** — a config finding, recorded as
such, not a null to be puzzled over afterwards.

**Also record, but it gates nothing in this round** — these four classes are
the ones that route to `process_tree` and `pipe_creator`, and no item here
produces them (§5). Recording their state now tells us whether a future
round on this host could exercise those templates, for free while you have
the dump open:

| event | name | routes to | enabled? |
|---|---|---|---|
| 1 | ProcessCreate | `process_tree` | |
| 10 | ProcessAccess | `process_tree` | |
| 17 | PipeEvent (created) | `pipe_creator` | |
| 18 | PipeEvent (connected) | `pipe_creator` | |

### 2d. If event 7 is EXCLUDED — stop at three items, do not run 3 or 3b

Record both as untested with the config reason and move on. Do **not** run
them: a null decided by the config before you started is not worth ten
minutes, and running it anyway invites someone later to read it as a rule
finding.

```json
{"item": 3,  "host": "expvdi012", "expected_class": "7",
 "status": "untested",
 "reason": "sysmon -c shows event 7 (ImageLoad) excluded on this host"},
{"item": "3b", "host": "expvdi012", "expected_class": "7",
 "status": "untested",
 "reason": "sysmon -c shows event 7 (ImageLoad) excluded on this host"}
```

Then the order becomes **1, 2, 4** and class 7 has no coverage this round.

**And there is a better host if that happens.** Class 7 is enabled
*somewhere* — the corpus holds **128 class-7 runs across 16 hosts** — so a
host that has actually produced one is strictly better evidence than a config
dump. Measured 2026-10-22, the quiet ones that have:

| host | alerts 30d | class-7 runs | sensor last seen | managed |
|---|---|---|---|---|
| **`exp-dfw2p34`** | 2 | 1 | **2026-10-22 05:25** | yes |
| **`exp-6chwtg3`** | 2 | 1 | **2026-10-22 05:38** | yes |
| `exp-3lwk334` | 2 | 2 | 2026-10-21 14:46 | yes |
| `exp-9j7yz93` | 2 | 1 | 2026-10-21 14:59 | yes |
| `exp-jz6dy24` | 4 | 1 | 2026-10-21 14:42 | yes |

All five are managed with a fresh sensor, as quiet as `expvdi012`, and each
has produced a class-7 alert. **`exp-dfw2p34`** or **`exp-6chwtg3`** on
recency. Two caveats before switching:

* **They are end-user laptops by chassis, not admin VMs** — the thing you
  wanted to avoid, and it brings item 4 back into question. Clearing the
  Security log on someone's laptop is a different proposition from clearing
  it on an `ExpAdmin` VM.
* **Our data cannot tell you whose laptop.** `entity_user` is null on every
  alert these five have ever produced. Do not assume unassigned.

Excluded deliberately: `exp-4lwk334` (70 class-7 runs but **2,253 alerts in
30 days** — attribution would be guesswork), `windows-test-device` and
`asiem-victim` (no Falcon sensor), `exp-7q6f163` (2 class-7 runs, zero alerts
in 30 days, 12-day-stale sensor).

For contrast, the other two Sysmon items are far better attested: **class 15
on 37 hosts (202 runs)** and **class 11 on 26 hosts (104 runs)**, against
class 7's 16. Items 1 and 2 are the safe ones.

**If we switch to `expvdi008`, run exactly the same check there.** Its three
Sysmon alerts are all **class 12** (RegistryEvent), which proves Sysmon is
installed and forwarding and says **nothing** about 15, 11 or 7.

### 2e. Is the Wazuh agent running and connected?

```powershell
Get-Service -Name Wazuh*,"OssecSvc" -ErrorAction SilentlyContinue |
  Format-Table Name,Status,StartType
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 5 `
  -ErrorAction SilentlyContinue
```

Expect a running service and no recent connection errors. The agent is proven
to reach us (the 2026-10-20 alert), so this is confirmation, not discovery.

### 2f. **Is the agent actually READING the Sysmon channel?** — the gate 2b–2d cannot see

2b proves Sysmon runs. 2c proves the events are not filtered out. **Neither
proves the forwarder is subscribed to that channel.** Sysmon can be running,
logging locally, with recent events and an open config, and Wazuh simply not
configured to collect `Microsoft-Windows-Sysmon/Operational` — in which case
items 1–3b produce perfect local telemetry that never reaches the platform,
and the result reads as a detection gap when it is a collection gap. The
fourth way to waste the window, and the only one with no symptom until forty
minutes in.

```powershell
# 1. The local config — the block that subscribes to the channel.
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" `
  -Pattern "Sysmon" -Context 3,3

# 2. **Centrally pushed config, if the local file has nothing.** Wazuh
#    commonly ships <localfile> blocks from the manager, so an absent block
#    in ossec.conf is NOT yet an answer.
Get-ChildItem "C:\Program Files (x86)\ossec-agent\shared" -ErrorAction SilentlyContinue |
  Format-Table Name,LastWriteTime
Select-String -Path "C:\Program Files (x86)\ossec-agent\shared\*.conf" `
  -Pattern "Sysmon" -Context 3,3 -ErrorAction SilentlyContinue
```

Expect a `<localfile>` block of this shape in one of the two:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Then the positive control, which beats both config reads.** A config
mentioning the channel is a declaration; this is the agent saying it did it:

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.log" `
  -Pattern "Sysmon" | Select-Object -Last 10
```

At startup the agent logs a line naming each channel it begins monitoring —
`Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'` or similar. If
that line is present from the current service start, the forwarder is looking
and §2f is settled affirmatively rather than inferred from XML.

| what you find | meaning | do |
|---|---|---|
| block present **and** the log line present | collecting | **proceed** |
| block present, no log line | configured but possibly not reloaded since | restart the agent service, re-check for the line |
| **no block in either file** | **the channel is not collected** | **STOP.** Items 1–3b cannot reach the platform. Tell me — this is a one-line config fix, or we switch to a host that has produced a Sysmon alert |
| `shared` folder absent and no local block | same as above | STOP |

Record as `sysmon_channel_collected: true` / `false`, and paste the
`<localfile>` block or its absence. **If this is false, nothing in items 1–3b
is worth running** — and unlike the event-7 case there is no partial fallback,
because all four Sysmon items depend on it.

---

## 3. The five items

Take a UTC timestamp **immediately before and immediately after** each
command block, from the VM itself:

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

### Item 1 — class 15, alternate data stream

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c echo groundtruth-item1-%RANDOM% > %TEMP%\gt1.txt:marker
cmd /c more < %TEMP%\gt1.txt:marker
cmd /c dir /r %TEMP%\gt1.txt

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

Writes a stream containing a literal string, reads it back, lists it. `dir /r`
shows the stream so you can paste proof it existed. Nothing is destroyed.

**Record the expanded `%RANDOM%` value** — the literal string is what lets
the comparison find the artefact.

### Item 2 — class 11, executable dropped

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c copy /y C:\Windows\System32\certutil.exe %TEMP%\gt2.exe
cmd /c dir %TEMP%\gt2.exe
cmd /c certutil -hashfile %TEMP%\gt2.exe SHA256

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

**Do not run `gt2.exe`.** Copying a signed OS binary into `%TEMP%` is the
whole item; executing `certutil` from a temp path is a different and much
noisier thing. The `-hashfile` line hashes it, which is a read — see §5 for
why the hash is now part of the record.

### Item 3 — class 7, image loaded (known-null control)

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c rundll32.exe version.dll,#1
cmd /c certutil -hashfile C:\Windows\System32\version.dll SHA256

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

`rundll32` loads `version.dll`, fails to find ordinal 1, and exits. The
**load** is the event. Expect an error dialog or a silent exit — both fine.

**This one is expected to produce no alert.** The class-7 rules in our corpus
are "debug/dump library loaded by a suspicious process" and
"credential-related library loaded by…", and `version.dll` is neither. If it
does not alert, that is a **detection-coverage** result and the correct
outcome to record — not a miss.

### Item 3b — class 7, debug library loaded (the real test)

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c rundll32.exe dbghelp.dll,#1
cmd /c certutil -hashfile C:\Windows\System32\dbghelp.dll SHA256

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

The same mechanism as item 3 with a library that **matches the rule**:
`dbghelp.dll` is the debug/dump library the class-7 corpus rule names. It is
a signed Microsoft DLL, loaded and discarded, and **nothing is dumped** — but
it is the shape a responder reads as memory-dump preparation, which is why it
sits immediately before item 4 rather than anywhere earlier.

**This is the only item that genuinely exercises class 7.** Item 3 establishes
that `version.dll` produces nothing; 3b is the test. Read the two together
via the table in §6.

### Item 4 — class 1102, Security log cleared (LAST)

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

wevtutil cl Security

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

Needs administrator. Clears that host's local Security log; everything
already forwarded is unaffected. **This is the item most likely to draw a
real response** — make sure whoever watches the console knows the window.

### Cleanup — after item 4 and its confirmation, not before

```bat
cmd /c del /f %TEMP%\gt1.txt
cmd /c del /f %TEMP%\gt2.exe
```

---

## 4. The ten-minute gaps and the confirmation point

The rhythm is: **item → timestamp pair → confirmation → wait ten minutes →
next item.**

**Do not batch the items.** The gap plus a confirmation is what makes each
alert attributable to one item by timestamp. The items will share a case
regardless (six-hour session gap), so timestamps are the only attribution you
have.

**None of the confirmation can be run from the VM.** It queries the platform
database, which that VM has no access to and should not have. Either paste me
the `started_utc` after each item and I run it, or run it yourself from
somewhere with repo and Docker access.

| after | run | expect |
|---|---|---|
| item 1 | `--since <1.started_utc> --expect-class 15` | ARRIVED class 15 |
| item 2 | `--since <2.started_utc> --expect-class 11` | ARRIVED class 11 |
| item 3 | `--since <3.started_utc> --expect-class 7` | **NOTHING (settled)** — the known-null |
| item 3b | `--since <3b.started_utc> --expect-class 7` | ARRIVED class 7 **if** event 7 is enabled |
| item 4 | `--since <4.started_utc> --expect-class 1102` | ARRIVED class 1102 |

```
docker compose exec -T -e PYTHONPATH=/app worker \
  python /app/scripts/check_item_alerted.py \
  --host expvdi012 --since 2026-10-22T09:00:12Z --expect-class 15
```

Three answers, and the middle one matters:

| it says | meaning | do |
|---|---|---|
| `ARRIVED` | an alert exists, with class, account, verdict and log-context status | proceed |
| `NOTHING YET` | inside the 20-minute settle window | **wait and re-run** — ingest and analysis are not instant |
| `NOTHING (settled)` | past 20 minutes with nothing | record no-alert for that item and proceed |

Exercised in both directions before writing this, against a window with a
known alert and a window with none.

**The ten minutes start when the confirmation returns, not when the command
finished.** If a confirmation says `NOTHING YET` you are waiting anyway, so
the gap absorbs it.

---

## 5. What changes now that `process_tree` and `pipe_creator` exist

Backlog 54 landed today. **It changes what you record, but it adds no new
item and no process or pipe selector to capture.** The reasoning, because the
conclusion is the opposite of what you'd expect:

### The two new templates will not run in this window at all

The five items produce classes **15, 11, 7 and 1102**. Their playbook rows,
read from `PLAYBOOK` rather than assumed:

| class | templates that will actually run |
|---|---|
| 15 | `hash_prevalence`, `ip_seen_anywhere`, `file_name_prevalence`, `host_detections_window`, `user_risk_timeline`, `host_threat_state` |
| 11 | the same |
| 7 | the same |
| 1102 | the same, minus the class row's own entry |

**`process_tree` and `pipe_creator` are on classes 10, 17, 18, 1 and 29 —
none of which any item produces.** So capturing a process path or a pipe name
would be capturing ground truth for a template that is never reached.

Record them as **not exercised by this round**, with the reason, so their
absence is not later read as a failure of the new code:

```json
"templates_not_exercised": {
  "process_tree": "no item produces class 1, 10 or 29",
  "pipe_creator": "no item produces class 17 or 18"
}
```

### Why not add a sixth item to cover them

I looked, and I am recommending against it:

* **`expvdi012` has produced zero class-10/17/18/1/29 alerts, ever.**
* Estate-wide, class 17/18 comes from **3 hosts only**, and the rules that
  fire are `Suspicious legacy/anonymous named-pipe pattern`, `Cobalt Strike
  malleable-pipe candidate: \MsFteWds` and `Unusually frequent monitored
  named-pipe activity`. A *benign* named pipe matches none of them — matching
  them means deliberately creating a C2-indicator pipe name. In a window that
  already ends with a cleared Security log, inside one case, that moves the
  narrative from "textbook intrusion" to "credible active C2". Not worth it
  for a template test.
* Class 10's rules are all **`Shellcode/BOF-style process access`** and
  `Repeated injection-capable access` — process-injection shaped, which is
  outside the benign-activity boundary you set.

**They do not need the window.** 1,526 class-10 and 2,221 class-17/18 runs
already exist with log context collected, and the replay is read-only. I can
exercise both templates against that existing corpus offline, at a sample
size three orders of magnitude larger than one synthetic event, and it costs
nothing and risks nothing. That is queued for after the window.

### What you DO need to record that the earlier runbook didn't ask for

**The SHA256 and exact filename of every artefact.** This is the real gap,
and it is about the templates that *do* run:

* `hash_prevalence` is on **all four** of this round's classes, and it is the
  only one of them whose selector is a value **extracted from the alert
  body** rather than taken from the host. Everything else keys on `host` or
  `user`, which we already know.
* So if it comes back `empty`, there are two very different causes and the
  protocol currently cannot distinguish them: **extraction missed the hash**,
  or **the hash is genuinely unseen in the estate**. With the true SHA256 in
  the record, the comparison can tell you which. Without it, "hash_prevalence:
  empty" is unreadable.

That is why items 2, 3 and 3b each carry a `certutil -hashfile` line above.
For item 1 the hashed object is the *stream*, which Sysmon computes itself —
record the `%RANDOM%` literal instead and we match on that.

**One known skip to expect, so it isn't mistaken for a defect.**
`file_name_prevalence` is in `INDICATOR_LED` and will run on all five items —
and will skip every time with *"no filename on this alert"*, because the
replay harness produces no `filename` selector. Confirmed on the dry run.
Record it as a known harness gap, not a result. It is a candidate for the
work after the window.

---

## 6. What to record

Append one object per item, in this exact shape:

```json
{"items": [
 {"item": 1,
  "host": "expvdi012",
  "account": "<exactly what whoami printed>",
  "command": "cmd /c echo groundtruth-item1-1234 > %TEMP%\\gt1.txt:marker",
  "artefact_path": "%TEMP%\\gt1.txt:marker",
  "artefact_literal": "groundtruth-item1-1234",
  "artefact_sha256": null,
  "started_utc": "2026-10-22T09:00:12Z",
  "finished_utc": "2026-10-22T09:00:14Z",
  "expected_class": "15"},
 {"item": 2, "...": "...", "expected_class": "11",
  "artefact_path": "%TEMP%\\gt2.exe",
  "artefact_sha256": "<certutil output>"},
 {"item": 3, "...": "...", "expected_class": "7",
  "artefact_path": "C:\\Windows\\System32\\version.dll",
  "artefact_sha256": "<certutil output>",
  "note": "version.dll — known-null control"},
 {"item": "3b", "...": "...", "expected_class": "7",
  "artefact_path": "C:\\Windows\\System32\\dbghelp.dll",
  "artefact_sha256": "<certutil output>",
  "note": "dbghelp.dll — the real class-7 test"},
 {"item": 4, "...": "...", "expected_class": "1102",
  "artefact_path": null, "artefact_sha256": null}
 ],
 "baseline_24h": 1,
 "sysmon_present": true,
 "sysmon_channel_collected": true,
 "sysmon_events": {"15": true, "11": true, "7": true},
 "sysmon_events_recorded_only": {"1": null, "10": null, "17": null, "18": null},
 "templates_not_exercised": {
   "process_tree": "no item produces class 1, 10 or 29",
   "pipe_creator": "no item produces class 17 or 18"
 },
 "known_harness_gap": "file_name_prevalence skips on every item — no filename selector",
 "notes": "anything that surprised you"
}
```

`command` **verbatim**. Timestamps to the second. The comparison refuses to
start if any of the seven original fields is missing, and names `account`
specifically.

Keep the file at `~/evidence/ground-truth-2026-10-xx/protocol.json`,
`chmod 600`, directory `700`, with an `INVENTORY.md` entry naming the
question it answers and its deletion trigger.

### Reading the two class-7 results together

The whole reason 3 and 3b are both run. Four outcomes, four different
findings:

| item 3 (`version.dll`) | item 3b (`dbghelp.dll`) | `sysmon -c` event 7 | what it means |
|---|---|---|---|
| nothing | **ARRIVED** | enabled | **the expected result.** The rule is specific to debug/dump libraries and works |
| nothing | nothing | **enabled** | a **Wazuh rule** finding: event 7 is collected and no rule matched either load |
| nothing | nothing | **excluded** | a **Sysmon config** finding, settled before you started — neither item could ever have alerted |
| **ARRIVED** | ARRIVED | enabled | the rule is broader than the corpus rule names suggest; worth knowing |

Record which row you are in. "Class 7 did not alert" on its own is not a
finding — it is three possible findings that need different fixes.

---

## 7. Representativeness — read before quoting any result

This exercise produces **one rich case**: four or five distinct rules on one
host inside an hour, which on this estate is the **1% tail**. Measured over
the 400 most recent closed `c00` cases:

* **4 (1.0%)** scored ≥90
* **32 (8.0%)** carried four or more distinct rules
* **282 (70.5%)** carried a **single** distinct rule

So the common case is the sparse one, and this round says nothing about it. A
loop that gathers well on five linked detections may gather nothing useful on
one isolated alert, and these five items cannot tell the difference.

The second round, if this one works:

* **one item per case**, which means gaps **wider than six hours**
  (`SESSION_GAP_HOURS = 6`) — spread across days, not an afternoon;
* prefer items 1 and 2 (classes 15 and 11), attested on 37 and 26 hosts, so
  they can run on several different quiet hosts rather than repeatedly on one;
* the comparison then has single-rule cases to read, which is the population
  70.5% of real closed cases live in.

The comparison tool prints this caveat with its results, so the figure cannot
be quoted without it.

---

## 8. Things that need you somewhere other than the VM

1. **The confirmation check between items** — platform database access. Me,
   or your own workstation with the repo.
2. **The replay and the comparison, afterwards** — both must run **inside the
   container**, because the OpenSearch CA is a container mount. From the host
   venv the replay exits 2 rather than reporting every SIEM query as a source
   failure.
3. **Agreeing the window with whoever watches the console** — before item 4
   especially, and before 3b.
4. **The EDR coverage note** (`docs/outbound/falcon-edr-coverage-gap.md`) —
   unrelated to this exercise and still needs a human to send: `dc`,
   `win11-mssql01` and `win10-mssql02` have no sensor.

---

## 9. Afterwards — what to paste back

* the **five** timestamp pairs
* the exact commands, with `%RANDOM%` expanded
* `whoami` output, verbatim
* the `sysmon -c` table for 15 / 11 / 7, and the record-only table for
  1 / 10 / 17 / 18
* the **`<localfile>` block** for `Microsoft-Windows-Sysmon/Operational`, or
  its absence from both `ossec.conf` and `shared\*.conf`, plus the
  `Analyzing event log` line from `ossec.log` (§2f)
* the **SHA256s** from items 2, 3 and 3b
* the Step 0 service and agent results
* anything that surprised you

I will run the replay on the items that alerted and the comparison against
`protocol.json`, and report **five columns per item with no aggregate** —
five exercises is not a rate either.
