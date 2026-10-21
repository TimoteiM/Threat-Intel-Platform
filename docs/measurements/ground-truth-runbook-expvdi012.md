# Runbook: ground-truth exercise on `expvdi012`

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`. `expvdi012` is a QEMU VM in
> `Computers,ExpertWare`, `ExpAdmin` the only human account ever seen on it.
> Nothing here touches a customer estate.

Order fixed as **1, 2, 3, 3b, then 4**, ten minutes between each. Item 4
last, because it is the one most likely to draw a real response and response
activity would contaminate the rest. 3b immediately before it, so the
sequence is not "Security log cleared, then dump library loaded".

**Five items**, since 3b is now a real item rather than an option: item 3
(`version.dll`) is a known-null and 3b (`dbghelp.dll`) is the only one that
genuinely exercises class 7.

---

## ⚠ Read this before booking the window

**Items 1, 2 and 3 are Sysmon classes (15, 11, 7). `expvdi012` has never
produced a Sysmon alert.** Its entire history is two alerts, both class
**4738** (User account changed, Windows Security), both `ExpAdmin`, both
benign — on 2026-09-20 and 2026-10-20.

That is **not proof Sysmon is absent**: Wazuh only raises an alert when a
rule matches, so a host can run Sysmon for months and produce no Sysmon
alert. But there is no positive evidence either, and if Sysmon is not
installed or not forwarded, items 1–3 cannot produce their classes at all —
and the result would look like a detection gap when it is a telemetry gap.
A third way to waste the window, after #61's missing sensor.

**Step 0 resolves it on the VM in two commands.** If Sysmon is not there,
stop and tell me: `expvdi008` is the only VDI-family host with a Sysmon
alert in 90 days (3 × class 12), and switching is cheaper than guessing.

Across the family: **2 of 16 hosts have any Sysmon alert in 90 days.**

---

## ⚠ All five items will land in ONE case, and it will probably score high

`SESSION_GAP_HOURS = 6` in `alert_session_service`: a case ends after a
**six-hour** quiet stretch. Ten-minute gaps are far inside that, so the five
items will correlate into **a single case**, in whatever order they run.

Two consequences, and the first is the one your reorder cannot fix:

* **The responder sees one case containing all five.** "Stream written, exe
  dropped, debug library loaded, Security log cleared" inside ~50 minutes is
  a textbook intrusion narrative read end to end, and reordering 3b before 4
  changes the order within that case rather than separating the stories. The
  heads-up to whoever watches the console is therefore doing the real work,
  not the ordering. If you want genuinely separate cases, the items need to
  be **more than six hours apart**, which means spreading them across a day
  or two.
* **It will likely be a high-scoring case.** `score_case` gives
  `30 × min(distinct_rules − 1, 3)` for rule agreement, so **four or more
  distinct rules on linked activity earns the full 90** before anything else
  is counted. Measured on this estate: only **1% of closed cases score ≥90**,
  and only 8% reach four distinct rules. This exercise is designed to fire
  four or five distinct rules on one host inside an hour, so expect it to
  produce one of the highest-scoring cases of the month.

Tell the console watcher **that** specifically — not just "I'm running
tests", but "expect one case on `expvdi012` scoring 90+, and here is the
window". A high score on our own estate that nobody was warned about is how
a measurement becomes an incident.

Attribution for the comparison is **by timestamp, not by case**, so one
shared case costs the measurement nothing.

---

## What I have already measured (you do not need to collect this)

**24-hour baseline for `expvdi012`:**

| window | alerts |
|---|---|
| last 24h | **1** |
| last 7d | 1 |
| last 30d | 1 |
| ever | **2** |

Both are class 4738, account `ExpAdmin`, verdict benign. Log context
collected on the one run that has it. **This host is effectively silent**,
which is exactly what makes attribution trivial: anything that arrives
during your window is yours.

Record this in `protocol.json` as `baseline_24h: 1` — you do not need to
re-derive it, but record it, because the reader of the results needs to know
attribution was easy rather than assume it.

---

## Step 0 — pre-flight, on the VM, before anything else

```bat
whoami
hostname
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

**Check `whoami` is not `NT AUTHORITY\SYSTEM`.** If you are SYSTEM, the
user-side templates cannot fire — the collector refuses to query a built-in
principal — and you would measure that instead of the loop. Expect
`ExpAdmin` or a domain form of it. Record it **exactly** as printed: the
platform stored it as bare `ExpAdmin` on the two historical alerts, not
`INT\ExpAdmin`.

```powershell
# Is Sysmon running, and is its log live?
Get-Service -Name Sysmon*,SysmonDrv -ErrorAction SilentlyContinue |
  Format-Table Name,Status,StartType

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 `
  -ErrorAction SilentlyContinue |
  Format-Table TimeCreated,Id,ProviderName
```

* **Service running and recent events** → proceed.
* **No service, or no such log** → **STOP.** Items 1–3 cannot produce their
  classes. Tell me and we switch host or get Sysmon enabled first.

```powershell
# **The effective Sysmon config — not just that Sysmon runs.**
# Event 7 (ImageLoad) is very commonly excluded outright for volume, so
# "class 7 did not alert" could be a SYSMON CONFIG finding rather than a
# Wazuh rule finding, and those are different answers. Same for 15
# (FileCreateStreamHash), which is also a common exclusion.
sysmon -c
```

Read the dump and record, per event id, whether it is **enabled** and what
filters apply:

| event | name | needed by | enabled? | filters? |
|---|---|---|---|---|
| **15** | FileCreateStreamHash | item 1 | | |
| **11** | FileCreate | item 2 | | |
| **7** | ImageLoad | items 3 and 3b | | |

Record this in `protocol.json` as `sysmon_events: {"15": true, "11": true,
"7": false}` or whatever it says. **If an event is excluded, the items that
need it cannot alert and that is established before you run them** — a
config finding, recorded as such, not a null result to be puzzled over
afterwards.

If `sysmon -c` is not on the path, the binary is usually
`C:\Windows\Sysmon64.exe -c` or `C:\Windows\Sysmon.exe -c`.

**If we switch to `expvdi008`, run exactly the same check there.** Its three
Sysmon alerts are all **class 12** (RegistryEvent), which proves Sysmon is
installed and forwarding and says **nothing** about whether 15, 11 or 7 are
enabled. Class 12 being present is not evidence for the three classes this
exercise needs.

```powershell
# Is the Wazuh agent running and connected?
Get-Service -Name Wazuh*,"OssecSvc" -ErrorAction SilentlyContinue |
  Format-Table Name,Status
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 5 `
  -ErrorAction SilentlyContinue
```

Expect a running service and no recent connection errors. The agent is
proven to reach us (yesterday's alert), so this is a confirmation rather
than a discovery.

---

## The five items

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

Writes a stream containing a literal string, reads it back, and lists it.
`dir /r` shows the stream so you can paste proof it existed. Nothing is
destroyed.

### Item 2 — class 11, executable dropped

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c copy /y C:\Windows\System32\certutil.exe %TEMP%\gt2.exe
cmd /c dir %TEMP%\gt2.exe

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

**Do not run `gt2.exe`.** Copying a signed OS binary into `%TEMP%` is the
whole item; executing `certutil` from a temp path is a different and much
noisier thing.

### Item 3 — class 7, image loaded

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c rundll32.exe version.dll,#1

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

`rundll32` loads `version.dll`, fails to find ordinal 1, and exits. The
**load** is the event. Expect an error dialog or a silent exit — both fine.

**This one is expected to produce no alert.** The class-7 rules in our
corpus are "debug/dump library loaded by a suspicious process" and
"credential-related library loaded by…", and `version.dll` is neither. If it
does not alert, that is a **detection-coverage** result and the correct
outcome to record — not a miss.

### Item 3b — class 7, debug library loaded

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

cmd /c rundll32.exe dbghelp.dll,#1

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

The same mechanism as item 3 with a library that **matches the rule**:
`dbghelp.dll` is the debug/dump library the class-7 corpus rule names. It is
a signed Microsoft DLL, loaded and discarded, and nothing is dumped — but it
is the shape a responder reads as memory-dump preparation, which is why it
sits immediately before item 4 rather than anywhere earlier.

**This is the only item that genuinely exercises class 7.** Item 3 is the
control that establishes `version.dll` produces nothing; 3b is the test. If
3b also produces nothing while `sysmon -c` showed event 7 **enabled**, that
is a Wazuh rule finding. If event 7 was **excluded**, both nulls were
decided before you started.

### Item 4 — class 1102, Security log cleared (LAST)

```bat
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"

wevtutil cl Security

powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

Needs administrator. Clears that host's local Security log; everything
already forwarded is unaffected. **This is the item most likely to draw a
real response** — make sure whoever watches the console knows the window.

### Cleanup, after item 4 and the final confirmation

```bat
cmd /c del /f %TEMP%\gt1.txt
cmd /c del /f %TEMP%\gt2.exe
```

---

## What to record

Append one object per item to `protocol.json`, in this exact shape:

```json
{"items": [
 {"item": 1,
  "host": "expvdi012",
  "account": "<exactly what whoami printed>",
  "command": "cmd /c echo groundtruth-item1-1234 > %TEMP%\\gt1.txt:marker",
  "started_utc": "2026-10-22T09:00:12Z",
  "finished_utc": "2026-10-22T09:00:14Z",
  "expected_class": "15"},
 {"item": 2, "...": "..."},
 {"item": 3,  "...": "...", "expected_class": "7",
  "note": "version.dll — known-null control"},
 {"item": "3b", "...": "...", "expected_class": "7",
  "note": "dbghelp.dll — the real class-7 test"},
 {"item": 4, "...": "...", "expected_class": "1102"}
 ],
 "baseline_24h": 1,
 "sysmon_present": true,
 "sysmon_events": {"15": true, "11": true, "7": true},
 "notes": "anything that surprised you"
}
```

`command` **verbatim**, including the expanded `%RANDOM%` value if you can
see it — the literal string is what lets the comparison find the artefact.
Timestamps to the second. The comparison tool refuses to start if any of the
seven fields is missing, and names `account` specifically.

Keep the file at `~/evidence/ground-truth-2026-10-xx/protocol.json`,
`chmod 600`, directory `700`, with an `INVENTORY.md` entry naming the
question it answers and its deletion trigger.

---

## The confirmation sequence — five items

**None of this can be run from the VM.** It queries the platform's database,
which that VM has no access to and should not have. Either paste me the
`started_utc` after each item and I run it, or run it yourself from
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

### Reading the two class-7 results together

This is the whole reason 3 and 3b are both run, and the three outcomes are
three different findings:

| item 3 (`version.dll`) | item 3b (`dbghelp.dll`) | `sysmon -c` event 7 | what it means |
|---|---|---|---|
| nothing | **ARRIVED** | enabled | **the expected result.** The rule is specific to debug/dump libraries and works |
| nothing | nothing | **enabled** | a **Wazuh rule** finding: event 7 is being collected and no rule matched either load |
| nothing | nothing | **excluded** | a **Sysmon config** finding, settled before you started — neither item could ever have alerted |
| **ARRIVED** | ARRIVED | enabled | the rule is broader than the corpus rule names suggest; worth knowing |

Record which of the four rows you are in. "Class 7 did not alert" on its own
is not a finding — it is three possible findings that need different fixes.

**Do not batch the items.** The ten-minute gap plus a confirmation is what
makes each alert attributable to one item by timestamp. The items will share
a case regardless (six-hour session gap), so timestamps are the only
attribution you have.

## Things that need you somewhere other than the VM

1. **The confirmation check between items** — platform database access. Me,
   or your own workstation with the repo.
2. **The replay and the comparison, afterwards** — both must run inside the
   container, because the OpenSearch CA is a container mount. From the host
   venv the replay now exits 2 rather than reporting every SIEM query as a
   source failure.
3. **Agreeing the window with whoever watches the console** — before item 4
   especially, and before optional 3b.
4. **The EDR coverage note** (`docs/outbound/falcon-edr-coverage-gap.md`) —
   unrelated to this exercise and still needs sending: `dc`,
   `win11-mssql01` and `win10-mssql02` have no sensor.

---

## Afterwards

Paste back: the **five** timestamp pairs, the exact commands, `whoami`
output, the `sysmon -c` event table,
the Step 0 results, and anything that surprised you. I will run the replay
on the items that alerted and the comparison against your `protocol.json`,
and report five columns per item with no aggregate — five exercises is not a
rate either.
