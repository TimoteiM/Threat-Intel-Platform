# Runbook: ground-truth exercise on `expvdi012`

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`. `expvdi012` is a QEMU VM in
> `Computers,ExpertWare`, `ExpAdmin` the only human account ever seen on it.
> Nothing here touches a customer estate.

Order fixed as **1, 2, 3, then 4**, ten minutes between each. Item 4 last,
because it is the one most likely to draw a real response and response
activity would contaminate 1–3.

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

## The four items

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

**Optional item 3b, only if you want class 7 actually exercised:** swapping
`version.dll` for `dbghelp.dll` would match the debug/dump rule. It is
equally benign — a signed Microsoft library, loaded and discarded — but it
is the shape a responder reads as memory-dump preparation. If you want it,
run it **after item 4**, so it cannot contaminate 1–3, and tell the console
watcher.

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
 {"item": 3, "...": "...", "expected_class": "7"},
 {"item": 4, "...": "...", "expected_class": "1102"}
 ],
 "baseline_24h": 1,
 "sysmon_present": true,
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

## The confirmation check between items

**This cannot be run from the VM.** It queries the platform's database, which
that VM has no access to and should not have. Two ways:

**Either** paste me the host and the item's `started_utc` and I run it:

```
check_item_alerted.py --host expvdi012 --since 2026-10-22T09:00:12Z --expect-class 15
```

**or** run it yourself from somewhere with repo and Docker access:

```
docker compose exec -T -e PYTHONPATH=/app worker \
  python /app/scripts/check_item_alerted.py \
  --host expvdi012 --since 2026-10-22T09:00:12Z --expect-class 15
```

It answers one of three things, and the middle one matters:

| it says | meaning | do |
|---|---|---|
| `ARRIVED` | an alert exists, with its class, account, verdict and log-context status | proceed to the next item |
| `NOTHING YET` | inside the 20-minute settle window | **wait and re-run** — ingest and analysis are not instant |
| `NOTHING (settled)` | past 20 minutes with nothing | record no-alert for that item as **detection coverage**, and proceed |

Exercised in both directions before writing this, against a window with a
known alert and a window with none.

**Do not skip the check and batch the items.** The ten-minute gap plus a
confirmation is what makes each alert attributable to one item; without it
you have four commands and a pile of alerts.

---

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

Paste back: the four timestamp pairs, the exact commands, `whoami` output,
the Step 0 results, and anything that surprised you. I will run the replay
on the items that alerted and the comparison against your `protocol.json`,
and report five columns per item with no aggregate — four exercises is not a
rate.
