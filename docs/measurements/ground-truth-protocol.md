# Ground-truth protocol: authoring an answer key on our own estate

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`, 176 device records / 171 distinct
> hostnames, every `machine_domain` an `expertware.net` domain. See
> [POPULATION.md](POPULATION.md). Nothing in this protocol touches a customer
> estate.

Written 2026-10-21 for an operator to execute. The existing answer key is
five historical cases, four `false_positive` and one `inconclusive`, with
**no true positives** — so it can measure whether the loop agrees nothing
happened and nothing else. This protocol makes the missing half.

---

## 0. The one decision to make first: which host

**Do not use a test host as it stands.** Measured today, the three obvious
candidates have **no Falcon sensor**:

| host | alerts in 30d | Falcon sensor |
|---|---|---|
| `windows-test-device` | **1,789** | **none** |
| `asiem-victim` | 26 | **none** |
| `laboratorvm001` | 7 | **none** |

`windows-test-device` is the host behind case **#61** — scored 100, no EDR
corroboration, analyst closed it `inconclusive`. Running the exercise there
reproduces #61 exactly and learns nothing: half the playbook has nothing to
answer with.

Eighteen alert-sending hosts have no sensor. **112 hosts are in both Falcon
and Wazuh**, 109 with a sensor seen inside 48 hours.

### Option A — recommended: put a sensor on a test VM

Install the Falcon sensor on **`laboratorvm001`** (or a fresh VM named for
the purpose). One-time, reversible, and it converts a host you can do
anything to into a host the whole playbook can answer about. Every later
exercise reuses it.

> **Checked 2026-10-21 and it is not ready.** `laboratorvm001` reports
> **`managed=False`** — no sensor is installed or reporting. So does
> `asiem-victim` and so does `windows-test-device`. **Option A is blocked
> until a sensor is installed on one of them**, which is the gate below
> doing its job.
>
> Option B was confirmed the same day: all five candidate hosts report
> `managed=True`, `status=normal`, last seen within the hour.

Confirm before running anything:

```
# in the container, so the OpenSearch CA mount exists
docker compose exec -T -e PYTHONPATH=/app worker python - <<'EOF'
from app.services.context_gathering.falcon_source import FalconSource
for ev in FalconSource(tenant_id="c00").query("host_threat_state",
                                              {"host": "laboratorvm001"}):
    print(ev["falcon"])
EOF
```

`managed=True` with a recent `last_seen` means proceed. `managed=False`
means the sensor is not reporting yet — **stop**, because that is #61 again.

### Option B — if you want to run today without installing anything

Use a quiet managed host. All of these had **1 alert in 14 days** and a
sensor seen within 24 hours:

`exp-3lwk334`, `exp-3xyzck3`, `exp-4brrpb4`, `exp-530gnx3`, `exp-6g6xgl3`

They are **end-user Windows 11 laptops**, so this needs the person's
agreement as well as the console owner's, and it restricts step 2 to the
non-destructive items only (no log clearing on someone's machine).

**Do not use:** any domain controller (`dc` appears in the unmanaged list),
`win10-mssql02`, `win11-mssql01`, or any host whose sensor was last seen
more than 48 hours ago — 13 sensors are stale, up to 42 days.

---

## 1. What to run

Benign, reversible, no real malware, nothing that touches credentials, and
each item chosen because the playbook **now has a row for its class**
(classes 15, 1102, 7 and 11 were added for the answer-key cases).

Run them **one at a time**, with a gap of at least 10 minutes, so each is
attributable. Record each separately.

| # | class | what to run | why benign | host restriction |
|---|---|---|---|---|
| 1 | **15** — FileCreateStreamHash | `cmd /c echo groundtruth-1 > %TEMP%\gt1.txt:marker` then `type %TEMP%\gt1.txt:marker` | writes an alternate data stream containing a literal string; delete the file after | any |
| 2 | **11** — FileCreate | copy a signed Microsoft binary into a watched folder: `copy C:\Windows\System32\certutil.exe %TEMP%\gt2.exe` — **do not run it** | a copy of a signed OS binary; the corpus rule is "executable dropped in a folder commonly used by malware" | any |
| 3 | **7** — Image loaded | `rundll32.exe C:\Windows\System32\version.dll,#1` | loads a signed OS DLL and exits; the corpus rules here are "debug/dump library" and "credential-related library", so expect this one may NOT alert | any |
| 4 | **1102** — audit log cleared | `wevtutil cl Security` | clears the local Security log. **Destroys local audit history on that host** — test VM only, and only after confirming nobody needs that host's log | **Option A only** |

Item 4 is the one that matters most — it is the class case **#1184** was
made of, and the class with **no user on any of its 20 corpus runs** — and
it is the one you must not run on a shared or production host.

**Do not substitute anything that touches `lsass`**, dumps process memory,
uses `mimikatz`-like tooling, or disables the sensor. Those would be real
detections with real response consequences, on our own estate, and the point
is a measurement rather than an incident.

---

## 2. What to record, and to what precision

Write this **before and during** execution, not reconstructed afterwards. A
protocol reconstructed afterwards records what happened rather than what was
intended, which is the defect this whole exercise is meant to measure
against.

For each item, record:

| field | precision | why this precision |
|---|---|---|
| `item` | the number above | so the comparison can key on it |
| `host` | the **exact Falcon hostname**, lowercase | the loop joins on hostname; a DNS suffix or a different case is a different host to a string join |
| `account` | `DOMAIN\user` exactly as Windows reports it (`whoami`) | `NT AUTHORITY\SYSTEM` is refused by the collector as a built-in — if you run as SYSTEM, the user-side templates cannot fire and you will have measured that instead |
| `command` | **verbatim**, including quoting | so the comparison can look for the artefact the command names |
| `started_utc` | **to the second**, UTC | windows are ±6h (Falcon) and ±60min (SIEM), so minutes would do for the window — seconds are what let an individual event be attributed to an item rather than to background |
| `finished_utc` | to the second, UTC | bounds the attribution |
| `expected_class` | from the table | the thing the comparison checks, not the thing it assumes |

Get UTC from the host itself, not from your watch:

```
powershell -c "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"
powershell -c "whoami; hostname"
```

**Also record the baseline.** Before item 1, note how many alerts that host
produced in the previous 24 hours. A host that normally emits nothing makes
attribution trivial; one that emits constantly makes it guesswork, and the
baseline is what tells the reader which situation they are in. The candidate
hosts above were chosen at 1 alert per 14 days for exactly this reason.

### Where to put it

```
~/evidence/ground-truth-2026-10-xx/protocol.json
```

with an `INVENTORY.md` entry naming the question it answers and its deletion
trigger, `chmod 600` on the file and `700` on the directory — the standing
rule for anything with estate detail in it.

---

## 3. How to run the replay blind

**The harness must not be able to read your notes.** If it can, the
comparison measures whether a file was parsed, not whether the loop gathers.

1. Keep `protocol.json` in `~/evidence/…`. The replay reads **nothing** from
   that path, and nothing in `backend/` references it.
2. Wait for the alerts to arrive and be analysed. Check they exist by host
   and time only:

   ```
   docker compose exec -T -e PYTHONPATH=/app worker python - <<'EOF'
   from sqlalchemy import create_engine, text
   from app.config import get_settings
   e = create_engine(get_settings().database_sync_url)
   with e.connect() as c:
       for r in c.execute(text("""
           SELECT id, event_time, result_json->'alert_fields'->>'event_id'
           FROM alert_body_investigation_runs
           WHERE entity_host = :h AND event_time > :since
           ORDER BY event_time"""), {"h": "<host>", "since": "<started_utc>"}):
           print(r)
   EOF
   ```

3. Run the replay against **those run ids**, giving it the host and the time
   and nothing else. It must run in the container:

   ```
   docker compose exec -T -e PYTHONPATH=/app worker \
     python /app/scripts/replay_answer_key_cases.py --alerts-per-case 1
   ```

   Run from the host venv it now **refuses** with exit code 2, because every
   SIEM query there returns `unavailable` and would be recorded as a source
   failure — case #1050 already looked like a broken source when it was a
   missing CA mount.

4. Only **after** the replay has produced its record, open `protocol.json`
   and compare.

---

## 4. What the comparison must report

The tool exists already: `backend/scripts/compare_ground_truth.py`, written
**before** the exercise on purpose — a comparison written after the results
exist is shaped by them.

```
docker compose exec -T -e PYTHONPATH=/app worker \
  python /app/scripts/compare_ground_truth.py /path/to/protocol.json
```

It refuses to start if an item is missing any of the seven recorded fields,
and it names `account` specifically, because running as SYSTEM makes the
user-side templates unfirable and you would measure that instead.

Exercised in both directions before the window: items with no alert in their
window report `ALERTED: NO` and are called **detection coverage**; items with
a real alert report the class match, the extracted selectors, the templates
that would run and every skip with its reason. It prints **no aggregate**.



Per item, five columns. The fifth is the one historical false positives
cannot give us.

| column | question |
|---|---|
| **alerted** | did an alert fire at all for this item? If not, nothing downstream means anything — and that is a detection-coverage finding, not a loop finding |
| **class** | did the alert carry the `event_id` class we expected? A mismatch means the playbook row that would have run is not the row that ran |
| **selectors** | did `host`, `user`, `hash` extract? Measured on the existing corpus: `alert_fields` carries **no indicator at all**; hashes come from `indicator_reports[].indicator`. If a selector is missing, the template skips and the skip is correct |
| **templates** | which ran, which were skipped with which reason, which returned `check_failed` and naming which source |
| **MISSED** | **what the loop failed to gather that we know happened** — the artefact the command created, the account that ran it, the host state at the time |

Report each as `expected / observed`, and state the absences as absences:
"no alert fired" and "an alert fired and the loop found nothing" are
different results, and the whole point of this estate is that we know which
one is true.

**Do not aggregate across items.** Four exercises is not a rate, and a
"3 of 4" summary would be a proportion of a sample of four.

---

## 5. What this can and cannot establish

It can establish: that an alert fires for a known action, that it carries
the class the playbook expects, that the selectors extract, that the sources
answer, and **what the loop misses** — which five historical false positives
cannot show at all.

It cannot establish that the playbook is right for a client's estate. Event
mix, host naming, noise floor and rule set are all unmeasured there, and
today neither Exabeam credential can even be attributed to an owner
(backlog 47). Authored ground truth on our own estate is the best available
evidence and it is still evidence about **our** machines.
