# What reaches the model, and how often

Two problems found on the same screen: a de-anonymisation table inside an AI
*input*, and correlation commissioning model calls from the read path.

## The resolution table was going back out

A finished report is de-anonymised for the analyst — `[HOST_1]` becomes the real
hostname — and a **Resolved Identifiers** table is appended mapping every token
to its value. Correct for the person reading it, wrong for anything that reads
it afterwards.

The correlated-case narrative reads it afterwards. `_resolutions_for` collects
each member's `report_markdown` into the evidence for a *new* model call, so the
de-anonymised prose and the token table both went back to the provider.

**What was actually leaking**, tested against the real sanitiser rather than
assumed:

| Value in the table | Re-tokenised on the way back? |
|---|---|
| `EXP-4LWK334.int.expertware.net` | yes — becomes `[HOST_1]` again |
| `10.10.126.64` | yes |
| `dnechita` | **no — sent in the clear** |

Hostnames and IPs survive because the sanitiser matches them on shape. Accounts
are matched on *keys* — `user=`, `Account Name:` — and a bare name in a markdown
table cell matches none of them. So the row `| [ACCOUNT_1] | Account |
dnechita |` handed over the account, and the two rows that did get re-tokenised
became `| [HOST_1] | Hostname | [HOST_1] |`: tokens spent to say nothing.

### Two fixes, because one of them is a reminder and the other is not

**The pre-restoration report is now stored.** `report_markdown_model_safe` is
what the model wrote before its tokens were resolved, and it is the only version
that may ever be model input again. The case narrative prefers it and falls back
to stripping the table from the analyst report for analyses written earlier.

**And `add_entry` strips the section unconditionally.** Every model input
becomes an `AssistantEntry` through that one method, which makes it the one
place this can be kept out of all of them. The first fix requires a caller to
remember; the second does not.

## Correlation ran from the read path

`correlate_alerts()` both groups alerts and *acts* on the grouping — fires case
webhooks, commissions an AI narrative for every case whose shape changed. It is
called by `case_for_run`, which runs when an analyst opens an alert. So reading
the queue was the thing that drove the AI bill, and a busy page produced a lot
of concurrent workers doing work nobody asked for.

Reads now compute and store; they no longer emit. `correlate_alerts(emit=False)`
is the default and every read path leaves it alone — a test asserts that.

`case-correlation-hourly` is what acts. It runs at five past the hour and
returns early unless an alert has been ingested since its last pass: an hour
with no ingest cannot have changed a case, so re-deriving the same grouping
would spend the scan for nothing.

```
pass 1 (forced)             -> ran, 12 cases over 48h, watermark 11:43:11
pass 2 (nothing new since)  -> skipped, "no new alerts"
pass 3                      -> skipped
```

The watermark is the newest alert this job has accounted for, kept in Redis
beside the other operational counters. Losing it fails in the safe direction: an
unknown watermark runs the pass.

`correlate_and_notify(force=True)` runs one immediately.

### One thing this needed that the first attempt got wrong

The task uses a dedicated unpooled engine per invocation. Celery runs each task
in a worker thread and `asyncio.run` builds a fresh event loop every time, so
the app-wide pooled engine hands the new loop asyncpg connections bound to the
previous one. With the shared engine the first beat tick succeeded and the
second raised *"attached to a different loop"* — which it duly did in testing.
The two neighbouring AI tasks already carry the same workaround for the same
reason.
