# The Falcon panel: scoped to what Falcon can actually answer

**Status:** specification. Nothing built. The scoping conclusion is the
deliverable, and it moves the panel off the email page.

## What the credential can reach

Measured on tenant `c00`'s real credential, `https://api.eu-1.crowdstrike.com`
(recorded in `falcon_client` beside the path constants):

| endpoint | result | so |
|---|---|---|
| `/alerts/queries/alerts/v2` | **200** | usable |
| `/devices/queries/devices/v1` | **200** | usable |
| `/alerts/queries/alerts/v1` | 200 | superseded by v2 |
| `/detects/queries/detects/v1` | **404** | the legacy Detects API is gone |
| `/devices/queries/devices/v2` | 404 | does not exist |
| `/intel/queries/indicators/v1` | **403** scope not permitted | unavailable |
| `/iocs/queries/indicators/v1` | **403** scope not permitted | unavailable |

The last two decide the shape of everything below. The endpoints that would
answer *"what does CrowdStrike Intelligence know about this domain?"* are
refused by this API client's scopes. **Falcon cannot be asked whether an
indicator is known-bad.** It can only be asked what this tenant's own estate
has done or seen.

The integration's stored state is `verified_ok`, checked 2026-10-15 08:31, and
that promotion rests on a real query rather than a token fetch — `verify()`
calls the alerts endpoint and records `estate_has_alerts: True`. Worth saying
because the token's own `scopes` field comes back `[]`, which is not "no
scopes": `fetch_token` reads `body["scope"]`/`["scopes"]` and stores `()` when
Falcon says nothing. Falcon does not report scopes here, so the empty list is
an absence stored as a value — minor, but it means scope coverage must be
inferred from endpoint behaviour, not read off the token.

## The hazard that sets the design

**The Alerts API does not validate FQL field names.** Measured on this tenant:
`behaviors.domain`, `domain`, `indicator_id`, `filename`,
`behaviors.ioc_value`, `ioc_value`, `sha256`, `behaviors.sha256`,
`device.hostname`, `hostname`, `local_ip`, and the *invented*
`behaviors.ioc_type` **all returned HTTP 200 with zero resources.**

From the response alone, a field that does not exist is indistinguishable from
a field that exists and matched nothing. That is precisely the
absence-as-answer shape this platform spent two days removing, handed over by
the vendor — and the failure direction is the bad one: a typo reads as "your
EDR has nothing on this host", for ever, silently, on every investigation.

The Devices API *does* validate: `local_ip:'example-host'` returns 400
"invalid IP address". So the hazard is specific to Alerts.

### The positive control

`estate_has_alerts` is already recorded and is *not* sufficient. It proves the
estate has some alerts; it says nothing about whether the field being filtered
on exists. The control has to exercise the same field the panel uses:

1. `GET /alerts/queries/alerts/v2?limit=1` with **no filter** → one alert id.
2. Fetch that alert's detail and read the value actually stored at the field
   the panel filters on (`behaviors.domain`, say).
3. Re-query with `filter=behaviors.domain:'<that exact value>'` → **must
   return at least that alert.**

If step 3 returns zero, the field name is wrong or not filterable, and every
panel result is meaningless. The panel then renders `check_failed` naming the
field — never "no detections". If step 1 returns nothing, the estate has no
alerts at all and the control cannot run: that is `too_little_history`, and
the panel says the control could not be exercised rather than claiming it
passed.

Two requests, cached per tenant for the life of a process. Cheap enough to run
before the panel's own query rather than on a schedule, which matters because
a field name breaks on a provider change, not on a clock.

## Why this does not belong on the email page

An email investigation's indicators are domains from links, the sender domain,
the sender IP, and attachment hashes. Falcon's two usable endpoints answer:

**Device search** — structurally inapplicable.

- For a domain, `lookup()` asks `hostname:'<domain>'`. That asks whether a
  machine in the estate is *named* `aka.ms`. It is not a meaningful question,
  and it returns a silent zero.
- For an IP, it asks `local_ip:'<ip>'`. `local_ip` is the device's own LAN
  address; an email's sender IP is a remote public address and will never be
  one. The Devices API validates the *shape*, so a public IP passes validation
  and returns 200 with zero resources — valid field, valid value, structurally
  impossible match.

Both produce "not found" for reasons that have nothing to do with the estate.
Rendering either as an EDR answer about an email is the proxy-metric mistake:
a number that cannot mean what the panel implies.

**Alerts search** — meaningful, but narrow. `behaviors.domain:'<domain>'` and
`behaviors.sha256:'<hash>'` genuinely ask "has this tenant's EDR raised an
alert whose behaviour mentions this?". That is one real question, and it is
worth having.

So on the email page Falcon can answer exactly one thing, and must be scoped
to it:

> **Has this tenant's EDR alerted on any of these indicators?**
> Asked of link domains and attachment hashes only. The sender IP and the
> hostname question are not asked, because Falcon cannot answer them about
> an email.

Not "is this domain malicious" — the intel endpoints are 403. Not "is this in
your estate" — that is the OpenSearch estate DNS panel's question, and it
answers it from 4.47M endpoint DNS events rather than from an EDR alert
corpus. The two panels sit side by side and must not be conflated: *resolved
by a host* and *alerted on by the EDR* are different findings, and a domain
can be the first without the second on every ordinary day.

## Where Falcon is actually worth showing

Where a **host** is in scope. The alert and case views have `agent.name` from
the Wazuh alert — a real hostname that `/devices/queries/devices/v1` can both
validate and match. There, all of Falcon's usable surface applies:

| question | endpoint | field |
|---|---|---|
| is this host managed by Falcon at all? | devices | `hostname` |
| when did Falcon last see it? | devices detail | `last_seen` |
| what has Falcon detected on it? | alerts | `device.hostname` |

That third row is the one an analyst acts on: *this Wazuh alert fired on
EXP-1234, and Falcon has three detections on EXP-1234 this week.* It is also
the row that makes the **unmanaged-host** finding possible — a host producing
Wazuh alerts that Falcon has never seen is a coverage gap, and the estate
already has a denominator to measure it against: 180 agents, 175 with DNS
telemetry. "Which of our 180 hosts is Falcon not managing?" is a question the
devices endpoint can answer at estate scale, and nobody has asked it.

A caution on that denominator: matching Wazuh `agent.name` to Falcon
`hostname` is a join on a hostname string, and the two products normalise case
and domain suffixes differently. That join needs its own measurement before it
becomes a coverage number — an unmatched host would read as "Falcon is not
managing it" when it means "the names do not line up". Partial coverage on a
join key is worse than none; the SID re-keying design died on this exact
point.

## Order of work

1. **The positive control**, in `falcon_client`, with its own absence kinds.
   Nothing that renders a Falcon result should ship before it, because the
   failure it catches is invisible.
2. **The host panel** on the alert/case view — device managed/last-seen plus
   detections by `device.hostname`.
3. **The email panel**, scoped to the one question above, after 1 and 2. It is
   last deliberately: it is the narrowest value and the easiest to overstate.
4. **The coverage question** (Wazuh agents vs Falcon-managed), gated on
   measuring the hostname join first.

Not in scope here: ingest. Polling Falcon's detections into the alert pipeline
needs `_create_alert_run` extracted from the API module, a field map that
quarantines unmapped fields as `no_field_map`, and a decision about Falcon's
own MITRE attributions as a third technique namer that must not quietly join
`rule_only`. That is why `integration_directions` says `enrichment` alone.

## Open, and needing a fact rather than a decision

- Whether this API client can be given the **intel** scope. If it can,
  "what does CrowdStrike know about this indicator" becomes answerable and the
  email panel grows a second question. If it cannot, the 403 is permanent and
  should be recorded as a capability absence rather than retried per
  investigation.
- Whether Falcon's alert FQL supports any field that carries a **sender IP**
  in a mail-flow context. If not, that indicator is permanently outside
  Falcon's reach from an email, which is worth stating in the panel once
  rather than discovering per alert.
