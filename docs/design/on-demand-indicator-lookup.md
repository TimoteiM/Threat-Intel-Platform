# On-demand indicator lookup — specification

**Status:** specification. Nothing built. One box, any indicator, routed by
type, and **every source states what it could not be asked.**

## The thing this must not become

A lookup that silently cannot answer is false exculpation with a search box on
it. Type a domain, see an empty Falcon section, conclude the EDR has nothing —
when Falcon has no field that could ever hold a domain. The whole value of
this feature is that it asks several sources at once; the whole risk is that
it reports their *inapplicability* as their *answer*.

So the governing rule: **for each source, the panel renders exactly one of
three things** — an answer, a named absence, or "this source cannot be asked
about this kind of indicator, because ⟨reason⟩". Never an empty result where
the third applies. This is `app/services/absence.py` applied per source and
per indicator type rather than per field.

## Routing

Type is detected from shape, and a value whose type cannot be determined is
`unparsed` rather than guessed at. (The existing `_DOMAIN` regex and
`_is_ip` in `estate_lookup_service` already do this; reuse them rather than
writing a third parser.)

| indicator | Falcon | Estate DNS (OpenSearch) |
|---|---|---|
| **hash** (sha256 / sha1 / md5) | **ask** — `sha256` / `sha1` / `md5` on the Alerts API, field chosen by digest length, **control-gated** | `out_of_scope` — no estate field holds a file hash |
| **hostname** | **ask** — `/devices/queries/devices/v1` on `hostname`; the Devices API validates field names, so an empty result is a real negative | `out_of_scope` — the estate answers about names a host *resolved*, not about the host itself |
| **domain** | **`no_field_map`**, explicitly and always — measured 2026-10-15: no Falcon alert field carries a domain. `behaviors.domain`, `domain`, `data_domains`, `ioc_context.domain` and `ioc_value` all return HTTP 200 with zero rows, and `data_domains` holds a data classification (`['Endpoint']`), not a name. The intel endpoints that would answer are 403. | **ask** — `data.win.eventdata.queryName`, event 22, with the observation floor and the per-host collection floor as already built |
| **ip** | **`out_of_scope`** with the reason: `source_ips` on an alert holds *internal* source addresses, and `local_ip` on a device is the device's own LAN address, so a remote address can never match either. Valid field, valid value, structurally impossible. | **ask** where applicable — `data.dstip`, with the standing caveat that this field comes from **one** perimeter appliance and is not estate-wide |
| **url** | `no_field_map` — follows from domain | `out_of_scope` — this estate has no proxy logs; ask the domain instead |
| **unrecognised** | `unparsed` | `unparsed` |

Note the asymmetry in the `domain` row. Falcon's answer is `no_field_map` — a
missing field — while the IP row is `out_of_scope` — a field that exists and
cannot match. They are different claims and should read differently: one says
"we have nowhere to look", the other "looking there cannot work".

## What each source section renders

Per source, in this order:

1. **The question asked**, in words, naming the field: *"Falcon alerts
   mentioning this SHA-256"*, *"Endpoint DNS queries for this name"*.
2. **The answer, or the absence.** Hits with their detail; or the named
   absence with its reason verbatim. Never a bare zero.
3. **The bound on the answer** — the covered window, not the requested one.
   Falcon: retention floor and sensor-enrolment floor. Estate DNS: retention
   and the per-host collection floor. Both already exist
   (`effective_window`, `observation_floor`); this surface reuses them rather
   than restating a window.
4. **The control's state**, where the source has one. Falcon alerts do.

## Why this is not just "ask everything"

Asking a source that cannot answer costs a request and produces a zero that
has to be explained away. The routing table above is not an optimisation — it
is the difference between a panel that says "no Falcon detections for
`evil.com`" (false, and dangerous) and one that says "Falcon has no field that
holds a domain; the estate's DNS telemetry answered instead".

## Cost

Per indicator, worst case: 1 Falcon token (cached) + 1 field control (cached
per process, hourly) + 1 Falcon query + 1 estate count + 2 estate floor
queries on a hit. Measured comparables: the estate lookup ran 7 indicators in
168 ms concurrently; a Falcon host lookup is ~2 requests.

A cap on indicators per request, and the number not asked stated in the
response — the estate route's `_ESTATE_INDICATOR_CAP` pattern.

## Out of scope here

- **Free-form log querying.** See backlog 24: it is blocked on the tenancy
  test in backlog 17, and it is probably the wrong feature anyway.
- **Writing anything.** This is a read surface. No containment, no policy
  change, no detection status change.

## Build order, when it is time

1. The routing table as data, with its reasons, tested so that adding an
   indicator type without a decision per source fails. This is the silent-
   registry shape: a new type that quietly gets an empty section is the defect.
2. The absence-per-source rendering, before any source is wired, so that no
   source can ship an empty result by default.
3. Hash → Falcon (the control already exists).
4. Domain → Estate DNS (already exists behind
   `/api/email-investigations/{run_id}/estate-dns`; this needs a
   run-independent entry point).
5. Hostname → Falcon devices.
6. IP → estate perimeter, with the single-appliance caveat on the face of it.
