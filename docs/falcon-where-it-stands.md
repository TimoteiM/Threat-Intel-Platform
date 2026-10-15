# CrowdStrike Falcon — where it stands, end of 2026-10-15

**Written for:** whoever picks this up next, including me tomorrow.

At 09:00 Falcon had a verified credential and a successful ping, and nothing a
user could see. It now has a panel on the alert page, driven by real data, and
one live false-negative defect was found and closed on the way.

## What a user can see now

On any alert investigation whose run names a host, at the bottom of the log
section: **CrowdStrike Falcon — this host.**

- **EDR coverage** — sensor installed or not, OS and build, sensor version,
  status, prevention policy, reduced-functionality mode, site, domain, first
  and last seen. "No sensor on this host" renders as a *finding*, because the
  Devices API validates `hostname` (an unknown field is a 400), so the empty
  result is a real negative.
- **Detections** — grouped by (name, filename), headline is **distinct open**
  detections. Tactic, technique, file, user, disposition, status per group.
  Closed ones collapse. The raw row count is behind a disclosure, labelled as
  repetition.
- **The window actually covered**, which is not always the window requested.
- **The field control's state**, in the footer, because every "nothing found"
  above depends on it.

Verified live, through the route, on real runs:

| host | result |
|---|---|
| `EXP-22MY264` | managed, Windows 11 build 26200, sensor 7.40.21309.0, prevention applied — **4 open of 9 distinct** from 500 raw rows |
| `ExpDC001` | managed, Windows Server 2016, sensor reporting, 0 detections |
| `EXP-26ML4Y2` | managed — *"Covers 4 days, not 30: this host's sensor was enrolled 2026-10-11"* |

Reach: 95.3% of alert runs in the last 7 days carry an `entity_host`
(1,993 of 2,091); 89.4% of hosts in SIEM alerts match a Falcon device on a
plain case-insensitive hostname compare.

## The defect found, and why it is worth remembering

`ALERT_FILTER_FIELDS` mapped every indicator kind to `behaviors.*`. **The
Falcon alert record has no `behaviors` key** — 0 of 200 sampled alerts carry
one — and the Alerts API answers an unknown field name with **HTTP 200 and
zero resources**. So every hash lookup returned "the EDR has nothing" while
the field worked perfectly under its real name: the same hash gives 17 rows as
`sha256` and 0 as `behaviors.sha256`.

That class is now named in `docs/problems/false-exculpation.md`: we asked, the
tool had something, and we told the analyst it had nothing. Worse than a false
negative because it is acted on, invisible, and becomes evidence.

**Damage: none, measured two ways.** No evidence row has ever carried a
`falcon` block (0 of 2,608), and all 84 stored attachment-hash/field pairs
across 26 email runs re-queried against the corrected field return **zero
hits, zero errors** — with both field controls passing first, so the zero is a
measurement and not another empty 200.

## Measured vs assumed

Everything load-bearing was measured today. What that means for each claim:

| claim | basis |
|---|---|
| 182 devices, 2,048 alerts | unfiltered queries |
| alert retention reaches 2026-07-17 (90 days) | oldest alert, sorted ascending; `>'2024-01-01'` returns the same total as `>'2026-06-01'`, so no silent clamp |
| 90 days is the tier-independent figure for detections | community sources only — **no official CrowdStrike page found**, so the measurement is the authority and 90 is a sanity bound |
| hostname join needs no normalisation | 160/179 exact, 0 needing suffix stripping |
| Devices validates fields, Alerts does not | 400 vs 200-with-zero, probed both ways |
| intel / iocs / falconx / scanner unavailable | 403 scope-not-permitted, re-measured today |
| no alert field carries a domain or a remote IP | every candidate probed, all 200/0 |

Nothing in the panel now asserts a window it has not established: an
unmeasured retention floor withholds the window claim rather than defaulting
to what was asked.

## Open questions

1. **Zero Falcon alerts since 2026-10-08.** Weekly totals since retention
   begins: 2, 64, 58, 50, 82, 46, 14, 79, 32, **1427**, 9, 13, 12, **0**, 0.
   Sensors are reporting (153 of 182 devices checked in within a day), so this
   is not a sensor outage. Against a 9–82/week baseline, zero for a week is at
   the low end but not outside it — and this is exactly the condition
   backlog 18 describes: Falcon alerts on escalation, not on a clock, so a
   quiet estate and a stopped alert flow are **indistinguishable**. Flagged,
   not diagnosed. If it is still zero in a few days it stops being ambiguous.
   (The 1,427 spike in the week of 2026-09-14 is one developer's `wsl.exe` on
   `EXP-22MY264`.)
2. **Can this API client be granted the intel scope?** If yes, "what does
   CrowdStrike know about this indicator" becomes answerable and the email
   panel gains a real question. If no, the 403 should be recorded once as a
   capability absence rather than retried per investigation. Needs someone with
   Falcon console admin.
3. **Are `DC`, the two SQL servers and `dns1` deliberately out of EDR scope?**
   A question for whoever owns the licence count — see the coverage document.

## Still to build, in order

1. **Attachment-hash lookup on the email panel.** The only Falcon question an
   email can ask. The field name is now correct and control-gated, so this is
   small. Not domains, not the sender IP — neither exists in Falcon.
2. **The coverage view in the product.** The 19-host gap is currently a
   document (`docs/outbound/falcon-edr-coverage-gap.md`) rather than a page.
   The join is measured and sound, so this is reporting work, not research.
3. **Stale-sensor list.** 9 of 182 devices last reported over 31 days ago, 10
   more between 8 and 30 days. Covered on paper, possibly not in fact — a
   different list and a different fix from the 19.
4. **Falcon ingest** (polling detections into the alert pipeline) is still a
   separate pass and still needs `_create_alert_run` extracted from the API
   module first, plus a field map that quarantines unmapped fields, plus a
   decision on Falcon's own MITRE attributions as a third technique namer.
   `integration_directions` says `enrichment` alone, correctly.

## Consolidation debt I created

- Four hand-rolled `${h}h ago` formatters remain (`watchlist`, `clients`, the
  dashboard, `DevicesTab`). `src/lib/time.ts` is the one to grow into; only
  the Falcon panel and the two integrations-card sites use it so far.
- `FalconHostPanel` renders `detections.basis` and the footer's
  `field_control`; the first is now deliberately one short sentence so the two
  do not say the same thing twice.

## Where things live

| | |
|---|---|
| client | `backend/app/integrations/falcon_client.py` — `lookup_host`, `alerts_field_control`, `alert_retention_floor`, `alert_filter_field` |
| shaping | `backend/app/services/falcon_host_panel_service.py` — `coverage`, `group_detections`, `effective_window`, `unjoinable` |
| route | `GET /api/alert-investigations/{run_id}/falcon` |
| panel | `frontend/src/components/report/FalconHostPanel.tsx` |
| what it can answer | `docs/design/falcon-panel.md` |
| the failure class | `docs/problems/false-exculpation.md` |
| field names | `docs/problems/a-field-name-is-not-a-question.md` |
| coverage gap, for handing on | `docs/outbound/falcon-edr-coverage-gap.md` |

Tests: 32 panel service, 15 field control. Full unit suite at the enumerated
14 tolerated failures, diffed by name. Frontend typechecks and builds.

Branch `feature/email-investigation-upload` at `f0a0ae7`, pushed. Liveness
green on all limbs.
