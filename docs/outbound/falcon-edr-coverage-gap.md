# CrowdStrike Falcon coverage gap — 19 hosts

**For:** whoever owns the Falcon rollout and licence count.
**Measured:** 2026-10-15, customer `c00`. Read-only; nothing was changed.

## Summary

Nineteen hosts are sending security events to the SIEM and have **no
CrowdStrike sensor**. They include a domain controller, two SQL servers, a
DNS server and a monitoring host. One of the nineteen is the SIEM's own
collector and is expected; the other eighteen are a genuine gap.

| | count |
|---|---|
| hosts sending alerts to the SIEM (last 7 days) | 179 |
| Falcon device records | 182 |
| distinct hostnames in Falcon | 175 |
| **hosts matched to a Falcon sensor** | **160 (89.4%)** |
| **hosts with no Falcon sensor** | **19** |
| Falcon hosts not sending SIEM alerts in 7 days | 15 |

## How the two lists were matched

Wazuh `agent.name` against Falcon `hostname`, compared case-insensitively.
That is the whole rule — 160 matched exactly and **none** required stripping a
DNS suffix or any other normalisation. A name-based join is usually the weak
point in a claim like this, so it was tested before being relied on; on this
estate it is sound.

Two consequences worth stating, because they bound what the number means:

- A host could carry a sensor registered under a *different* hostname and
  appear here as uncovered. Nothing in either system would reveal that, so
  each entry below should be confirmed against the asset itself before a
  licence is bought.
- The 15 Falcon-managed hosts with no SIEM alerts in 7 days are the mirror
  image and are **not** part of this gap. They may be powered off, off the
  network, or not forwarding logs — a separate question for the SIEM side.

## The gap

Ordered by SIEM alert volume over 7 days, which is a rough proxy for how much
is happening on the host — not for risk.

| host | alerts / 7d | what it appears to be | what no EDR means here |
|---|---|---|---|
| `wm-c00.siembiot.int` | 122,879,523 | the SIEM's own Wazuh manager | **Expected.** A log collector is not an EDR target. No action. |
| `DC` | 753,124 | a domain controller | **Highest priority.** Credential-theft and DCSync activity on a DC is the single event an EDR is bought for, and nothing on this host would detect or block it. |
| `EXP-044036414857` | 140,513 | workstation (naming matches the managed fleet) | A workstation among 160 covered peers. Likely a missed enrolment rather than a decision. |
| `EXP-3BRRPB4` | 83,195 | workstation | As above. |
| `EXPM365Analytics401` | 59,480 | M365 analytics server | Handles mail/tenant data; no process-level detection or blocking. |
| `EXP-OPS-46807` | 33,250 | workstation | As above. |
| `WIN11-MSSQL01` | 33,219 | SQL server | A database host with no EDR. Ransomware staging and credential dumping go unseen. |
| `Windows-Test-Device` | 32,869 | test machine | Possibly deliberate. Worth confirming — a test device is often where unknown software runs. |
| `ASIEM-VICTIM` | 28,061 | lab / target machine, by name | Probably deliberate. Confirm it is isolated. |
| `WIN10-MSSQL02` | 27,193 | SQL server | As `WIN11-MSSQL01`. |
| `CPC-alexa-GTFXM` | 24,618 | Cloud PC (Windows 365) | Cloud PCs need enrolment in their own image; easy to miss. |
| `expgrafana001.int.expertware.net` | 23,904 | monitoring server | Holds dashboards and often credentials to other systems. |
| `EXP-OPS-58255` | 17,890 | workstation | As above. |
| `STANDALONE02` | 15,551 | standalone server | "Standalone" usually means outside domain management, so also outside whatever deploys the sensor. |
| `SERVER01` | 11,578 | server | Unidentified; worth naming properly. |
| `EXP-OPS-81958` | 5,097 | workstation | As above. |
| `LABORATORVM001` | 4,459 | lab VM | Possibly deliberate. |
| `EXP-OPS-66927` | 4,339 | workstation | As above. |
| `dns1.expertware.net` | 1,814 | DNS server | DNS is how most malware reaches its operator. No EDR on the resolver itself. |

### Grouped for a decision

- **Act now (3):** `DC`, `WIN11-MSSQL01`, `WIN10-MSSQL02` — a domain
  controller and two database servers.
- **Infrastructure, next (3):** `dns1.expertware.net`,
  `expgrafana001.int.expertware.net`, `EXPM365Analytics401`.
- **Probably missed enrolments (6):** the `EXP-*` and `CPC-alexa-GTFXM`
  workstations, which look like the covered fleet and should simply be
  enrolled.
- **Confirm intent (4):** `Windows-Test-Device`, `ASIEM-VICTIM`,
  `LABORATORVM001`, `STANDALONE02`.
- **No action (1):** `wm-c00.siembiot.int`.
- **Name it first (1):** `SERVER01`.

## Two things that are not coverage gaps

**Re-enrolled sensors.** Five hostnames carry two or three Falcon device
records each — 182 records for 175 distinct hostnames. In every case the older
record's last check-in hands straight off to the newer record's first
check-in, which is the signature of a sensor reinstall or a re-imaged machine.
These hosts are covered. They are listed here only because a tool reading
device records naively would either double-count them or report the retired
record and call a live host stale:

| hostname | records | retired enrolment ended | current enrolment began |
|---|---|---|---|
| `exp-3lj1p54` | 2 | 2026-09-29 | 2026-09-29 |
| `exp-4jhpzy2` | 3 | 2026-09-10 | 2026-09-10 |
| `exp-8wc1f14` | 2 | 2026-09-03 | 2026-09-04 |
| `exp-jrtvg63` | 2 | 2026-09-22 | 2026-09-22 |
| `expvpnext001` | 3 | 2026-09-24 | (one record live since 2026-06-08) |

**Stale sensors.** Nine of 182 devices last reported more than 31 days ago,
and ten more between 8 and 30 days. A sensor that has not reported is not a
sensor that saw nothing, so those hosts are covered on paper and may not be
covered in fact. That is a different list and a different fix from this one;
it is worth a look once the nineteen above are resolved.

| last reported | devices |
|---|---|
| within 1 day | 153 |
| 2–7 days | 10 |
| 8–30 days | 10 |
| over 31 days | 9 |

## What was asked of Falcon to produce this

Read-only, through the existing integration credential:

- `GET /devices/queries/devices/v1` (unfiltered) — 182 device ids
- `GET /devices/entities/devices/v2` — the device records, in batches of 100
- the SIEM side is an aggregation on `agent.name` over the last 7 days

No configuration, policy, containment or host state was changed, and no
detection was closed or modified.
