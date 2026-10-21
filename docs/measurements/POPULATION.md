# Whose estate is each corpus? Read this before quoting any figure

Every measurement in this directory has a population, and for most of them
that population is **not a customer**. This file is the one place that says
which is which, so a figure cannot be lifted out of a document and attached
to the wrong estate.

## `c00` is Expertware's own estate

Confirmed 2026-10-21 by asking CrowdStrike, read-only
(`scripts/verify_tenant_ownership.py`), not by reading our configuration back
to ourselves.

| the vendor's answer | value |
|---|---|
| CID | `eed7e41845d04c26b4198f4c85f6216e` — **176 of 176** devices |
| `machine_domain` | `int.expertware.net` 141, `ext.expertware.net` 24, `dev.expertware.net` 10, blank 1 |
| `site_name` | `EXPERTWARE` 141, `Default-First-Site-Name` 34, blank 1 |
| `ou` | every path ends in `ExpertWare` — `Hybrid Joined Devices,Computers,ExpertWare` 123, `Servers,ExpertWare` 27, `Computers,ExpertWare` 19 |

**175 of 176 devices carry an `expertware.net` domain**; the one that carries
none has the same CID and an `ExpertWare` OU. There is no customer estate
mixed into this tenant.

## What that means for the numbers

`c00` is **16,552 of 17,640 alert runs (93.8%)** and **2,118 of 2,526 closed
cases (83.8%)**. So unless a measurement says otherwise, its population is:

> **Expertware's own estate — 176 Falcon-managed devices, one CID, three
> `expertware.net` domains. Not a customer.**

The figures are correctly measured. What was wrong was the label, and the
label is what turns a measurement into a customer report.

## The other tenants

| tenant | what it is | runs | closed cases |
|---|---|---|---|
| `c00` | **Expertware's own estate**, confirmed | 16,552 | 2,118 |
| (unassigned) | 1,045 legacy runs with no tenant; deliberately left unassigned rather than inferred from a self-declared `client` value | 1,045 | 394 |
| `pov` | an Exabeam credential that **cannot be attributed to anyone** — see backlog 47 | 23 | 9 |
| `lin` | likewise unattributable | 20 | 5 |
| `boc` | 1 run | 1 | 0 |

`alert_client` is **not** a discriminator: it is self-declared and says
`unknown` on 17,540 of 17,640 runs.

## How to quote a figure from this directory

1. Name the population in the same sentence as the number. "4.09 identifiers
   per alert **on our own estate**" is a true sentence; "4.09 per alert" in a
   client deck is not.
2. If the figure is going outside Expertware, say which estate it describes
   explicitly. `docs/outbound/` is the highest-risk directory for this,
   because a file's location is how a document inherits an audience it was
   never measured against.
3. If a measurement's population is a mix, say the mix. None of the current
   ones are.

See backlog 45 for the open decision about what `c00` should be called, and
whether it is a tenant at all or a permanent internal estate alongside the
client tenants.
