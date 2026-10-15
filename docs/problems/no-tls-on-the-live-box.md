# No TLS on the live box — analyst credentials and tenant data in cleartext

> ## ⛔ SEQUENCING CONSTRAINT — read before starting either piece of work
>
> **CORS closes before or with TLS. Never after.**
>
> Adding TLS means setting `session_cookie_secure=True`. The moment `Secure`
> is available, `SameSite=None` becomes reachable — and `SameSite=Lax` is the
> *only* reason the wildcard `allow_origin_regex` + `allow_credentials=True`
> is latent rather than exploitable today. **The TLS remediation is what arms
> the CORS wildcard.**
>
> Severity read alone says fix TLS first: cleartext credentials outrank a
> latent misconfiguration. Doing so without closing CORS in the same change
> converts the latent finding into a live one on a platform holding customer
> alert data.
>
> Order: **1. real CORS origins → 2. `APP_ENV=production` → 3. TLS.**

Established 2026-10-15, by measurement rather than assumption. **Scoped, not
fixed.** This outranks the CORS finding in
[app-env-is-development-in-production.md](app-env-is-development-in-production.md),
and that document explains why the two must be sequenced together.

## What listens, and what does not

| | |
|---|---|
| listeners on this host | `0.0.0.0:3000` (frontend), `0.0.0.0:8000` (api) — **plain HTTP** |
| listeners on 80 / 443 | **none** |
| reverse proxy in `docker-compose.yml` | **none** — no nginx, traefik, caddy, haproxy or ingress service |
| reverse proxy on the host | **none** on 80/443 |
| host | `siem-mon.int.expertware.net`, interfaces `10.45.0.71/24` and `172.16.45.20/24` |

So nothing terminates TLS anywhere in the path that this box can see. Whether
something terminates it *upstream* — a load balancer or firewall outside this
host — **cannot be established from here** and is the one open question; the
frontend is published on `0.0.0.0`, so even if an upstream proxy exists, the
plain-HTTP port is reachable directly by anything that can route to the host.

## What crosses the network in cleartext

1. **The login POST.** `POST /api/auth/login` carries the analyst's username
   and password over plain HTTP.
2. **The session cookie, on every subsequent request.** `tip_session`,
   `HttpOnly`, `SameSite=Lax`, **`Secure=false`**, 12-hour lifetime. Anyone
   positioned on the network path can read it and impersonate that analyst
   for the remainder of its life, with no credential needed.
3. **Tenant alert content in responses** — alert bodies, host names, account
   names, case narratives.
4. **API keys**, when a machine caller uses `Authorization: Bearer tip_…` or
   `X-API-Key` against port 8000. The two observed ingest callers
   (`172.23.10.16`, `172.20.30.35`) authenticate this way.

A 12-hour bearer cookie in cleartext is the sharpest item: it is a
replayable credential, it needs no interaction from the victim, and nothing
on the platform would record the replay as anything other than normal use.

## Remediation options, with costs

### A. Reverse proxy on this host, terminating TLS

nginx or Caddy as a compose service on 443, proxying to the frontend; the api
published only on the docker network rather than `0.0.0.0:8000`.

* **Cost:** one new service, a certificate, and the `INGEST_CIDRS` firewall
  rules re-pointed at 443. The ingest callers must move to HTTPS, which needs
  coordination with whoever runs them — they are outside this repository.
* **Also required:** `session_cookie_secure=True`, and the CORS wildcard
  closed **first** (see the coupling note in the other document).
* Caddy obtains and renews certificates itself for a resolvable name;
  `siem-mon.int.expertware.net` is internal, so this likely means an internal
  CA or a long-lived internal certificate rather than ACME.

### B. TLS terminated upstream, this box left plain

Acceptable **only** if the plain port is unreachable from anywhere but the
proxy — which it is not today, since both ports bind `0.0.0.0`.

* **Cost:** binding the published ports to a single interface or to loopback,
  plus host firewall rules; plus establishing that the upstream exists, which
  is the open question above.
* **Risk:** this is the option that looks done while leaving `:3000` and
  `:8000` open on the LAN. If chosen, the verification is a connection
  attempt from another host on `10.45.0.0/24`, not a configuration review.

### C. TLS inside the compose network as well

Full end-to-end, api included.

* **Cost:** certificates for service-to-service traffic and the client
  changes to trust them; disproportionate while A or B is missing, and the
  log store already shows how much work an internal CA is — the OpenSearch CA
  took until 2026-09-24 to resolve.

## Recommendation, for a decision rather than for action today

**A**, with the ports rebound so the plain ones are not reachable, and
`session_cookie_secure=True` in the same change. **B** only with the
interface-binding work done, because without it B is indistinguishable from
doing nothing from an attacker's position.

Either way the sequence from the other document holds: **CORS origins first,
`APP_ENV=production` second, TLS third** — because the TLS step is what makes
the CORS wildcard exploitable.

## Not covered here

* Whether an upstream proxy already terminates TLS. Needs establishing, and
  it changes which option applies but not the fact that the plain ports are
  open on the LAN.
* The ingest callers' own TLS support. They are outside this repository;
  moving them is coordination, not code.
