"""Ask each vendor who its own credential belongs to.

**Not our config read back to itself.** On 2026-10-16 the Falcon tenant this
platform had been analysing as a customer's turned out to be our own estate,
and nothing in our configuration could have said so — the only authority on
"whose tenant is this" is the vendor.

Read-only throughout. No `configure()`, no writes, no health stamping: a
repro against a live credential row once overwrote a real secret and then
deleted it. Credentials are never printed; where a credential has to be
compared across tenants, a truncated SHA-256 of its key id is used, which
answers "is this the same key" without carrying the key.
"""
from __future__ import annotations

import hashlib
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services import tenant_scope

#: Hostname suffixes that are OUR estate, not a client's. If a vendor answers
#: with one of these, the credential is pointed at us.
OUR_OWN = ("expertware.net", "int.expertware.net", "siembiot.int", "siembiot.eu")


def _fingerprint(value: str) -> str:
    """Enough to compare two credentials, not enough to be one."""
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:12]


def configured_rows() -> list[dict]:
    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        conn.execute(text("SELECT set_config(:k, :v, true)"),
                     {"k": tenant_scope.SCOPE_SETTING,
                      "v": tenant_scope.ALL_TENANTS_SENTINEL})
        return [
            {"tenant_id": r.tenant_id, "tool": r.tool, "config": r.config or {}}
            for r in conn.execute(text("""
                SELECT tenant_id, tool, config FROM tenant_integrations
                WHERE secret_ciphertext IS NOT NULL
                ORDER BY tenant_id, tool"""))
        ]


def open_credential(tenant_id: str, tool: str):
    from app.services import integration_credential_service as creds

    return creds.open_for_tenant_sync(tenant_id, tool)


# ── CrowdStrike / Falcon ───────────────────────────────────────────────────

def verify_falcon(tenant_id: str, config: dict) -> dict:
    """The vendor's own `cid`, plus what its device records say about the estate.

    `cid` is CrowdStrike's customer identifier — the authoritative answer. The
    device record also carries `machine_domain`, `ou` and `site_name`, which
    is how "whose estate" becomes readable rather than a hex string.

    Both calls are GETs that this platform already makes in `lookup_host`.
    """
    import requests

    from app.integrations import falcon_client as fc

    out: dict = {"tenant_id": tenant_id, "tool": "falcon", "identity": {},
                 "error": None, "checkable": True}
    try:
        cred = open_credential(tenant_id, "falcon")
        secrets = getattr(cred, "secrets", None) or {}
        client_id = secrets.get("client_id") or secrets.get("api_key") or ""
        client_secret = secrets.get("client_secret") or secrets.get("api_secret") or ""
        out["credential_fingerprint"] = _fingerprint(client_id)
        base = fc.base_url_for(config)
        out["base_url"] = base

        token = fc.fetch_token(client_id=client_id, client_secret=client_secret,
                               base_url=base)
        headers = {"Authorization": f"Bearer {token.access_token}"}

        ids = (requests.get(f"{base.rstrip('/')}{fc.DEVICES_PATH}",
                            headers=headers, params={"limit": 20}, timeout=30)
               .json() or {}).get("resources") or []
        out["identity"]["devices_sampled"] = len(ids)
        if not ids:
            out["identity"]["note"] = (
                "the credential authenticates but returned no devices, so the "
                "estate cannot be read from device records"
            )
            return out

        recs = (requests.get(f"{base.rstrip('/')}/devices/entities/devices/v2",
                             headers=headers, params={"ids": ids}, timeout=30)
                .json() or {}).get("resources") or []
        cids, domains, ous, sites, suffixes = (set(), set(), set(), set(), set())
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            if rec.get("cid"):
                cids.add(str(rec["cid"]))
            if rec.get("machine_domain"):
                domains.add(str(rec["machine_domain"]).lower())
            if rec.get("ou"):
                ous.add(str(rec["ou"]) if not isinstance(rec["ou"], list)
                        else ",".join(map(str, rec["ou"])))
            if rec.get("site_name"):
                sites.add(str(rec["site_name"]))
            host = str(rec.get("hostname") or "")
            if "." in host:
                suffixes.add(host.split(".", 1)[1].lower())
        out["identity"].update({
            "cid": sorted(cids),
            "machine_domain": sorted(domains),
            "ou": sorted(ous),
            "site_name": sorted(sites),
            "dns_suffixes": sorted(suffixes),
            "devices_described": len(recs),
        })
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {str(exc)[:140]}"
    return out


# ── Exabeam ───────────────────────────────────────────────────────────────

def verify_exabeam(tenant_id: str, config: dict) -> dict:
    """Whatever identity Exabeam's own API exposes for this credential.

    The search API is the only contract this platform has evidence for. If
    nothing in it names the tenant, that is reported as **not checkable** —
    which is a different answer from "verified", and the point of the
    exercise is to keep them apart.
    """
    out: dict = {"tenant_id": tenant_id, "tool": "exabeam", "identity": {},
                 "error": None, "checkable": False}
    try:
        from app.integrations import exabeam_client as ec

        cred = open_credential(tenant_id, "exabeam")
        secrets = getattr(cred, "secrets", None) or {}
        client_id = secrets.get("client_id") or ""
        client_secret = secrets.get("client_secret") or ""
        out["credential_fingerprint"] = _fingerprint(client_id)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        out["base_url"] = base
        out["identity"]["config_fields_present"] = sorted(config.keys())
        if not base or not client_id:
            out["error"] = "no base_url or client_id configured"
            return out

        # The token exchange is the only authenticated call with a documented
        # contract here. Its NON-SECRET fields are the only place an identity
        # could appear.
        import requests

        resp = requests.post(
            f"{base}{ec.TOKEN_PATH}",
            json={"client_id": client_id, "client_secret": client_secret,
                  "grant_type": "client_credentials"},
            headers={"Content-Type": "application/json"}, timeout=30)
        out["identity"]["token_http"] = resp.status_code
        if resp.status_code >= 400:
            out["error"] = f"token exchange returned HTTP {resp.status_code}"
            return out
        body = resp.json() if resp.content else {}
        # Keys only, minus anything that is or could be the token itself.
        secretish = {"access_token", "token", "refresh_token", "id_token"}
        out["identity"]["token_response_fields"] = sorted(
            k for k in (body or {}) if k not in secretish)
        for key in ("scope", "tenant", "tenant_id", "instance", "site",
                    "customer", "organisation", "organization", "aud", "iss"):
            if body.get(key):
                out["identity"][f"token.{key}"] = str(body[key])[:120]
                out["checkable"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {str(exc)[:140]}"
    return out


VERIFIERS = {"falcon": verify_falcon, "exabeam": verify_exabeam}


def main() -> None:
    rows = configured_rows()
    print(f"{len(rows)} configured integration(s) with a stored credential\n")

    results = []
    for row in rows:
        fn = VERIFIERS.get(row["tool"])
        if fn is None:
            results.append({"tenant_id": row["tenant_id"], "tool": row["tool"],
                            "identity": {}, "error": "no verifier for this tool",
                            "checkable": False})
            continue
        print(f"  … asking {row['tool']} for tenant {row['tenant_id']}",
              file=sys.stderr)
        results.append(fn(row["tenant_id"], row["config"]))

    print("=" * 78)
    print("WHAT THE VENDOR SAYS EACH CREDENTIAL BELONGS TO")
    print("=" * 78)
    for r in results:
        print(f"\n  our tenant_id : {r['tenant_id']}")
        print(f"  platform      : {r['tool']}")
        print(f"  base_url      : {r.get('base_url', '(none)')}")
        print(f"  credential    : fingerprint {r.get('credential_fingerprint', '?')}"
              f"  (SHA-256 prefix of the key id, not the key)")
        if r.get("error"):
            print(f"  VENDOR SAID   : ERROR — {r['error']}")
        elif not r["identity"]:
            print("  VENDOR SAID   : nothing")
        else:
            for k, v in r["identity"].items():
                print(f"      {k:26} {v}")
        print(f"  checkable     : {r['checkable']}")

    # ── the three flags ──
    print("\n" + "=" * 78)
    print("FLAGS")
    print("=" * 78)

    own = [r for r in results
           if any(any(s.endswith(o) or s == o for o in OUR_OWN)
                  for s in (r["identity"].get("dns_suffixes") or [])
                  ) or any(any(d.endswith(o) for o in OUR_OWN)
                           for d in (r["identity"].get("machine_domain") or []))]
    print(f"\n  1. vendor's answer is OUR OWN ESTATE: {len(own)}")
    for r in own:
        print(f"       {r['tenant_id']}/{r['tool']}: "
              f"domains={r['identity'].get('machine_domain')} "
              f"suffixes={r['identity'].get('dns_suffixes')}")
    if not own:
        print("       none")

    by_cred: dict[str, list[str]] = defaultdict(list)
    for r in results:
        fp = r.get("credential_fingerprint")
        if fp:
            by_cred[fp].append(f"{r['tenant_id']}/{r['tool']}")
    shared = {fp: names for fp, names in by_cred.items() if len(names) > 1}
    print(f"\n  2. one credential answering for MORE THAN ONE tenant: {len(shared)}")
    for fp, names in shared.items():
        print(f"       fingerprint {fp}: {', '.join(names)}")
    if not shared:
        print("       none")

    unchecked = [r for r in results if not r["checkable"]]
    print(f"\n  3. NO VENDOR IDENTITY to check — verification not possible, "
          f"not passed: {len(unchecked)}")
    for r in unchecked:
        print(f"       {r['tenant_id']}/{r['tool']}: "
              f"{r.get('error') or 'the API exposes no tenant identity'}")
    if not unchecked:
        print("       none")


if __name__ == "__main__":
    main()
