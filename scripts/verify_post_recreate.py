"""Confirm a recreate did what was intended. Two checks, three layers each.

Run after `docker compose up -d --force-recreate`.

**Check 1 is the subtle one.** "The Microsoft keys are absent from the
containers" is true in TWO different worlds, and only one of them is the
intended outcome:

  world A  the lines were deleted from .env            <- intended
  world B  the lines are still there and the parser dropped them again

A container-only check cannot tell them apart — which is the whole mistake
this project made about these keys once already. So absence is asserted at
**three layers that must all agree**:

  1. .env itself has no such assignment, under ANY whitespace variant
  2. `docker compose config` does not resolve one for any service
     (it TRIMS names, so a whitespace-mangled key still shows up here —
     this is the layer that separates world A from world B)
  3. no container has the variable

Layer 2 is the discriminator. If 1 and 3 are clean but 2 still lists the key,
the line is still in the file and something downstream is hiding it.

**Check 2** proves the callback signature is live by calling the real
function inside the running worker, not by reading configuration. It prints a
boolean, the format, and a FINGERPRINT of the loaded secret — never the secret
and never a signature, which would be an oracle over a known body.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
KEYS = ("MicrosoftClientId", "MicrosoftClientSecret", "MicrosoftTenantId")
SERVICES = ("api", "worker", "beat")
#: Printed when the secret was installed. Both sides compare this, never the
#: value. If the container's fingerprint differs, it loaded a different secret.
EXPECTED_FINGERPRINT = "8bb4ba6540fdc641"


def run(args: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(args, cwd=str(ROOT), capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception as exc:  # noqa: BLE001
        return 1, f"__ERROR__ {type(exc).__name__}: {exc}"


def check_keys_gone(env_path: pathlib.Path | None = None) -> bool:
    print("CHECK 1 — the three Microsoft keys are gone, at three layers")
    print("=" * 70)
    ok = True

    # Layer 1: the file. `env_path` exists so the failure path can be proven
    # against a fixture: by the time this script was written the real keys were
    # already deleted, so running it on .env could only ever show a pass, and
    # a check only ever observed passing is not known to be able to fail.
    text = (env_path or ENV).read_text(errors="replace")
    in_file = []
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        if line.partition("=")[0].strip() in KEYS:
            in_file.append(line.partition("=")[0].strip())
    print(f"  [1] .env assignments found      : "
          f"{in_file if in_file else 'NONE  ok'}")
    if in_file:
        ok = False

    # Layer 2: THE DISCRIMINATOR. compose trims names, so a whitespace-mangled
    # key is still visible here. Clean here means the line is really gone.
    rc, out = run(["docker", "compose", "config", "--format", "json"])
    if rc != 0 or out.startswith("__ERROR__"):
        print("  [2] docker compose config       : COULD NOT READ — not agreement")
        ok = False
    else:
        try:
            cfg = json.loads(out)
        except Exception:  # noqa: BLE001
            print("  [2] docker compose config       : UNPARSEABLE — not agreement")
            return False
        seen = set()
        for svc in SERVICES:
            env = (cfg.get("services", {}).get(svc, {}) or {}).get("environment") or {}
            names = set(env.keys()) if isinstance(env, dict) else {
                str(e).split("=", 1)[0] for e in env}
            seen |= {n for n in names if n in KEYS}
        print(f"  [2] compose-resolved (trims!)   : "
              f"{sorted(seen) if seen else 'NONE  ok'}   <- discriminator")
        if seen:
            ok = False

    # Layer 3: the running containers.
    for svc in SERVICES:
        rc, out = run(["docker", "compose", "exec", "-T", svc, "sh", "-lc",
                       "env | cut -d= -f1 | grep -i -c '^microsoft' || true"])
        n = (out or "").strip().splitlines()[-1] if out.strip() else "?"
        if rc != 0 or out.startswith("__ERROR__"):
            print(f"  [3] {svc:6s} container           : UNREACHABLE — not agreement")
            ok = False
        else:
            print(f"  [3] {svc:6s} container           : "
                  f"{n} matching var(s)  {'ok' if n == '0' else 'STILL PRESENT'}")
            if n != "0":
                ok = False

    print(f"\n  VERDICT: {'the delete took' if ok else 'NOT CLEAN — see above'}")
    if ok:
        print("  All three layers agree, so this is world A (deleted) and not")
        print("  world B (still in the file, dropped downstream).")
    return ok


def check_signature_live() -> bool:
    print("\nCHECK 2 — the callback signature is active in the worker")
    print("=" * 70)
    probe = (
        "import hashlib, os;"
        "from app.services.alert_ingest_service import sign_payload;"
        "s = sign_payload(b'liveness-probe');"
        "sec = os.environ.get('ALERT_CALLBACK_SECRET') or '';"
        "print('present', bool(sec));"
        "print('fingerprint', hashlib.sha256(sec.encode()).hexdigest()[:16] if sec else 'none');"
        "print('returns', 'SIGNATURE' if s else 'None');"
        "print('format_ok', bool(s and s.startswith('sha256=') and len(s) == 71))"
    )
    rc, out = run(["docker", "compose", "exec", "-T", "-e", "PYTHONPATH=/app",
                   "worker", "python", "-c", probe], timeout=180)
    if rc != 0 or out.startswith("__ERROR__"):
        print("  COULD NOT RUN the probe inside the worker — not agreement")
        print(f"  {out.strip()[:200]}")
        return False
    vals = {}
    for line in out.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) == 2:
            vals[parts[0]] = parts[1]
    print(f"  secret present in worker : {vals.get('present')}")
    print(f"  secret fingerprint       : {vals.get('fingerprint')} "
          f"(expected {EXPECTED_FINGERPRINT})")
    print(f"  sign_payload returns     : {vals.get('returns')}")
    print(f"  format sha256=<64 hex>   : {vals.get('format_ok')}")
    ok = (vals.get("present") == "True"
          and vals.get("returns") == "SIGNATURE"
          and vals.get("format_ok") == "True"
          and vals.get("fingerprint") == EXPECTED_FINGERPRINT)
    print(f"\n  VERDICT: {'signature is live' if ok else 'NOT LIVE — see above'}")
    if vals.get("fingerprint") not in (EXPECTED_FINGERPRINT, None, "none"):
        print("  The fingerprint does not match: the worker loaded a DIFFERENT")
        print("  secret than the one generated. The receiver would reject.")
    print("  Note: neither the secret nor any signature is printed — a")
    print("  signature over a known body is an oracle.")
    return ok


def main() -> int:
    fixtures = [a for a in sys.argv[1:] if not a.startswith("-")]
    if fixtures:
        # Control mode: layer 1 only, against a fixture, to prove the check
        # can fail. Layers 2 and 3 read the real system and are not faked.
        print(f"(CONTROL MODE: layer 1 against {fixtures[0]})\n")
        return 0 if check_keys_gone(pathlib.Path(fixtures[0])) else 1
    a = check_keys_gone()
    b = check_signature_live()
    print("\n" + "=" * 70)
    print(f"keys gone: {'YES' if a else 'NO'}   signature live: {'YES' if b else 'NO'}")
    return 0 if (a and b) else 1


if __name__ == "__main__":
    sys.exit(main())
