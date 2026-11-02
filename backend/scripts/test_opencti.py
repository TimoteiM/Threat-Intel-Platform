"""
OpenCTI connectivity diagnostic.

Run from inside the worker/api container:
    python scripts/test_opencti.py [optional-search-term]

Example:
    python scripts/test_opencti.py cmmxhurildiigqghlryq.com
"""

import os
import sys
import json
import time
import socket
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# ── Load .env exactly as config.py does ─────────────────────────────────────
try:
    from dotenv import load_dotenv
    _backend_dir = Path(__file__).resolve().parent.parent   # /app
    for candidate in [_backend_dir / ".env", _backend_dir.parent / ".env"]:
        if candidate.exists():
            load_dotenv(candidate, override=False)
            print(f"[env] Loaded: {candidate}")
            break
    else:
        print("[env] No .env file found — using process environment only")
except ImportError:
    print("[env] python-dotenv not available — using process environment only")

try:
    import requests
except ImportError:
    print("ERROR: requests not installed")
    sys.exit(1)

# ── Config ───────────────────────────────────────────────────────────────────
API_URL   = (os.getenv("OPENCTI_API_URL") or "").rstrip("/")
API_KEY   = (os.getenv("OPENCTI_API_KEY") or "").strip()
VERIFY    = os.getenv("OPENCTI_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
TIMEOUT   = 10
TERM      = sys.argv[1] if len(sys.argv) > 1 else "test"

print()
print("=" * 60)
print("OpenCTI Connectivity Diagnostic")
print("=" * 60)
print(f"  API_URL    : {API_URL or '(not set)'}")
print(f"  API_KEY    : {API_KEY[:8]}...{API_KEY[-4:] if len(API_KEY) > 12 else '(short/empty)'}" if API_KEY else "  API_KEY    : (not set)")
print(f"  VERIFY_SSL : {VERIFY}")
print(f"  TIMEOUT    : {TIMEOUT}s")
print(f"  Search term: {TERM}")
print()

if not API_URL or not API_KEY:
    print("FAIL: OPENCTI_API_URL or OPENCTI_API_KEY not set.")
    print("      Check backend/.env has both variables defined.")
    sys.exit(1)

from urllib.parse import urlparse
parsed  = urlparse(API_URL)
host    = parsed.hostname or API_URL
port    = parsed.port or (443 if parsed.scheme == "https" else 80)
endpoint = f"{API_URL}/graphql"
headers  = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

# ── Step 1: DNS resolution ────────────────────────────────────────────────────
print("[1] DNS resolution ...")
try:
    ip = socket.gethostbyname(host)
    print(f"    OK — {host} → {ip}")
except socket.gaierror as e:
    print(f"    FAIL: cannot resolve '{host}': {e}")
    print("    The container cannot resolve this hostname.")
    print("    Add it to /etc/hosts or use an IP address in OPENCTI_API_URL.")
    sys.exit(1)
print()

# ── Step 2: TCP port reachability ─────────────────────────────────────────────
print(f"[2] TCP connectivity to {host}:{port} ...")
t0 = time.monotonic()
try:
    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    sock.close()
    elapsed = int((time.monotonic() - t0) * 1000)
    print(f"    OK — port {port} reachable ({elapsed}ms)")
except Exception as e:
    elapsed = int((time.monotonic() - t0) * 1000)
    print(f"    FAIL ({elapsed}ms): {type(e).__name__}: {e}")
    print("    Container cannot reach the OpenCTI port.")
    print("    Check firewall rules or VPN requirements.")
    sys.exit(1)
print()

# ── Step 3: GraphQL ping ──────────────────────────────────────────────────────
print("[3] GraphQL ping (POST /graphql) ...")
t0 = time.monotonic()
try:
    r = requests.post(
        endpoint, headers=headers,
        json={"query": "{ __typename }"},
        timeout=TIMEOUT, verify=VERIFY,
    )
    elapsed = int((time.monotonic() - t0) * 1000)
    print(f"    HTTP {r.status_code} ({elapsed}ms)")
    if r.status_code == 401:
        print("    FAIL: 401 Unauthorized — OPENCTI_API_KEY is invalid or expired")
        sys.exit(1)
    if r.status_code == 403:
        print("    FAIL: 403 Forbidden — token lacks permissions")
        sys.exit(1)
    if r.status_code != 200:
        print(f"    FAIL: unexpected status. Body: {r.text[:400]}")
        sys.exit(1)
    data = r.json()
    if data.get("errors"):
        print(f"    GraphQL error: {data['errors']}")
    else:
        print(f"    OK — GraphQL: {data}")
except requests.exceptions.SSLError as e:
    print(f"    SSL FAIL: {e}")
    print("    Set OPENCTI_VERIFY_SSL=false in backend/.env for self-signed certs")
    sys.exit(1)
except Exception as e:
    elapsed = int((time.monotonic() - t0) * 1000)
    print(f"    FAIL ({elapsed}ms): {type(e).__name__}: {e}")
    sys.exit(1)
print()

# ── Step 4: search query ──────────────────────────────────────────────────────
print(f"[4] stixCyberObservables search='{TERM}' ...")
t0 = time.monotonic()
try:
    r = requests.post(
        endpoint, headers=headers,
        json={"query": """
query($search:String,$first:Int){
  stixCyberObservables(search:$search,first:$first){
    edges{node{id entity_type observable_value x_opencti_score}}
  }
}""", "variables": {"search": TERM, "first": 10}},
        timeout=TIMEOUT, verify=VERIFY,
    )
    elapsed = int((time.monotonic() - t0) * 1000)
    data = r.json()
    if data.get("errors"):
        print(f"    GraphQL errors: {data['errors'][0].get('message','')}")
    else:
        edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
        print(f"    {len(edges)} result(s) ({elapsed}ms)")
        for e in edges:
            n = e["node"]
            print(f"      [{n.get('entity_type')}] {n.get('observable_value')}  score={n.get('x_opencti_score')}")
except Exception as e:
    print(f"    FAIL: {type(e).__name__}: {e}")
print()

# ── Step 5: v5 filter ─────────────────────────────────────────────────────────
print(f"[5] v5 filter (value contains '{TERM}') ...")
t0 = time.monotonic()
try:
    r = requests.post(
        endpoint, headers=headers,
        json={"query": """
query($filters:[StixCyberObservablesFiltering],$first:Int){
  stixCyberObservables(filters:$filters,first:$first){
    edges{node{id entity_type observable_value x_opencti_score}}
  }
}""", "variables": {
            "first": 10,
            "filters": [{"key": "value", "values": [TERM], "operator": "contains"}],
        }},
        timeout=TIMEOUT, verify=VERIFY,
    )
    elapsed = int((time.monotonic() - t0) * 1000)
    data = r.json()
    if data.get("errors"):
        print(f"    GraphQL errors: {data['errors'][0].get('message','')} ({elapsed}ms)")
    else:
        edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
        print(f"    {len(edges)} result(s) ({elapsed}ms)")
        for e in edges:
            n = e["node"]
            print(f"      [{n.get('entity_type')}] {n.get('observable_value')}")
except Exception as e:
    print(f"    FAIL: {type(e).__name__}: {e}")
print()

# ── Step 6: v6 FilterGroup ────────────────────────────────────────────────────
print(f"[6] v6 FilterGroup (value contains '{TERM}') ...")
t0 = time.monotonic()
try:
    r = requests.post(
        endpoint, headers=headers,
        json={"query": """
query($filters:FilterGroup,$first:Int){
  stixCyberObservables(filters:$filters,first:$first){
    edges{node{id entity_type observable_value x_opencti_score}}
  }
}""", "variables": {
            "first": 10,
            "filters": {
                "mode": "and",
                "filters": [{"key": ["value"], "values": [TERM], "operator": "contains", "mode": "or"}],
                "filterGroups": [],
            },
        }},
        timeout=TIMEOUT, verify=VERIFY,
    )
    elapsed = int((time.monotonic() - t0) * 1000)
    data = r.json()
    if data.get("errors"):
        print(f"    GraphQL errors: {data['errors'][0].get('message','')} ({elapsed}ms)")
    else:
        edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
        print(f"    {len(edges)} result(s) ({elapsed}ms)")
        for e in edges:
            n = e["node"]
            print(f"      [{n.get('entity_type')}] {n.get('observable_value')}")
except Exception as e:
    print(f"    FAIL: {type(e).__name__}: {e}")
print()
print("=" * 60)
print("Diagnostic complete. Share the full output above.")
