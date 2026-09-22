"""Live CAPE smoke test. Disabled unless explicitly asked for.

Runs one request: GET /apiv2/cuckoo/status/. It never uploads a sample, never
creates a task, and never touches the VM pool — there is no safe way to make
"detonate something" part of a routine test run, so it is not here.

    CAPE_SMOKE_TEST=1 pytest tests/integration/test_cape_smoke.py -v

It reads the same CAPE_* environment the application does, so a pass proves
the deployment's own configuration works: the reverse proxy is reachable from
this host, TLS verifies, and the token is accepted.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CAPE_SMOKE_TEST", "").strip().lower() not in {"1", "true", "yes"},
    reason="Live CAPE smoke test: set CAPE_SMOKE_TEST=1 to run it.",
)


def test_cape_status_is_reachable_and_authenticated():
    from app.config import get_settings
    from app.services import cape_client as cape

    settings = get_settings()
    if not settings.cape_configured:
        pytest.skip("CAPE_ENABLED, CAPE_API_BASE_URL and CAPE_API_TOKEN must all be set.")

    with cape.CapeClient(settings=settings) as client:
        status = client.status()

    assert status.reachable is True
    print(f"\nCAPE version      : {status.version}")
    print(f"machines available: {status.machines_available}/{status.machines_total}")
    print(f"tasks             : {status.tasks}")

    # The documented expectation for this deployment: six Windows x64 guests,
    # all free when the pool is idle. A lower number is not a failure — a task
    # may legitimately be running — so this reports rather than asserts.
    if status.machines_total is not None and status.machines_total != 6:
        print(f"NOTE: expected 6 machines, CAPE reported {status.machines_total}")


def test_an_anonymous_request_is_rejected():
    """The other half of the documented check: no token must mean 401."""
    import httpx

    from app.config import get_settings

    settings = get_settings()
    if not settings.cape_configured:
        pytest.skip("CAPE is not configured.")

    with httpx.Client(verify=settings.cape_tls_verify, follow_redirects=False, timeout=15) as client:
        response = client.get(f"{settings.cape_base_url}/cuckoo/status/")

    assert response.status_code == 401, (
        f"An unauthenticated CAPE request returned {response.status_code}, not 401. "
        "The API is not requiring a token."
    )
