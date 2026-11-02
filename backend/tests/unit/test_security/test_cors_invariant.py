"""Never a non-None `allow_origin_regex` alongside `allow_credentials=True`.

The combination means *any origin matching the pattern may make credentialed
cross-origin requests and read the response*. On 2026-10-15 the live config
had `allow_origin_regex=r"^https?://[A-Za-z0-9\\.\\-]+(:\\d+)?$"` — which
matches every hostname — with `allow_credentials=True`, verified against the
running service:

    OPTIONS /api/detections/correlated-cases   Origin: https://evil.example.test
    → 200, access-control-allow-origin: https://evil.example.test
           access-control-allow-credentials: true

It was latent only because the session cookie is `SameSite=Lax`, which
withholds it from cross-site fetch. Adding TLS would have armed it, because
`Secure` makes `SameSite=None` reachable.

**The invariant holds in EVERY environment, including development.** The
earlier shape of this guard was conditional on `APP_ENV`, which meant it
failed for anyone running in development and would have been answered with a
tolerated-list entry. A guard expected to fail somewhere is already half
dead. So development gets explicit localhost origins in the allow-list
instead of a regex, and the regex is unconditionally absent.
"""
from __future__ import annotations

import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[3] / "app" / "main.py"


def test_main_py_passes_no_allow_origin_regex_at_all():
    """Asserted on the source, because the value is chosen at import time
    from settings and a test importing `app.main` would only ever see this
    process's environment — not every environment the code runs in."""
    src = MAIN.read_text()
    hits = [
        line.strip() for line in src.splitlines()
        if "allow_origin_regex" in line and not line.strip().startswith("#")
    ]
    # Strict: the argument must be absent, or literally `None`. The first
    # version of this assertion accepted any line CONTAINING "None", and the
    # vulnerable line was
    #     allow_origin_regex=... if settings.is_development else None,
    # which contains "None" and passed. A control that cannot fail on the
    # defect it names is not a control.
    allowed = {"allow_origin_regex=None", "allow_origin_regex=None,"}
    offenders = [h for h in hits if h.replace(" ", "") not in allowed]
    assert offenders == [], (
        f"allow_origin_regex is passed something other than a bare None: "
        f"{offenders}. With allow_credentials=True this permits credentialed "
        f"cross-origin reads from every origin the pattern matches. Put "
        f"explicit origins in CORS_ORIGINS instead — including for "
        f"development."
    )


def test_credentials_are_still_allowed_so_the_invariant_is_not_vacuous():
    """If someone removes allow_credentials the test above stops meaning
    anything. Pin both halves."""
    src = MAIN.read_text()
    assert re.search(r"allow_credentials\s*=\s*True", src), (
        "allow_credentials is no longer True — re-read this invariant before "
        "changing it; the pairing is what makes the regex dangerous"
    )


def test_no_environment_branch_reintroduces_a_wildcard():
    """The original defect was `… if settings.is_development else None`.

    A conditional wildcard is the same hole with a narrower blast radius, and
    development is where an analyst's browser and a hostile page can coexist
    just as easily.
    """
    src = MAIN.read_text()
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("#") or "allow_origin" not in s:
            continue
        assert "is_development" not in s and "app_env" not in s, (
            f"CORS origin handling branches on the environment: {s!r}. The "
            f"invariant must hold in every environment."
        )


def test_the_cors_middleware_is_actually_installed():
    """Otherwise all three assertions above pass on a file that configures
    nothing."""
    src = MAIN.read_text()
    assert "CORSMiddleware" in src
    assert "allow_origins" in src
