"""The brand-reference signal is off, and the ownership test is inverted.

Measured 2026-10-14 before disabling, grain one row per investigation:

    carried the signal        1,651 of 2,430 rows (67.9%)
    prevalence, suspicious     83.5%   1.23x base -- endogenous, it feeds
                                       http_score and http_score >= 1
                                       reaches suspicious
    prevalence, benign         36.5%   0.54x
    prevalence, MALICIOUS      47.6%   0.70x

`malicious` is reached through clauses that never consult this signal, so
that row is the informative one: among the domains those clauses condemned,
the signal is *below* base rate. A detector pointing backwards.

Removing it moves 833 of 1,651 carriers to a milder class. The five that lose
severity are `googlebot.com`, `www.google.com/bot.html`,
`www.apple.com/go/applebot`, an attack.mitre.org technique page and
`otar.nl` — every one a false positive sitting at malicious/82. The detection
cost of disabling is zero.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.collectors.http_collector import KNOWN_BRANDS

from app import config as _config_mod

# The module object, never the dotted string form.
#
# `monkeypatch.setattr("app.x.y.attr", v)` is resolved by walking
# `getattr(app, "x")` from an already-imported `app`, and in a full-suite run
# that walk raises `AttributeError: module 'app' has no attribute 'x'` while an
# isolated run of this file passes. That is what put these tests in
# docs/testing/tolerated-failures.txt. A module object is already resolved, so
# there is no walk to fail. See docs/testing/writing-tests.md.

BRAND_MARKER = "Third-party brand reference"


def _settings(**over):
    base = dict(brand_reference_signal_enabled=False)
    base.update(over)
    return SimpleNamespace(**base)


# ─── the inversion, stated as a test against the rule's own logic ─────────

@pytest.mark.parametrize("host,brand,should_flag_under_old_rule", [
    # The brand's own estate: the brand word is NOT in the hostname, so the
    # old rule flagged Microsoft's own domains as referencing Microsoft.
    ("live.com", "microsoft", True),
    ("office.com", "microsoft", True),
    ("outlook.com", "microsoft", True),
    ("bing.com", "microsoft", True),
    ("youtube.com", "google", True),
    ("gstatic.com", "google", True),
    ("icloud.com", "apple", True),
    # A lookalike: the brand word IS in the hostname, so the old rule
    # concluded the brand owned it and EXEMPTED it. This is the shape the
    # rule exists to catch, and the condition it used to exclude.
    ("paypal-secure-login-update-account.xyz", "paypal", False),
    ("microsoft-verify-account.tk", "microsoft", False),
    ("apple-id-locked.support", "apple", False),
])
def test_the_old_ownership_test_is_inverted(host, brand, should_flag_under_old_rule):
    """`brand_slug not in own_host_lower` — containment of the brand word
    read as evidence of ownership, when it is evidence of the opposite.

    This asserts the inversion directly rather than describing it, so the
    replacement cannot be built on the same predicate by accident.
    """
    old_rule_flags = brand not in host.lower()
    assert old_rule_flags is should_flag_under_old_rule

    # And the two halves disagree with reality in opposite directions.
    brand_owns_it = host in {
        "live.com", "office.com", "outlook.com", "bing.com",
        "youtube.com", "gstatic.com", "icloud.com",
    }
    if brand_owns_it:
        assert old_rule_flags, "the brand's own domain was not flagged"
    else:
        assert not old_rule_flags, "a lookalike was not exempted"


# ─── the gate ─────────────────────────────────────────────────────────────

def _run_content_analysis(monkeypatch, body: str, host: str, enabled: bool):
    """Drive the real collector's content analysis, nothing reimplemented."""
    from app.collectors import http_collector as mod

    monkeypatch.setattr(mod, "get_settings",
                        lambda: _settings(brand_reference_signal_enabled=enabled),
                        raising=False)
    monkeypatch.setattr(_config_mod, "get_settings",
                        lambda: _settings(brand_reference_signal_enabled=enabled))

    collector = mod.HTTPCollector(
        domain=host,
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=5,
    )
    return collector, mod


def test_the_signal_is_off_by_default():
    from app.config import get_settings

    assert get_settings().brand_reference_signal_enabled is False


def test_the_emit_is_inside_the_gate():
    """A guard that the emit cannot escape, asserted structurally rather
    than by running the collector — because the dangerous direction here is
    the gate being added above code that still runs."""
    import inspect

    from app.collectors import http_collector as mod

    src = inspect.getsource(mod)
    gate = src.index("brand_reference_signal_enabled:")
    emit = src.index(f'f"{BRAND_MARKER}', gate)
    between = src[gate:emit]
    # Nothing may dedent back to the enclosing block between the two.
    assert BRAND_MARKER not in src[:gate], (
        "the signal is emitted somewhere outside the gate"
    )
    assert emit > gate
    assert "\n        evidence.phishing_indicators.append" not in between, (
        "an append at the outer indentation sits between gate and emit"
    )


def test_known_brands_is_still_the_single_list():
    """Not a ninth hand-maintained list. The replacement must reuse this one
    rather than add a brand-ownership list beside it — which is the obvious
    repair and the one that has failed seven times here."""
    assert "microsoft" in KNOWN_BRANDS
    assert len(KNOWN_BRANDS) > 10
    import app.collectors.http_collector as mod
    import inspect

    src = inspect.getsource(mod)
    assert "BRAND_OWNERS" not in src and "OWNED_DOMAINS" not in src, (
        "a brand-ownership list has appeared; the measurements say decide "
        "ownership from evidence already collected, with an explicit "
        "unknown state, rather than from a list"
    )
