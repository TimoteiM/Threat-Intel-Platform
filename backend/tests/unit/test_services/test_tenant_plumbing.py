"""The tenant must reach every collector path, or none of them.

Written before the plumbing. The dangerous direction is not "the tenant does
not arrive" — Falcon already records an absence and makes no call for that.
It is the two failures that look like success:

  * a tenant reaching the inline path and silently not the spawned one, so
    the same alert enriches or does not depending on which branch the
    indicator took;
  * `None` arriving as `""`, which is a tenant-shaped value that no tenant
    owns — absence turned into a value, and the credential lookup would then
    fail as "not configured for ''" rather than "nobody asked".
"""
from __future__ import annotations

import inspect

from app.services import alert_body_investigation_service as abis
from app.services import alert_investigation_spawn_service as spawn


def test_the_inline_collector_runner_accepts_a_tenant():
    sig = inspect.signature(abis._run_collector)
    assert "tenant_id" in sig.parameters, (
        "_run_collector instantiates the collector, so it is the only place "
        "that can put the tenant in external_context"
    )


def test_both_paths_accept_a_tenant_or_the_feature_is_half_built():
    """The user's own standard: some paths and not others is worse than none."""
    inline = inspect.signature(abis._investigate_indicator).parameters
    spawned = inspect.signature(spawn.spawn_investigation).parameters
    assert "tenant_id" in inline, "inline path cannot carry the tenant"
    assert "tenant_id" in spawned, "spawned path cannot carry the tenant"


def test_the_top_level_entry_point_accepts_a_tenant():
    sig = inspect.signature(abis.run_alert_body_investigation)
    assert "tenant_id" in sig.parameters


def test_a_missing_tenant_does_not_become_an_empty_string(monkeypatch):
    """`None` must stay absent, not arrive as a tenant nobody owns."""
    seen: dict[str, object] = {}

    class FakeCollector:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def run(self):
            raise RuntimeError("not reached")

    monkeypatch.setattr(abis, "get_collector", lambda name: FakeCollector)
    abis._run_collector(
        "falcon", value="x", observable_type="ip",
        investigation_ref="ref", timeout=1, tenant_id=None,
    )
    ctx = seen.get("external_context") or {}
    assert "tenant_id" not in ctx, (
        f"absence must not be represented as a value; got {ctx!r}"
    )


def test_a_present_tenant_reaches_the_collector(monkeypatch):
    seen: dict[str, object] = {}

    class FakeCollector:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def run(self):
            raise RuntimeError("stop here")

    monkeypatch.setattr(abis, "get_collector", lambda name: FakeCollector)
    abis._run_collector(
        "falcon", value="x", observable_type="ip",
        investigation_ref="ref", timeout=1, tenant_id="acme",
    )
    ctx = seen.get("external_context") or {}
    assert ctx.get("tenant_id") == "acme"


def test_blank_and_whitespace_tenants_are_treated_as_absent(monkeypatch):
    """A tenant_id of spaces is not a tenant."""
    for bad in ("", "   ", "\t"):
        seen: dict[str, object] = {}

        class FakeCollector:
            def __init__(self, **kwargs):
                seen.update(kwargs)

            def run(self):
                raise RuntimeError("stop")

        monkeypatch.setattr(abis, "get_collector", lambda name: FakeCollector)
        abis._run_collector(
            "falcon", value="x", observable_type="ip",
            investigation_ref="ref", timeout=1, tenant_id=bad,
        )
        ctx = seen.get("external_context") or {}
        assert "tenant_id" not in ctx, f"{bad!r} must read as absent"
