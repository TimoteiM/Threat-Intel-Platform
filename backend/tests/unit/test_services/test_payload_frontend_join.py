"""The join: does the component read the key the payload actually has?

Fifth instance this week of verifying two halves and not the seam. The
integrations card rendered under "OTHER — Uncategorised tools" while the
payload carried `category: "edr"` — and the payload check and the page check
had each passed on their own.

The cause of THAT instance was staleness, not a key mismatch: the api runs
without `--reload` and the serving process predated the category code by
3h11m. But the class is real and cheap to guard, so this asserts the two
sides against each other rather than each against my expectation.

Deliberately reads the frontend source. A fixture copied by hand is a third
copy of the fact, and this repo has been bitten by hand-written fixtures
before.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

from app.services import integration_status_service as st

FRONTEND = (
    pathlib.Path(__file__).resolve().parents[4]
    / "frontend" / "src" / "app" / "integrations" / "page.tsx"
)


def _tool_payload() -> dict:
    """One real tool entry, built by the same function the route uses."""
    spec = st.catalogue()["falcon"]
    return st.status_of(spec, None, "falcon")


class _Row:
    """A configured tenant_integrations row, enough for status_of."""

    def __init__(self) -> None:
        from datetime import datetime, timezone
        now = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
        self.tool = "falcon"
        self.tenant_id = "c00"
        self.config = {"base_url": "https://api.crowdstrike.com"}
        self.secret_ciphertext = b"x"
        self.secret_set_at = now
        self.configured_by = "someone"
        self.updated_at = now
        self.health = {}
        self.enrichment_status = None
        self.enrichment_checked_at = None
        self.enrichment_reason = None


def _all_branch_keys() -> set[str]:
    """Every key a tool entry can carry, across all three branches.

    The union, not one branch: `config`, `secret_set` and `configured_by`
    exist only once a credential is stored, and the page guards them behind
    `t.configured`. Checking one branch would flag those as drift.
    """
    spec = st.catalogue()["falcon"]
    keys: set[str] = set()
    for payload in (
        st.status_of(spec, None, "falcon"),       # implemented, unconfigured
        st.status_of(None, None, "sentinelone"),  # no connector
        st.status_of(spec, _Row(), "falcon"),     # configured
    ):
        keys |= set(payload)
    return keys


def test_the_payload_has_a_category_at_the_top_level_of_a_tool():
    tool = _tool_payload()
    assert "category" in tool, (
        "the page groups on tool.category; nesting it deeper silently sends "
        "every card to Other"
    )
    assert tool["category"] == "edr"


@pytest.mark.skipif(not FRONTEND.exists(), reason="frontend not checked out")
def test_the_component_reads_that_exact_key_at_that_exact_depth():
    """`t?.category`, not `t?.spec?.category` and not `t?.kind`."""
    src = FRONTEND.read_text()
    reads = set(re.findall(r"\bt\??\.(\w+)", src))
    tool = _tool_payload()

    # The grouping key the component actually dereferences.
    assert "category" in reads, (
        "page.tsx does not read `t.category` anywhere; the payload key and "
        "the component have drifted apart"
    )
    # And every key it reads off a tool must exist in the payload, or it is
    # reading something the API never sends — which renders as a default and
    # looks like data rather than a bug.
    allowed_elsewhere = {
        # Read off other objects that happen to be called `t` in scope.
        "tenant_id", "name", "status", "tool", "map", "length", "filter",
        "slice", "toLowerCase", "cells", "overall",
    }
    every_key = _all_branch_keys()
    unknown = sorted(
        k for k in reads
        if k not in every_key and k not in allowed_elsewhere
    )
    assert unknown == [], (
        f"page.tsx reads keys no tool payload branch carries: {unknown}. "
        f"Union of branch keys: {sorted(every_key)}"
    )


@pytest.mark.skipif(not FRONTEND.exists(), reason="frontend not checked out")
def test_the_grouping_default_is_not_reachable_for_an_implemented_tool():
    """"other" must be a real category, never where a declared tool lands."""
    src = FRONTEND.read_text()
    assert 'String(t?.category || "other")' in src, (
        "the fallback changed; this test pins the shape it falls back FROM"
    )
    for name, spec in st.catalogue().items():
        assert spec.category != "other", (
            f"{name} would render under Other; declare integration_category"
        )


def test_every_payload_branch_carries_the_key():
    """All three status_of branches, since a card can be in any of them.

    The configured branch was the one on screen, but an unconfigured or
    unimplemented tool rendering under Other would be the same bug with a
    different trigger.
    """
    spec = st.catalogue()["falcon"]
    unconfigured = st.status_of(spec, None, "falcon")
    unimplemented = st.status_of(None, None, "sentinelone")
    assert unconfigured["category"] == "edr"
    assert "category" in unimplemented, (
        "a tool with no connector still needs a grouping key or it vanishes "
        "from the grid's headings"
    )
    # Serialisable, because it crosses the wire before the component sees it.
    json.dumps([unconfigured, unimplemented])
