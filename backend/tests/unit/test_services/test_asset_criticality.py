"""Crown jewels: an explicit table, three states, and a helper that proposes
without ever deciding.

The invariant pinned here is the one standing between the seeding helper and
the feedback shape that made the supersession migration non-idempotent: a
helper that reads its own output must not be able to escalate it.
"""

from __future__ import annotations

import pytest

from app.services.asset_criticality_service import (
    CONFIRMED,
    CROWN_JEWEL,
    HIGH,
    NORMAL,
    PROPOSED,
    dclist_targets,
    propose_from_behaviour,
    propose_from_name,
)


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def scalars(self):
        return self

    def first(self):
        return self._row


class _FakeSession:
    """Enough of a session to exercise propose/confirm without a database."""

    def __init__(self, existing=None):
        self.existing = existing
        self.added = []

    async def execute(self, *_a, **_k):
        return _FakeResult(self.existing)

    def add(self, row):
        self.added.append(row)


@pytest.mark.asyncio
async def test_propose_never_overwrites_a_confirmation():
    """The helper reads `asset_criticality` to skip hosts already classified.
    That is reading its own output, which is safe only while it cannot change
    what it reads. Without this test that is a property of the code rather
    than a pinned invariant — and a migration that consumed its own output as
    input is exactly what cost a run to untangle."""
    from app.models.database import AssetCriticality
    from app.services.asset_criticality_service import propose

    confirmed = AssetCriticality(
        host="exp-dc-01", tier=HIGH, state=CONFIRMED,
        reason="A person decided this.", set_by="analyst",
    )
    db = _FakeSession(existing=confirmed)
    returned = await propose(
        db, host="exp-dc-01", tier=CROWN_JEWEL, reason="a name pattern matched"
    )
    assert returned is confirmed
    assert confirmed.state == CONFIRMED, "a proposal must not reopen a decision"
    assert confirmed.tier == HIGH, "a proposal must not change a confirmed tier"
    assert confirmed.reason == "A person decided this."
    assert confirmed.set_by == "analyst"
    assert db.added == [], "nothing new is written for a host already classified"


@pytest.mark.asyncio
async def test_propose_does_not_escalate_an_existing_proposal_either():
    """Re-running the helper must be a no-op, or its own output becomes its
    input and the tier ratchets upward every run."""
    from app.models.database import AssetCriticality
    from app.services.asset_criticality_service import propose

    existing = AssetCriticality(
        host="lab-01", tier=NORMAL, state=PROPOSED, reason="first pass",
        set_by="seeding helper",
    )
    db = _FakeSession(existing=existing)
    await propose(db, host="lab-01", tier=CROWN_JEWEL, reason="second pass")
    assert existing.tier == NORMAL
    assert existing.reason == "first pass"
    assert db.added == []


@pytest.mark.asyncio
async def test_only_confirm_can_reach_the_confirmed_state():
    from app.services.asset_criticality_service import confirm

    db = _FakeSession(existing=None)
    row = await confirm(
        db, host="EXP-DC-01.corp.local", tier=CROWN_JEWEL,
        reason="It is the domain controller.", set_by="tudor",
    )
    assert row is not None
    assert row.host == "exp-dc-01", "keyed on the short label, as the graph merges hosts"
    assert row.state == CONFIRMED
    assert row.set_by == "tudor"


def test_a_name_pattern_cannot_match_inside_a_longer_word():
    """`EXP-DC-01` matches and `EXP-DCOM-02` must not. A pattern anchored
    loosely fails silently in both directions, which is why a name can only
    ever produce a proposal."""
    assert propose_from_name("EXP-DC-01") is not None
    assert propose_from_name("EXP-DCOM-02") is None
    assert propose_from_name("EXP-SRV-09") is None, (
        "a controller named like a server matches nothing, which is exactly "
        "why the table is explicit rather than inferred"
    )


def test_a_name_proposal_says_it_is_only_about_a_string():
    tier, reason = propose_from_name("exp-dc-02")
    assert tier == CROWN_JEWEL
    assert "evidence about a string, not about a role" in reason


def test_behaviour_outranks_a_name_and_says_what_was_observed():
    found = propose_from_behaviour(host="anything", observed=["remote_exec_via"])
    assert found is not None
    tier, reason = found
    assert tier == HIGH
    assert "administrative share" in reason
    assert propose_from_behaviour(host="anything", observed=["ran_as"]) is None


def test_dclist_reports_the_domain_it_names_not_a_host():
    """`nltest /dclist:corp.local` names a domain. Resolving that to machines
    needs directory data this platform does not ingest."""
    assert dclist_targets("nltest /dclist:corp.local") == ["corp.local"]
    assert dclist_targets("whoami /all") == []
