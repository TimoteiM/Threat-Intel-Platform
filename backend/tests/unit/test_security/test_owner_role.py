"""The owner role: administrator rights, and an account nobody can remove.

Two halves, and the second is the reason the role exists. An owner has every
right an administrator has. On top of that the account itself is protected —
not by convention, but by refusals that apply to everyone including other
owners and the owner themselves.

The tests that matter most are the ways the protection could be *bypassed*
rather than broken: demote instead of delete, deactivate instead of delete,
reset the password and sign in as them, or simply grant yourself the role.
Each leaves the owner's account technically intact while taking everything
the role was supposed to guarantee.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.api import auth as auth_api
from app.api.auth import (
    ADMIN_ROLES,
    ROLES,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_OWNER,
    has_admin_rights,
)


class Row:
    def __init__(self, role=ROLE_OWNER, row_id="11111111-1111-1111-1111-111111111111"):
        self.role = role
        self.id = row_id
        self.username = f"{role}-account"


OWNER = {"kind": "user", "id": "1", "username": "timotei", "role": ROLE_OWNER}
ADMIN = {"kind": "user", "id": "2", "username": "alex", "role": ROLE_ADMIN}
ANALYST = {"kind": "user", "id": "3", "username": "sam", "role": ROLE_ANALYST}


class Request:
    def __init__(self, identity=None):
        self.state = type("S", (), {"identity": identity})()


# ── Owner has administrator rights ───────────────────────────────────────────


def test_owner_is_part_of_the_role_vocabulary():
    assert ROLE_OWNER in ROLES
    assert ROLE_OWNER in ADMIN_ROLES


@pytest.mark.parametrize(
    "role,expected",
    [(ROLE_OWNER, True), (ROLE_ADMIN, True), (ROLE_ANALYST, False), ("viewer", False), (None, False)],
)
def test_who_has_administrator_rights(role, expected):
    assert has_admin_rights(role) is expected


def test_an_owner_passes_the_administrator_gate():
    assert auth_api._require_admin(Request(OWNER)) is OWNER


def test_an_analyst_still_does_not():
    with pytest.raises(HTTPException) as caught:
        auth_api._require_admin(Request(ANALYST))
    assert caught.value.status_code == 403


def test_an_owner_may_use_the_sandbox_endpoints():
    """A role added to the vocabulary and missed in one check is a role with
    fewer rights than intended, and nothing says so."""
    from app.api import cape as cape_api

    assert cape_api._require_human(Request(OWNER)) is OWNER
    assert cape_api._require_admin(Request(OWNER)) is OWNER


# ── The account cannot be removed ────────────────────────────────────────────


def _refuse(row, action):
    return asyncio.run(auth_api._refuse_if_owner(row, action=action))


@pytest.mark.parametrize("action", ["deleted", "demoted", "deactivated"])
def test_an_owner_cannot_be_deleted_demoted_or_deactivated(action):
    """All three, because the last two are deletion in all but name: either
    strips the role of everything it carries and leaves the row behind."""
    with pytest.raises(HTTPException) as caught:
        _refuse(Row(role=ROLE_OWNER), action)
    assert caught.value.status_code == 409
    assert action in caught.value.detail


def test_the_refusal_does_not_depend_on_who_is_asking():
    """Another owner, and the owner themselves, are refused too. 'Nobody' has
    to mean nobody or it is a convention rather than a rule."""
    for action in ("deleted", "demoted", "deactivated"):
        with pytest.raises(HTTPException):
            _refuse(Row(role=ROLE_OWNER), action)


def test_administrators_and_analysts_are_not_protected_by_this():
    for role in (ROLE_ADMIN, ROLE_ANALYST):
        for action in ("deleted", "demoted", "deactivated"):
            _refuse(Row(role=role), action)  # must not raise


# ── The role cannot be taken ─────────────────────────────────────────────────


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _DB:
    """Answers only the owner count this guard asks for."""

    def __init__(self, owners: int):
        self._owners = owners

    async def execute(self, *_a, **_k):
        return _Result(self._owners)


def _grant(role, identity, owners):
    return asyncio.run(auth_api._refuse_if_granting_owner(role, identity, _DB(owners)))


def test_an_administrator_cannot_make_themselves_an_owner():
    """Otherwise the protection inverts: any admin promotes themselves into
    the one account nobody may remove."""
    with pytest.raises(HTTPException) as caught:
        _grant(ROLE_OWNER, ADMIN, owners=1)
    assert caught.value.status_code == 403


def test_an_owner_may_grant_the_role():
    _grant(ROLE_OWNER, OWNER, owners=1)


def test_the_first_owner_may_be_created_by_an_administrator():
    """The role has to start somewhere. Until one exists an administrator is
    the highest authority on the platform."""
    _grant(ROLE_OWNER, ADMIN, owners=0)


def test_granting_any_other_role_is_unaffected():
    for role in (ROLE_ADMIN, ROLE_ANALYST):
        _grant(role, ADMIN, owners=1)


# ── The account cannot be taken over ─────────────────────────────────────────


def test_only_an_owner_may_reset_an_owner_password():
    """Set the password, sign in as them, and the protected account is yours —
    so this is the same bypass as deletion, wearing a different hat."""
    assert auth_api._is_owner(Row(role=ROLE_OWNER)) is True
    assert auth_api._is_owner(Row(role=ROLE_ADMIN)) is False
    assert auth_api._is_owner(ADMIN) is False
    assert auth_api._is_owner(OWNER) is True


# ── Lockout protection still counts owners ───────────────────────────────────


def test_an_owner_counts_as_an_administrator_for_the_last_admin_guard():
    """An owner can administer, so demoting the last plain admin while an owner
    exists must not be refused as a lockout."""
    class _CountingDB:
        def __init__(self, remaining):
            self._remaining = remaining

        async def execute(self, *_a, **_k):
            return _Result(self._remaining)

    # One owner remains, so removing this admin leaves administration possible.
    asyncio.run(
        auth_api._refuse_if_last_admin(
            Row(role=ROLE_ADMIN, row_id="x"), _CountingDB(1), {"id": "other"}, action="delete"
        )
    )

    with pytest.raises(HTTPException):
        asyncio.run(
            auth_api._refuse_if_last_admin(
                Row(role=ROLE_ADMIN, row_id="x"), _CountingDB(0), {"id": "other"}, action="delete"
            )
        )
