"""The connection check, driven in the direction that must fail.

Every assertion here is a control for the liveness limb. A check that has
only ever been seen to pass is a check nobody has established can fail, and
this one exists precisely because three deployments were quietly wrong while
everything reported healthy.

So each of the four problem kinds is provoked:

* `absent` — the variable is not set and a default takes over. The original
  fault, three times;
* `wrong_role` — the variable is set, the connection works, and the principal
  is not the one the grants and the row-level policy were written for;
* `unreachable` — not checked, which the limb must not read as correct;
* `undeclared` — a connection added without anyone saying who it opens as.
  The one that makes this a class rather than four instances.

`undeclared` is driven by putting a real field on `Settings`, not by faking
the derivation, because the claim being tested is that the set comes FROM
`Settings` rather than from a list somebody has to remember to update.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic.fields import FieldInfo

from app.config import Settings, get_settings
from app.db import connection_check as cc


# ─────────────────────── a stub for the layer below ───────────────────────
#
# The connection itself is stubbed, never `check()` or `declared_connections()`
# — a test that patched the thing under test would agree with whatever the
# thing under test currently does. What is faked here is Postgres answering
# `SELECT current_user`, which is one layer below the code being exercised.

class _FakeConn:
    def __init__(self, user: str) -> None:
        self._user = user

    def execute(self, _stmt):
        user = self._user

        class _Result:
            def scalar(self):
                return user
        return _Result()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakeEngine:
    def __init__(self, user: str) -> None:
        self._user = user

    def connect(self):
        return _FakeConn(self._user)

    def dispose(self) -> None:
        pass


def _engines(*, roles: dict[str, str] | None = None, raises: set[str] | None = None):
    """A `create_engine` that answers with the role embedded in the URL.

    The default makes every connection resolve to the username in its own
    URL, which is what a correct deployment looks like. `roles` overrides one
    by username, `raises` makes one fail to connect.
    """
    roles = roles or {}
    raises = raises or set()

    def factory(url: str, **_kwargs):
        from sqlalchemy.engine import make_url
        username = make_url(url).username or ""
        if username in raises:
            raise OSError("connection refused")
        return _FakeEngine(roles.get(username, username))
    return factory


@pytest.fixture(autouse=True)
def _clean_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _problems(**engine_kwargs) -> list[cc.Problem]:
    with patch("sqlalchemy.create_engine", _engines(**engine_kwargs)):
        return cc.check()


# ───────────────────────── the derivation itself ─────────────────────────

def test_the_checked_set_is_derived_from_settings_not_listed():
    """Every database connection `Settings` has, and no others.

    This is the assertion that turns the instance into the class. If someone
    adds a fifth connection, this fails here and the limb fails in
    production, rather than the connection going unexamined because nobody
    thought to add it to a list.
    """
    assert cc.declared_connections() == set(cc.CONNECTION_ROLES)


def test_a_new_connection_with_no_declared_role_is_a_problem():
    """A field added to Settings and nowhere else.

    Driven through a real `Settings` field so the derivation is what notices.
    """
    field = FieldInfo(annotation=str, default="postgresql://who:knows@localhost/x")
    Settings.model_fields["database_reporting_url"] = field
    try:
        Settings.model_rebuild(force=True)
        assert "database_reporting_url" in cc.declared_connections()
        problems = _problems()
        undeclared = [p for p in problems if p.kind == "undeclared"]
        assert [p.field for p in undeclared] == ["database_reporting_url"]
        assert "CONNECTION_ROLES" in undeclared[0].detail
    finally:
        Settings.model_fields.pop("database_reporting_url", None)
        Settings.model_rebuild(force=True)
        get_settings.cache_clear()
    # And the removal really did restore the world, or every later test in
    # the file is measuring a Settings this one left behind.
    assert "database_reporting_url" not in cc.declared_connections()


def test_a_declared_role_for_a_setting_that_no_longer_exists_is_a_problem():
    """The other direction: the registry naming a connection that went away.

    A stale entry reads as coverage. It is the same fault as a missing one.
    """
    with patch.dict(cc.CONNECTION_ROLES, {"database_retired_url": "tip_app"}):
        problems = _problems()
    undeclared = [p for p in problems if p.kind == "undeclared"]
    assert [p.field for p in undeclared] == ["database_retired_url"]
    assert "no longer exists" in undeclared[0].detail


# ──────────────────────────── absent ────────────────────────────

def test_an_unset_variable_is_absent_even_though_the_app_would_start():
    """The fault that bit three times.

    The point is that nothing else is wrong: a default is in place, the
    connection opens, the application runs. Only the principal is not the one
    anybody intended.
    """
    variable = cc.env_name("database_sanitizer_url")
    with patch.dict(os.environ):
        os.environ.pop(variable, None)
        problems = _problems()
    absent = [p for p in problems if p.kind == "absent"]
    assert [p.field for p in absent] == ["database_sanitizer_url"]
    assert variable in absent[0].detail


def test_an_empty_variable_is_absent_too():
    """`DATABASE_X_URL=` in an env file. Set, and carrying nothing."""
    variable = cc.env_name("database_migration_url")
    with patch.dict(os.environ, {variable: "   "}):
        problems = _problems()
    assert [p.field for p in problems if p.kind == "absent"] == [
        "database_migration_url"
    ]


def test_a_present_variable_is_not_reported():
    """The positive control.

    Without this, every assertion above is satisfied by a check that reports
    a problem for everything regardless.
    """
    assert _problems() == []


# ──────────────────────────── wrong role ────────────────────────────

def test_a_connection_resolving_to_another_role_is_wrong_role():
    """Set, reachable, working — and connecting as the owner.

    This is the host/container divergence: `tip_app` in the containers and
    the owning superuser on a laptop, where row-level security exempts an
    owner and the check that said "protected" was run in the wrong place.
    """
    problems = _problems(roles={"tip_app": "threatintel"})
    wrong = [p for p in problems if p.kind == "wrong_role"]
    assert sorted(p.field for p in wrong) == [
        "database_sync_url", "database_url",
    ]
    assert "threatintel" in wrong[0].detail and "tip_app" in wrong[0].detail


def test_the_sanitizer_role_is_checked_separately_from_the_app_role():
    """`tip_sanitizer` is the only role that may read the token map.

    The app role resolving correctly says nothing about this one, which is
    how the sanitizer URL was missed when the other three were fixed.
    """
    problems = _problems(roles={"tip_sanitizer": "tip_app"})
    assert [p.field for p in problems if p.kind == "wrong_role"] == [
        "database_sanitizer_url"
    ]


# ──────────────────────────── unreachable ────────────────────────────

def test_a_connection_that_cannot_be_opened_is_not_silently_passed():
    """Could not check is its own answer, distinct from checked and correct.

    An exception swallowed into a clean result is the shape of the fault this
    whole module is about — absence read as a value.
    """
    problems = _problems(raises={"tip_sanitizer"})
    unreachable = [p for p in problems if p.kind == "unreachable"]
    assert [p.field for p in unreachable] == ["database_sanitizer_url"]
    assert "not the same as correct" in unreachable[0].detail


# ──────────────────────────── env_name ────────────────────────────

def test_env_name_upper_cases_by_default():
    assert cc.env_name("database_sync_url") == "DATABASE_SYNC_URL"


def test_env_name_honours_a_validation_alias():
    """A check looking for the wrong variable reports everything absent.

    Which would be loud rather than quiet, but it would also be wrong, and a
    limb that cries wolf gets an exemption added to it.
    """
    field = FieldInfo(annotation=str, default="x", validation_alias="PGURL_LEGACY")
    with patch.dict(Settings.model_fields, {"database_legacy_url": field}):
        assert cc.env_name("database_legacy_url") == "PGURL_LEGACY"


def test_env_name_honours_an_alias_choice_list():
    from pydantic import AliasChoices

    field = FieldInfo(
        annotation=str, default="x",
        validation_alias=AliasChoices("PGURL_NEW", "PGURL_OLD"),
    )
    with patch.dict(Settings.model_fields, {"database_choice_url": field}):
        assert cc.env_name("database_choice_url") == "PGURL_NEW"


# ──────────────────────────── the summary line ────────────────────────────

def test_summary_says_how_many_when_clean():
    with patch("sqlalchemy.create_engine", _engines()):
        line = cc.summary()
    assert line.startswith(f"{len(cc.CONNECTION_ROLES)} database connection(s)")


def test_summary_names_each_problem_when_not_clean():
    with patch("sqlalchemy.create_engine", _engines(roles={"tip_app": "threatintel"})):
        line = cc.summary()
    assert "database_url" in line and "wrong_role" in line
    # The liveness limb treats any output as a failure, so a problem must
    # never render as the clean sentence.
    assert "resolving to the declared role" not in line
