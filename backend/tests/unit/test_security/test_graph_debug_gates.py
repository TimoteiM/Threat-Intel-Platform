"""The two gates on the case-graph debug route.

A note on the instrument, because it is the subject of the route itself:
`TestClient` is a valid instrument *here* and an invalid one for deployment.
These tests ask "what does this code do", which is a question about source and
is exactly what TestClient answers. They cannot answer "what is the running
server doing" — that needs a request over the published port, and conflating
the two is how seven commits stayed unserved for an afternoon on 2026-10-12.
"""

from __future__ import annotations

import pytest

from app.api import graph_debug
from app.middleware.auth import PUBLIC_PATHS


class _Settings:
    def __init__(self, flag: str = "", token: str = "") -> None:
        self.graph_debug_route = flag
        self.graph_debug_token = token


def _patch(monkeypatch, flag: str, token: str) -> None:
    # Patch the gate, not the route: the check moved to
    # `app/security/diagnostics_gate` so `/health` could share one
    # implementation, one switch and one token to rotate.
    from app.security import diagnostics_gate

    monkeypatch.setattr(diagnostics_gate, "get_settings", lambda: _Settings(flag, token))


def test_off_by_default(monkeypatch) -> None:
    _patch(monkeypatch, "", "")
    with pytest.raises(Exception) as caught:
        graph_debug._authorise("anything")
    assert caught.value.status_code == 404


def test_a_set_token_alone_does_not_enable_it(monkeypatch) -> None:
    """Both conditions are required; neither implies the other."""
    _patch(monkeypatch, "", "s3cret")
    with pytest.raises(Exception) as caught:
        graph_debug._authorise("s3cret")
    assert caught.value.status_code == 404


def test_the_flag_alone_does_not_enable_it(monkeypatch) -> None:
    """An unset token must not become a secret that matches unset input."""
    _patch(monkeypatch, "1", "")
    for presented in (None, "", "anything"):
        with pytest.raises(Exception) as caught:
            graph_debug._authorise(presented)
        assert caught.value.status_code == 404


def test_a_wrong_token_is_refused(monkeypatch) -> None:
    _patch(monkeypatch, "1", "s3cret")
    with pytest.raises(Exception) as caught:
        graph_debug._authorise("not-it")
    assert caught.value.status_code == 404


def test_a_missing_header_is_refused(monkeypatch) -> None:
    _patch(monkeypatch, "1", "s3cret")
    with pytest.raises(Exception) as caught:
        graph_debug._authorise(None)
    assert caught.value.status_code == 404


def test_the_right_token_passes(monkeypatch) -> None:
    _patch(monkeypatch, "1", "s3cret")
    graph_debug._authorise("s3cret")  # does not raise


@pytest.mark.parametrize("flag", ["1", "true", "TRUE", "yes", "on"])
def test_the_flag_accepts_the_usual_truthy_spellings(monkeypatch, flag) -> None:
    _patch(monkeypatch, flag, "s3cret")
    graph_debug._authorise("s3cret")


@pytest.mark.parametrize("flag", ["0", "false", "no", "off", " ", "maybe"])
def test_anything_else_is_off(monkeypatch, flag) -> None:
    _patch(monkeypatch, flag, "s3cret")
    with pytest.raises(Exception) as caught:
        graph_debug._authorise("s3cret")
    assert caught.value.status_code == 404


def test_every_failure_is_404_and_never_401(monkeypatch) -> None:
    """A 401 would tell an unauthenticated caller the route exists here."""
    for flag, token, presented in [("", "", "x"), ("1", "", "x"), ("1", "s", "bad")]:
        _patch(monkeypatch, flag, token)
        with pytest.raises(Exception) as caught:
            graph_debug._authorise(presented)
        assert caught.value.status_code == 404
        assert caught.value.detail == "Not Found"


def test_the_path_is_in_the_auth_allowlist() -> None:
    """It bypasses the session deliberately — that is the point — and the
    allowlist is hand-maintained, so being absent would make it 401 instead."""
    assert graph_debug.GRAPH_PATH in PUBLIC_PATHS
