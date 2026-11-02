"""The unauthenticated `/health` payload is frozen at three keys.

This test exists because a comment was doing its job. Beside the endpoint
stood an invariant — it reports liveness "and nothing else — no data, no
configuration" — which justified the lack of authentication. The code then
drifted from it: a code fingerprint on 2026-10-12, watch liveness on
2026-10-13, 85 bytes to 3,782 and three keys to five. The comment went on
being quoted approvingly, by me, as the reason `/health` was a good home for
the very material that falsified it.

**An unenforced invariant in a comment is worse than no comment**, because it
is load-bearing in people's reasoning and nothing checks it. So the invariant
is here instead, where drifting from it costs a red test.

It is also the only real defence against accretion. Every one of those
additions was individually reasonable; an endpoint whose contract is "small
and dumb" has no natural resistance to growth unless something enforces the
size. Adding a fourth unauthenticated key should require deleting a line of
this file, deliberately, with a reason.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import app

#: Everything an unauthenticated caller may see. TraceCat polls this before
#: every delivery, so it is a contract with a consumer outside this repo.
PUBLIC_KEYS = {"status", "timestamp", "version"}


#: Built once, and deliberately **without** the lifespan context manager.
#:
#: `with TestClient(app)` runs startup, which opens the pooled async engine.
#: Doing that per test opened it under a succession of event loops and
#: reproduced the exact fault these changes exist to fix:
#:
#:     RuntimeError: ... got Future ... attached to a different loop
#:
#: The unauthenticated payload touches no database — that is the property
#: being tested — so the tests need no startup, and not running it keeps the
#: suite from depending on a live Postgres.
client = TestClient(app)


@pytest.mark.parametrize("path", ["/health", "/api/health"])
def test_the_unauthenticated_payload_is_exactly_three_keys(path):
    body = client.get(path).json()
    assert set(body) == PUBLIC_KEYS, (
        "a key was added to the unauthenticated /health payload. TraceCat "
        "parses this, and the endpoint is public precisely because it "
        "carries no data and no configuration. If the new key is genuinely "
        "public, change PUBLIC_KEYS deliberately and say why."
    )


@pytest.mark.parametrize("path", ["/health", "/api/health"])
def test_both_paths_answer_identically(path):
    """The prefixless path is what TraceCat and every operator curl call, and
    it is the one that was left behind when `/api/health` was changed."""
    assert client.get("/health").json().keys() == client.get(path).json().keys()


def test_a_query_parameter_cannot_unlock_diagnostics():
    """`?diagnostics=1` was the first gate and is not a credential: it is
    discoverable in source, guessable, and ends up in access logs and
    bookmarks."""
    for attempt in ("?diagnostics=1", "?diagnostics=true", "?diagnostics=yes"):
        assert set(client.get(f"/health{attempt}").json()) == PUBLIC_KEYS


def test_a_wrong_header_reveals_nothing():
    assert set(client.get("/health", headers={"X-Graph-Debug": "nope"}).json()) == PUBLIC_KEYS


def test_the_probe_still_answers_when_the_credential_is_wrong():
    """This surface omits rather than denies. The debug route 404s so a
    caller cannot learn it exists; here a gate that refused the request would
    break the liveness probe it is attached to."""
    assert client.get("/health", headers={"X-Graph-Debug": "nope"}).status_code == 200
    assert client.get("/health").json()["status"] == "ok"


def test_the_schedules_are_not_served_unauthenticated():
    """The cron periods are the sensitive half. A fingerprint says which
    version is deployed; the periods say how long ingestion can stop before
    anything notices — for this platform, a map of its blind spots."""
    body = client.get("/health").text
    for leak in ("period_seconds", "code_fingerprint", "materialise_graphs",
                 "watch_pipeline", "imported_at", "git_sha"):
        assert leak not in body
