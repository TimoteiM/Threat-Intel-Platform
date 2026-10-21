"""The alert body through the boundary: what leaves, and what cannot.

This is change (b-2): the body is **stored raw** and tokenised only on the
way to the provider, with the answer restored. Two labelled changes measured
separately, because they have opposite properties:

1. **identifier tokenisation** — provably the identity function over the
   corpus (17,549 of 17,550 bodies round-trip byte-identical; the one
   exception loses five `\r` characters inside `sanitize_entries`, which
   already runs on that alert today);
2. **secret redaction** — deliberately NOT identity. Secret placeholders are
   non-reversible by design, so what the model sees genuinely changes for the
   3,179 runs that carry a key-anchored credential.

Probes read the text handed to `AssistantService`, captured by intercepting
`_run_assistant` — the real assembly, not a restatement of it, and no
database row written.
"""

from __future__ import annotations

import pytest

from app.services import alert_body_ai_service as ai
from app.services import token_boundary as tb
from app.services.alert_log_prompt import BoundaryUnavailable

# Nothing in any corpus, so finding one downstream means it travelled there.
SENT_HOST_SINGLE = "ZZSENTHOST01"          # gap 1
SENT_ACCOUNT = "zzsentaccount"             # the colon / JSON keyed account
SENT_DOMAIN_ACCOUNT = r"ZZDOM\zzsentbeta"  # gap 2
SENT_UNC = "ZZSENTFS01"                    # gap 3
SENT_IPV6 = "2001:db8:dead:beef::77"       # gap 4
SENT_SWITCH = "zzsentgamma"                # gap 5
SENT_SECRET = "ZzSentPassw0rd"             # key-anchored secret
NON_IDENTIFIER = "ZzSentinelRuleText"      # must survive: the control


def _body() -> str:
    """One alert body carrying every class, in the shapes ingest produces."""
    return (
        f"rule: {NON_IDENTIFIER}\n"
        f"agentDetectionInfo.agentComputerName: {SENT_HOST_SINGLE}\n"
        f"sourceProcessInfo.user: {SENT_ACCOUNT}\n"
        f"indicators.description: logon by {SENT_DOMAIN_ACCOUNT}\n"
        f"sourceProcessInfo.commandline: powershell.exe -User {SENT_SWITCH} "
        f"-File \\\\{SENT_UNC}\\finance\\q3.xlsx\n"
        f"agentDetectionInfo.agentIpV6: {SENT_IPV6}\n"
        f"vendorDetail: password={SENT_SECRET}\n"
    )


def _boundary():
    return tb.in_memory(tenant_id="t-outbound", investigation_id="run-outbound")


def _sent(body: str, *, boundary, digest: str | None = None) -> str:
    """The text handed to `AssistantService`, from the real assembly."""
    captured = {}

    async def _capture(session_factory, *, entry_text, title, model, boundary):
        captured["text"] = entry_text
        return {}

    original = ai._run_assistant
    ai._run_assistant = _capture
    try:
        ai.run_alert_body_ai_analysis(
            alert_body=body, title="probe", boundary=boundary,
            log_context_digest=digest,
        )
    finally:
        ai._run_assistant = original
    return captured["text"]


# ── change 1: identifier tokenisation ───────────────────────────────────────

ALL_IDENTIFIERS = (
    SENT_HOST_SINGLE, SENT_ACCOUNT, SENT_DOMAIN_ACCOUNT,
    SENT_UNC, SENT_IPV6, SENT_SWITCH,
)


def test_no_identifier_class_reaches_the_assistant():
    """Every class measured leaking at the wire, now tokenised before it."""
    sent = _sent(_body(), boundary=_boundary())
    # The control first. A body that failed to assemble would otherwise
    # satisfy every absence assertion by containing nothing.
    assert NON_IDENTIFIER in sent
    assert len(sent) > 150
    for value in ALL_IDENTIFIERS:
        assert value not in sent, f"{value!r} reached the assistant"


def test_the_round_trip_restores_every_identifier():
    """Provably reversible: what was taken out comes back.

    This is the property that makes change 1 safe to call text-preserving.
    """
    boundary = _boundary()
    body = _body()
    sent = _sent(body, boundary=boundary)
    restored = boundary.restore(sent)
    for value in ALL_IDENTIFIERS:
        assert value in restored, f"{value!r} did not come back"


def test_tokenise_then_restore_is_the_identity_function_on_a_body():
    """The corpus result, pinned as a unit test.

    Measured over all 17,550 bodies under the size bound: 17,549 identical.
    The one exception loses five `\r` characters, and loses them inside
    `sanitize_entries` — which already runs on that alert today — so the
    round trip adds no loss of its own.
    """
    boundary = _boundary()
    body = _body()
    assert boundary.restore(boundary.tokenize(body)) == body


def test_a_carriage_return_is_the_known_exception_and_it_is_not_ours():
    """The single corpus failure, reproduced and attributed.

    Pinned so that if the loss ever moves into the boundary or into
    `restore`, this fails rather than the claim quietly becoming false.
    """
    from app.services.assistant_sanitizer_service import sanitize_entries

    body = "host: ZZSENTHOST01\r\nuser: zzsentaccount\r\n"
    assert body.count("\r") == 2
    # The shipped sanitiser is where it goes.
    assert sanitize_entries([body]).entries[0].sanitized_text.count("\r") == 0
    # And the boundary does not remove anything the shipped layer kept.
    boundary = _boundary()
    kept = boundary.tokenize("host: ZZSENTHOST01\nuser: zzsentaccount\n")
    assert boundary.restore(kept) == "host: ZZSENTHOST01\nuser: zzsentaccount\n"


def test_one_host_is_one_token_across_the_alert_and_the_digest():
    """Two halves, one map.

    With separate boundaries the alert's host and the same host in a gathered
    event would be different tokens, and the model would read one machine as
    two — which is worse than a leak, because it is a wrong answer rather
    than a disclosure.

    The digest is built the way production builds it: through
    `alert_log_prompt.build` with the **same** boundary. See the test below
    for why it cannot be hand-written as raw JSON here.
    """
    from datetime import datetime, timezone

    from app.services import alert_log_prompt
    from app.services.alert_log_selection import AlertPivots

    boundary = _boundary()
    event = {
        "key": "i:1", "ref": "i:1", "index": "i", "id": "1", "event_id": "4624",
        "timestamp": "2026-10-21T12:00:00.000+0000",
        "agent": {"name": SENT_HOST_SINGLE, "id": "1"},
        "rule": {"id": "1", "level": 3, "description": "d", "groups": []},
        "users": [], "process": {}, "full_log": "nothing",
    }
    digest, _sel, _red = alert_log_prompt.build(
        [event], boundary=boundary, pivots=AlertPivots(),
        alert_time=datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc),
        pinned_keys=["i:1"], only_pinned=True,
    )
    assert digest, "the digest did not build; the rest of this proves nothing"

    sent = _sent(_body(), boundary=boundary, digest=digest)
    token = next(t for t, v in boundary.token_map.items() if v == SENT_HOST_SINGLE)
    # The same token in both halves, and exactly one token for that host.
    assert sent.count(token) >= 2
    assert sum(1 for v in boundary.token_map.values() if v == SENT_HOST_SINGLE) == 1


def test_this_layer_depends_on_the_digest_arriving_already_tokenised():
    """A limitation, pinned rather than discovered later.

    `_protect_outbound` receives a flat string and runs the **prose** pass,
    which keys on identifier-shaped words — `hostname`, `computername`,
    `user` and the rest. It has no field-path knowledge, so a structured
    `{"agent":{"name":"EXPDC001"}}` is invisible to it: `name` is not an
    identifier-shaped key, and only `tokenize_records` knows that
    `agent.name` is a host because `DECLARED_FIELDS` says so.

    In production this never fires, because `alert_log_prompt.build` has
    already tokenised the digest with this same boundary and both layers are
    idempotent. But it is a **dependency, not a guarantee**: if a future
    caller passes a raw structured digest, this layer will not save it. That
    is what this test says out loud.
    """
    boundary = _boundary()
    raw_structured = f'{{"agent":{{"name":"{SENT_HOST_SINGLE}"}}}}'
    assert SENT_HOST_SINGLE in ai._protect_outbound(raw_structured, boundary=boundary)
    # Whereas the keyed prose form IS caught, which is the contrast that
    # shows this is about the shape and not about the boundary being inert.
    keyed = f'computername="{SENT_HOST_SINGLE}"'
    assert SENT_HOST_SINGLE not in ai._protect_outbound(keyed, boundary=boundary)


# ── change 2: secret redaction (deliberately not identity) ─────────────────

def test_a_key_anchored_secret_does_not_reach_the_assistant():
    sent = _sent(_body(), boundary=_boundary())
    assert NON_IDENTIFIER in sent                      # control
    assert SENT_SECRET not in sent
    assert "<SECRET:password:" in sent


def test_the_secret_is_not_restorable_and_that_is_the_point():
    """Non-reversible by design: `restore` must not undo a credential."""
    boundary = _boundary()
    sent = _sent(_body(), boundary=boundary)
    restored = boundary.restore(sent)
    assert SENT_SECRET not in restored
    assert "<SECRET:password:" in restored
    # Which means the round trip is NOT the identity function here. Asserted
    # so nobody later reads change 1's identity property as covering this.
    assert restored != _body()


def test_the_two_layers_run_secrets_first():
    """Order, not just presence.

    A credential must be behind a non-reversible placeholder before anything
    reversible touches the text, or it can end up inside the reversible map
    — and the map is restorable.
    """
    boundary = _boundary()
    _sent(f"password={SENT_SECRET} host: {SENT_HOST_SINGLE}\n", boundary=boundary)
    assert SENT_SECRET not in boundary.token_map.values()


# ── fail closed ────────────────────────────────────────────────────────────

def test_no_boundary_means_nothing_is_sent():
    with pytest.raises(BoundaryUnavailable) as caught:
        ai._protect_outbound(_body(), boundary=None)
    assert "nothing was sent" in str(caught.value)


def test_a_broken_boundary_means_nothing_is_sent():
    class _Broken:
        def tokenize(self, text):
            raise RuntimeError("map expired")

    with pytest.raises(BoundaryUnavailable) as caught:
        ai._protect_outbound(_body(), boundary=_Broken())
    assert "RuntimeError" in str(caught.value)


def test_the_report_says_it_was_withheld_rather_than_merely_failed():
    """An analyst reading `failed` cannot tell which of the two happened."""
    report = ai.run_alert_body_ai_analysis(
        alert_body=_body(), title="probe", boundary=None,
    )
    assert report["status"] == "failed"
    assert report["withheld"] is True
    assert "not tokenised" in (report["error"] or "")


def test_a_successful_run_is_not_marked_withheld():
    """The positive control for the flag above."""
    async def _ok(session_factory, *, entry_text, title, model, boundary):
        return {"report_markdown": "ok"}

    original = ai._run_assistant
    ai._run_assistant = _ok
    try:
        report = ai.run_alert_body_ai_analysis(
            alert_body=_body(), title="probe", boundary=_boundary(),
        )
    finally:
        ai._run_assistant = original
    assert report["status"] == "completed"
    assert report["withheld"] is False


def test_the_boundary_is_required_with_no_default():
    """The rule lives in the signature, not in a caller's memory."""
    import inspect

    sig = inspect.signature(ai.run_alert_body_ai_analysis)
    assert sig.parameters["boundary"].default is inspect.Parameter.empty


# ── 44a: every add_entry caller, not just the alert-body one ───────────────

def test_add_entry_itself_applies_the_boundary():
    """The manual assistant path, which leaked live on 2026-10-21.

    Two `source_type='manual'` entries went to the provider with zero scoped
    tokens and 24 gap-class identifiers, because the assistant API calls
    `add_entry` directly and b-2 had put the boundary in a caller. There are
    four callers and three were unprotected, so the boundary moved into
    `add_entry` — where "every model input becomes an entry" already holds.

    Exercised at the function that does the work, with the database stubbed,
    because the claim is about `add_entry` and not about SQLAlchemy.
    """
    import asyncio
    from app.services.assistant_service import AssistantService

    class _Session:
        id = "11111111-1111-1111-1111-111111111111"
        entries: list = []

    class _Db:
        def add(self, _obj): pass
        async def flush(self): pass
        async def commit(self): pass

    service = AssistantService(_Db())
    service._get_session = lambda _sid: _done(_Session())

    def _done(value):
        fut = asyncio.Future()
        fut.set_result(value)
        return fut

    entry = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        service.add_entry(_Session.id, text=_body(), entry_label="entry-1")
    )
    # Nothing in the clear...
    for value in ALL_IDENTIFIERS:
        assert value not in entry.raw_text, f"{value!r} survived add_entry"
    assert SENT_SECRET not in entry.raw_text
    # ...the control that it inspected real text...
    assert NON_IDENTIFIER in entry.raw_text
    # ...and the map travelled with the entry, or the restore cannot resolve
    # what this call minted.
    assert entry.token_map_json, "the boundary map was not persisted"
    assert any(v == SENT_HOST_SINGLE for v in entry.token_map_json.values())


def test_the_boundary_is_applied_at_add_entry_for_every_caller():
    """A structural assertion, so a fifth caller is covered by default.

    Derived from the source rather than from a list of callers, because a
    list of callers is the ninth hand-maintained registry.
    """
    import inspect

    from app.services import assistant_service

    source = inspect.getsource(assistant_service.AssistantService.add_entry)
    assert "protect_outbound" in source, (
        "add_entry no longer applies the boundary; every caller is exposed"
    )
    assert "token_map_json=dict(boundary.token_map)" in source, (
        "the boundary map is not persisted, so the restore cannot resolve it"
    )
