"""The two-way boundary: tokens out, real values in, refusals in between.

Every test is in the dangerous direction, because every failure on this path
is silent. A query with an unresolved token runs against a literal string and
returns a clean zero; a token resolved under the wrong tenant's map returns a
confident answer about the wrong estate; a value that slips through
tokenisation is simply *in* the request, and nothing raises.

`test_the_known_gaps_are_still_these` is deliberately an assertion that the
boundary FAILS to cover certain classes. When it breaks, a gap was closed and
the list in front of a reviewer needs updating — a documented gap that nothing
checks is a gap that silently becomes a lie.
"""

from __future__ import annotations

import logging
import re
import traceback
from datetime import datetime, timedelta, timezone

import pytest

from app.services import token_boundary as tb

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)

#: Held in a module constant so a call site that passes it does not render the
#: values into its own traceback frame.
SENSITIVE_TEXT = "host " + "EXPDC002" + " user " + "jdoe" + " " + "10.1.2.3"


def _boundary(tenant="c00", investigation="run-1", ttl=timedelta(hours=1), now=None):
    clock = now or (lambda: T0)
    return tb.in_memory(
        tenant_id=tenant, investigation_id=investigation, ttl=ttl, now=clock
    )


# ── round trip ───────────────────────────────────────────────────────────


def test_round_trip_returns_the_original_value():
    b = _boundary()
    out = b.tokenize('computer="EXPDC002" srcuser="INT\\jdoe" from 10.1.2.3')

    assert "EXPDC002" not in out
    assert "10.1.2.3" not in out

    host = next(t for t, v in b.token_map.items() if v == "EXPDC002")
    query = b.detokenize_query(f'AgentName = "{host}"')

    assert query.text == 'AgentName = "EXPDC002"'
    assert query.substitutions == 1


def test_round_trip_through_a_query_with_several_tokens():
    b = _boundary()
    b.tokenize('computer="EXPDC002" srcuser="INT\\jdoe" from 10.1.2.3')
    host = next(t for t, v in b.token_map.items() if v == "EXPDC002")
    ip = next(t for t, v in b.token_map.items() if v == "10.1.2.3")

    q = b.detokenize_query(f"host:{host} AND src:{ip}")
    assert q.text == "host:EXPDC002 AND src:10.1.2.3"
    assert q.substitutions == 2


def test_a_quote_function_escapes_the_substituted_value():
    """A value is data in someone else's query language.

    Built from state rather than by tokenising, because the value that
    actually carries syntax characters is a command line, not a hostname —
    and the risk is real: interpolated verbatim, the embedded quote ends the
    string it was supposed to be inside and the rest becomes query syntax.
    """
    state = tb.TokenMapState(
        tenant_id="c00", investigation_id="run-1",
        fingerprint=tb.fingerprint_for("c00", "run-1"),
        token_map={}, expires_at=None,
    )
    token = f"[HOST_{state.fingerprint}_1]"
    state.token_map[token] = 'EXP" OR 1=1 --'
    b = tb.TokenBoundary(state, now=lambda: T0)

    unquoted = b.detokenize_query(f"name = {token}")
    assert unquoted.text == 'name = EXP" OR 1=1 --', "no quote function means verbatim"

    quoted = b.detokenize_query(
        f"name = {token}", quote=lambda v: '"' + v.replace('"', '\\"') + '"'
    )
    assert quoted.text == 'name = "EXP\\" OR 1=1 --"'
    assert quoted.text.count('"') == 3


# ── consistency ──────────────────────────────────────────────────────────


def test_the_same_entity_gets_the_same_token_across_calls():
    b = _boundary()
    first = b.tokenize('computer="EXPDC002" seen')
    second = b.tokenize("later, the host EXPDC002 was seen again")

    tokens_first = set(tb.TOKEN_RE.findall(first))
    tokens_second = set(tb.TOKEN_RE.findall(second))
    assert tokens_first & tokens_second, "the same host got a different token on the second call"
    assert len([v for v in b.token_map.values() if v == "EXPDC002"]) == 1


def test_consistency_holds_for_an_identifier_inside_a_free_text_field():
    """The account in `Account Name: jdoe` and the one in a Windows path are
    the same person, and a model told they are two accounts will reason about
    two people."""
    b = _boundary()
    out = b.tokenize("Account Name:  jdoe ran C:\\Users\\jdoe\\Downloads\\x.js")
    accounts = {t for t in tb.TOKEN_RE.findall(out) if t[0] == "ACCOUNT"}
    assert len({b.token_map[f"[ACCOUNT_{f}_{i}]"] for _, f, i in
                [m.groups() for m in tb.TOKEN_RE.finditer(out)]
                if _ == "ACCOUNT"}) == 1
    assert "jdoe" not in out


def test_records_and_free_text_share_one_map():
    b = _boundary()
    b.tokenize('computer="EXPDC002"')
    [record] = b.tokenize_records([{"full_log": "host EXPDC002 rebooted"}])
    host = next(t for t, v in b.token_map.items() if v == "EXPDC002")
    assert host in record["full_log"], (
        "the result used a different token for the same host, so the model "
        "cannot join it to the alert"
    )


def test_different_investigations_get_different_tokens_for_the_same_value():
    a = _boundary(investigation="run-1")
    c = _boundary(investigation="run-2")
    a.tokenize('computer="EXPDC002"')
    c.tokenize('computer="EXPDC002"')
    assert set(a.token_map) & set(c.token_map) == set(), (
        "two investigations issued the same token for the same host, so a "
        "token from one resolves under the other"
    )


def test_a_nested_value_is_tokenised_not_only_the_listed_fields():
    """A field list is a hand-maintained registry, and a vendor that puts a
    hostname in a key nobody listed ships it verbatim."""
    b = _boundary()
    [out] = b.tokenize_records([
        {"vendor": {"unlisted_field": "host EXPDC002", "nested": [{"deep": "to 10.1.2.3"}]}}
    ])
    assert "EXPDC002" not in str(out)
    assert "10.1.2.3" not in str(out)


# ── cross-tenant ─────────────────────────────────────────────────────────


def test_a_token_from_another_tenant_is_refused_not_resolved():
    """THE one. Bare `[HOST_1]` tokens are textually identical across tenants,
    so the failure without a scope in the token is not an error — it is tenant
    B's host, returned confidently."""
    a = _boundary(tenant="c00")
    b = _boundary(tenant="lin")
    a.tokenize('computer="EXPDC002"')
    b.tokenize('computer="LINDC001"')

    foreign = next(iter(a.token_map))
    with pytest.raises(tb.ForeignToken) as exc:
        b.detokenize_query(f"host = {foreign}")

    assert a.fingerprint in str(exc.value)
    assert b.fingerprint in str(exc.value)
    assert "EXPDC002" not in str(exc.value)
    assert "LINDC001" not in str(exc.value)


def test_the_two_tenants_do_not_even_share_a_token_namespace():
    a = _boundary(tenant="c00")
    b = _boundary(tenant="lin")
    a.tokenize('computer="SAMENAME"')
    b.tokenize('computer="SAMENAME"')
    assert set(a.token_map) & set(b.token_map) == set()


def test_a_state_whose_fingerprint_does_not_match_its_scope_is_refused():
    """Caught at construction, not at first use: every token such a map went
    on to issue would carry a scope it was not minted under."""
    with pytest.raises(tb.ForeignToken):
        tb.TokenBoundary(
            tb.TokenMapState(
                tenant_id="c00", investigation_id="run-1",
                fingerprint="000000", token_map={}, expires_at=None,
            )
        )


def test_a_boundary_cannot_be_opened_without_a_tenant():
    with pytest.raises(tb.TokenBoundaryError):
        tb.open_boundary(None, tenant_id="", investigation_id="run-1")


# ── refusals ─────────────────────────────────────────────────────────────


def test_an_invented_token_is_refused_not_guessed():
    """In prose an unknown token becomes "the affected host" and the sentence
    survives. In a query it would run against the literal string and return a
    clean zero — the strongest possible answer, from nothing."""
    b = _boundary()
    b.tokenize('computer="EXPDC002"')
    with pytest.raises(tb.UnknownToken):
        b.detokenize_query(f"host = [HOST_{b.fingerprint}_99]")


def test_an_unscoped_token_is_refused():
    b = _boundary()
    with pytest.raises(tb.MalformedToken) as exc:
        b.detokenize_query("host = [HOST_1]")
    assert "unscoped" in str(exc.value)


def test_a_token_shaped_string_that_does_not_parse_is_refused():
    b = _boundary()
    with pytest.raises(tb.MalformedToken):
        b.detokenize_query("host = [HOSTNAME]")


def test_a_secret_placeholder_is_refused_outright():
    """One-way by construction. Resolving it would mean searching a platform
    for a customer's credential."""
    b = _boundary()
    with pytest.raises(tb.SecretRefused):
        b.detokenize_query("password = <SECRET:password:4f2a91>")


def test_detokenisation_is_all_or_nothing():
    """A partially resolved query is the worst outcome: it is syntactically
    valid, it runs, and one of its clauses matches a literal token."""
    b = _boundary()
    b.tokenize('computer="EXPDC002"')
    good = next(iter(b.token_map))
    with pytest.raises(tb.TokenBoundaryError):
        b.detokenize_query(f"host = {good} AND user = [ACCOUNT_{b.fingerprint}_77]")


def test_an_expired_map_refuses_rather_than_resolving():
    clock = {"t": T0}
    b = _boundary(ttl=timedelta(minutes=5), now=lambda: clock["t"])
    b.tokenize('computer="EXPDC002"')
    token = next(iter(b.token_map))
    clock["t"] = T0 + timedelta(hours=2)
    with pytest.raises(tb.MapExpired):
        b.detokenize_query(f"host = {token}")
    with pytest.raises(tb.MapExpired):
        b.tokenize("anything")


# ── no leakage ───────────────────────────────────────────────────────────

#: What must never survive tokenisation, for the classes the boundary claims.
LEAK_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sid": re.compile(r"\bS-\d-(?:\d+-){1,14}\d+\b"),
}

CORPUS = [
    {
        "full_log": 'computer="EXPDC002" srcuser="INT\\jdoe" src_ip=10.1.2.3 '
                    'dst_ip=192.168.5.9 mail=ana.popovici@expertware.net',
        "process": {"command_line": "powershell -enc ZQBj -User jdoe"},
    },
    {
        "full_log": "Account Name:  mpopescu\nAccount Domain: INT\n"
                    "Security ID: S-1-5-21-1786752729-1234567890-999-1001",
        "agent": {"name": "EXPREU002", "ip": "10.44.1.9"},
    },
    {
        "message": "the host EXPVDI012 reached expdc002.int.expertware.net "
                   "and signed in as jdoe@expertware.net from 172.20.30.35",
    },
    {
        "full_log": 'user="svc-backup" computer="EXPFS01" wrote to 10.10.126.151',
        "network": {"src_ip": "10.10.126.151", "dst_ip": "8.8.8.8"},
    },
]


def test_no_covered_identifier_survives_the_corpus():
    b = _boundary()
    out = b.tokenize_records(CORPUS)
    blob = str(out)

    for label, pattern in LEAK_PATTERNS.items():
        found = [m for m in pattern.findall(blob) if not m.startswith("S-1-5-21-00")]
        assert found == [], f"{label} survived tokenisation: {found}"

    # The hostnames and accounts this corpus names, by value.
    for value in (
        "EXPDC002", "EXPREU002", "EXPVDI012", "EXPFS01",
        "expdc002.int.expertware.net",
        "ana.popovici@expertware.net", "jdoe@expertware.net",
        "10.1.2.3", "192.168.5.9", "10.44.1.9", "172.20.30.35", "10.10.126.151",
    ):
        assert value not in blob, f"{value!r} survived into the model-facing output"


def test_the_corpus_actually_produced_tokens():
    """A tokeniser that returned the input unchanged would pass every
    assertion above by matching nothing. Assert the pass is earned."""
    b = _boundary()
    blob = str(b.tokenize_records(CORPUS))
    assert len(tb.TOKEN_RE.findall(blob)) >= 10


def test_the_known_gaps_are_still_these():
    """**This test asserts the boundary FAILS on these classes.**

    Measured 2026-10-19. When one of these starts passing, the gap was closed
    and the list given to a reviewer is now wrong — which is why it is a test
    and not a comment. See the module docstring list in the design note.
    """
    b = _boundary()
    gaps = {
        "bare DOMAIN\\user in free text": ("User INT\\jdoe ran it", "INT\\jdoe"),
        "IPv6": ("from fe80::1c2d:3e4f:5a6b:7c8d", "fe80::1c2d:3e4f:5a6b:7c8d"),
        "UNC path host": ("copied \\\\EXPFS01\\finance\\q3.xlsx", "EXPFS01"),
        "MAC address": ("nic 00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5E"),
        "bare NetBIOS host, no keyword": ("EXPREU002 reported", "EXPREU002"),
        # Found while writing these tests, not predicted. A single-label
        # hostname with no digit and no dot is never tokenised — not even
        # with a key in front of it. `FILESERVER`, `MAILGW`, `EXCHANGE` and
        # `PRINTSRV` are all ordinary names in a Windows estate.
        "alphabetic hostname, keyed": ('computer="FILESERVER"', "FILESERVER"),
        "alphabetic hostname, declared field": ("MAILGW", "MAILGW"),
    }
    still_missing = {
        label for label, (text, value) in gaps.items() if value in b.tokenize(text)
    }
    assert still_missing == set(gaps), (
        f"a gap was closed — update the reviewer list. Now covered: "
        f"{set(gaps) - still_missing}"
    )


# ── error paths ──────────────────────────────────────────────────────────


def test_a_refusal_names_the_token_and_never_the_value():
    b = _boundary()
    b.tokenize('computer="EXPDC002" srcuser="INT\\jdoe"')
    other = _boundary(tenant="lin")
    # A name with a digit: purely alphabetic single-label hostnames are not
    # tokenised at all (see `test_the_known_gaps_are_still_these`), and a
    # fixture that silently produced an empty map would make this test pass
    # by testing nothing.
    other.tokenize('computer="LINDC001"')
    assert other.token_map, "fixture produced no token"
    foreign = next(iter(other.token_map))

    for raiser in (
        lambda: b.detokenize_query(f"h = {foreign}"),
        lambda: b.detokenize_query(f"h = [HOST_{b.fingerprint}_99]"),
        lambda: b.detokenize_query("h = [HOST_1]"),
        lambda: b.detokenize_query("p = <SECRET:password:4f2a91>"),
    ):
        with pytest.raises(tb.TokenBoundaryError) as exc:
            raiser()
        rendered = str(exc.value) + "".join(
            traceback.format_exception(type(exc.value), exc.value, exc.value.__traceback__)
        )
        for value in ("EXPDC002", "LINDC001", "jdoe"):
            assert value not in rendered, (
                f"{value!r} reached an exception message or traceback"
            )


def test_the_executable_query_is_not_in_its_own_repr():
    """The accidental paths — an f-string in a log line, a traceback rendering
    locals, a dict dumped into an error response — must show nothing."""
    b = _boundary()
    b.tokenize('computer="EXPDC002"')
    token = next(iter(b.token_map))
    q = b.detokenize_query(f"host = {token}")

    for rendered in (repr(q), str(q), f"{q}", "{}".format(q)):
        assert "EXPDC002" not in rendered
        assert "Detokenized" in rendered
    assert q.text == "host = EXPDC002"


def test_nothing_in_the_boundary_logs():
    """A value cannot reach a log the module does not write to. Structural,
    because a test that checks one call site is a test of that call site."""
    import ast
    import inspect

    # Parsed, not grepped. The module's own docstring discusses logging at
    # length and contains the literal `logger.info(...)` as an example, so a
    # text search finds the documentation rather than the behaviour — which
    # is the mistake this codebase keeps writing down.
    tree = ast.parse(inspect.getsource(tb))
    imported: list[str] = []
    attribute_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names if a.name.split(".")[0] == "logging"]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "logging":
                imported.append(node.module or "logging")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in ("logging", "logger", "log"):
                attribute_calls.append(f"{node.value.id}.{node.attr}")

    assert imported == [], f"the boundary imports logging: {imported}"
    assert attribute_calls == [], (
        f"the boundary calls a logger: {attribute_calls} — every value it "
        f"handles is one a log line could now carry"
    )


def test_a_failure_inside_tokenisation_does_not_put_the_text_in_the_traceback(monkeypatch):
    """Force the detection layer to fail mid-pass and assert the raw record is
    not rendered into the exception that escapes."""
    def boom(entries, existing_token_map=None):
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr(tb, "sanitize_entries", boom)
    b = _boundary()
    # Via a variable, deliberately. A traceback renders each frame's SOURCE
    # LINE, so a literal written at the call site is leaked by the caller's
    # own code, not by the boundary — and that caveat is in the reviewer list
    # rather than hidden by a test that arranges it.
    text = SENSITIVE_TEXT
    with pytest.raises(RuntimeError) as exc:
        b.tokenize(text)

    rendered = "".join(
        traceback.format_exception(type(exc.value), exc.value, exc.value.__traceback__)
    )
    for value in ("EXPDC002", "jdoe", "10.1.2.3"):
        assert value not in rendered


def test_a_failure_in_the_secret_layer_does_not_leak_the_record(monkeypatch):
    # `sanitize_text`, not `sanitize_records`: the boundary stopped calling the
    # record-level helper when the field list turned out to miss credentials
    # outside `full_log`. This test failed when that changed, which is the
    # test doing its job — a forced-failure test that no longer forces one
    # passes by exercising nothing.
    def boom(text, **kwargs):
        raise RuntimeError("secret scan unavailable")

    monkeypatch.setattr(tb.secrets, "sanitize_text", boom)
    b = _boundary()
    with pytest.raises(RuntimeError) as exc:
        b.tokenize_records(CORPUS)

    rendered = "".join(
        traceback.format_exception(type(exc.value), exc.value, exc.value.__traceback__)
    )
    for value in ("EXPDC002", "ana.popovici@expertware.net", "10.1.2.3"):
        assert value not in rendered


def test_no_raw_value_reaches_the_log_during_a_normal_pass(caplog):
    b = _boundary()
    with caplog.at_level(logging.DEBUG):
        b.tokenize_records(CORPUS)
        token = next(iter(b.token_map))
        b.detokenize_query(f"host = {token}")

    logged = "\n".join(r.getMessage() for r in caplog.records)
    for value in ("EXPDC002", "ana.popovici@expertware.net", "10.1.2.3", "jdoe"):
        assert value not in logged


def test_a_secret_outside_the_default_field_list_is_still_scrubbed():
    """`log_secret_sanitizer.sanitize_records` scans `full_log`, `message` and
    `process.command_line` — the Wazuh shape. Measured 2026-10-19: a
    credential in `vendor_detail` passed through untouched, so the boundary
    walks every string instead of taking the field list."""
    b = _boundary()
    [out] = b.tokenize_records([{
        "full_log": "cmd password=Sup3rSecret!",
        "vendor_detail": "password=Sup3rSecret!",
        "nested": {"deep": {"t": "api_key=AKIAIOSFODNN7EXAMPLE"}},
    }])
    blob = str(out)
    assert "Sup3rSecret" not in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert blob.count("<SECRET:") >= 2


def test_the_same_secret_is_the_same_placeholder_across_fields():
    """Per-string scrubbing must not mean per-string maps: a credential
    appearing twice has to be recognisable as one thing."""
    b = _boundary()
    [out] = b.tokenize_records([
        {"a": "password=Sup3rSecret!", "b": "password=Sup3rSecret!"}
    ])
    assert out["a"] == out["b"]
    assert "<SECRET:" in out["a"]


def test_a_secret_never_enters_the_reversible_map():
    """The ordering that matters: a non-reversible placeholder is in place
    before anything reversible runs, so a credential cannot end up as a token
    that `detokenize_query` would happily resolve."""
    b = _boundary()
    b.tokenize_records([{"full_log": "password=Sup3rSecret! host EXPDC002"}])
    assert all("Sup3rSecret" not in v for v in b.token_map.values())
