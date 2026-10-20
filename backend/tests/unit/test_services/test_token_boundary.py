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


def test_the_scope_fingerprint_is_twelve_hex_characters():
    """The width is a security parameter, so it is pinned.

    A collision makes two scopes indistinguishable and the cross-tenant check
    passes. The bound is the BIRTHDAY bound: at 24 bits a 50% chance arrives
    at ~4,800 scopes, which an estate reaches in a month. At 48 bits it is
    ~20 million. Narrowing this is a silent weakening, which is why a test
    says the number out loud.
    """
    assert tb.FINGERPRINT_CHARS == 12
    b = _boundary()
    assert len(b.fingerprint) == 12
    assert re.fullmatch(r"[0-9a-f]{12}", b.fingerprint)

    b.tokenize('computer="EXPDC002"')
    token = next(iter(b.token_map))
    parsed = tb.TOKEN_RE.fullmatch(token)
    assert parsed and len(parsed.group("fingerprint")) == 12

    # A six-character fingerprint is now malformed, not merely foreign — the
    # grammar refuses it before any map lookup happens.
    with pytest.raises(tb.MalformedToken):
        b.detokenize_query(f"h = [HOST_{b.fingerprint[:6]}_1]")


# ── closed 2026-10-19 ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, value",
    [
        ('computer="FILESERVER"', "FILESERVER"),
        ('computer="MAILGW"', "MAILGW"),
        ('hostname="EXCHANGE"', "EXCHANGE"),
        ("User INT\\jdoe ran it", "INT\\jdoe"),
        ("copied \\\\EXPFS01\\finance\\q3.xlsx", "EXPFS01"),
        ("from fe80::1c2d:3e4f:5a6b:7c8d", "fe80::1c2d:3e4f:5a6b:7c8d"),
        ("to 2a00:1450:4001:80e::200e", "2a00:1450:4001:80e::200e"),
    ],
)
def test_the_classes_closed_on_2026_10_19(text, value):
    """Single-label names, bare `DOMAIN\\user`, UNC servers and IPv6."""
    b = _boundary()
    assert value not in b.tokenize(text)


@pytest.mark.parametrize(
    "text",
    [
        'user="NT AUTHORITY\\SYSTEM" started it',
        'user="SYSTEM"',
        'user="NT SERVICE\\MSSQLSERVER"',
        "Account Name:  LOCAL SERVICE",
        "Account Name:  NETWORK SERVICE",
        'computer="localhost"',
    ],
)
def test_universal_builtins_stay_readable(text):
    """THE control on the deny-list. These mean the same thing on every
    estate, and "[ACCOUNT_3] created a service" has lost the finding.

    They are protected BEFORE the detectors run, because the account pattern
    stops at a space: `NT AUTHORITY\\SYSTEM` was otherwise already two
    fragments — `NT` tokenised, `AUTHORITY\\SYSTEM` left — before any
    deny-list could see it, and neither fragment is a built-in.
    """
    b = _boundary()
    assert b.tokenize(text) == text


def test_a_name_that_merely_starts_like_a_builtin_is_tokenised():
    """The deny-list is exact names, not prefixes. `systemadmin` is a person."""
    b = _boundary()
    assert "systemadmin" not in b.tokenize('user="systemadmin"')
    assert "SYSTEMS-01" not in b.tokenize('computer="SYSTEMS-01"')


@pytest.mark.parametrize(
    "text",
    ["at 12:34:56 today", "nic 00:1A:2B:3C:4D:5E", "version 1:2:3", "ratio 10:20:30"],
)
def test_a_shape_that_is_not_an_address_is_left_alone(text):
    """`ipaddress` decides, not the regex. Measuring IPv6 by shape said 89.5%
    of alert bodies carried it; validating said 1.2%, and the difference was
    timestamps."""
    b = _boundary()
    assert b.tokenize(text) == text


def test_the_same_account_gets_one_token_keyed_or_bare():
    """`user="INT\\jdoe"` and `INT\\jdoe` in a sentence are one person."""
    b = _boundary()
    out = b.tokenize('user="INT\\jdoe" and later INT\\jdoe again')
    assert len([v for v in b.token_map.values() if v == "INT\\jdoe"]) == 1
    assert out.count("[ACCOUNT_") == 2


def test_a_unc_path_keeps_its_share_and_loses_its_server():
    b = _boundary()
    out = b.tokenize("copied \\\\EXPFS01\\finance\\q3.xlsx")
    assert "EXPFS01" not in out
    assert "finance" in out and "q3.xlsx" in out, (
        "the share and file are not identifiers and removing them costs the "
        "reader what happened"
    )


def test_the_known_gaps_are_still_these():
    """**This test asserts the boundary FAILS on these classes.**

    Measured 2026-10-19. When one of these starts passing, the gap was closed
    and the list given to a reviewer is now wrong — which is why it is a test
    and not a comment. See the module docstring list in the design note.
    """
    b = _boundary()
    gaps = {
        # Accepted: a MAC is an identifier, and no pattern covers it. Left
        # open deliberately — see the risk register.
        "MAC address": ("nic 00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5E"),
        # Accepted: a single-label name with NO key saying it is a host is
        # indistinguishable from an ordinary word. The keyed form is closed.
        "bare NetBIOS host, no keyword": ("EXPREU002 reported", "EXPREU002"),
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


@pytest.mark.parametrize(
    "text, value",
    [
        ("powershell -enc ZQBj -User jdoe", "jdoe"),
        ("net use /user:INT\\mpopescu", "mpopescu"),
        ("runas -username svc-backup", "svc-backup"),
    ],
)
def test_an_account_passed_as_a_command_line_switch_is_tokenised(text, value):
    """Found by re-measuring the corpus after the other closures: `-User jdoe`
    uses a SPACE as its separator, so no `key=value` pattern reaches it."""
    b = _boundary()
    assert value not in b.tokenize(text)


@pytest.mark.parametrize(
    "text",
    [
        "the user clicked the link",
        "the user account was locked out",
        "a user reported the message",
    ],
)
def test_prose_about_a_user_is_not_mistaken_for_one(text):
    """THE control on the switch pattern, and the reason it requires a leading
    `-` or `/`. Without that, `user\\s+VALUE` tokenises `clicked` — corrupting
    the sentence to hide an identifier that was never in it."""
    b = _boundary()
    assert b.tokenize(text) == text


# ── lifetime: completion, with a ceiling as the backstop ─────────────────


def test_the_ceiling_is_twenty_four_hours_and_is_not_the_lifetime():
    """Six hours was a number chosen for a loop that does not exist yet, so it
    could not have been measured. The lifetime is "until the investigation
    completes"; this is only what catches the ones that never do."""
    assert tb.CEILING == timedelta(hours=24)
    assert tb.DEFAULT_TTL == tb.CEILING


def test_a_completion_purge_and_a_ceiling_purge_are_distinguishable():
    """A single `deleted: int` makes housekeeping and a leak indicator the
    same number. They are different findings and carry different reasons."""
    completed = tb.PurgeResult(reason=tb.PURGE_COMPLETED, deleted=3)
    ceiling = tb.PurgeResult(reason=tb.PURGE_CEILING, deleted=3, scopes=("c00/run-1",))

    assert completed.warning is None, "routine housekeeping must not warn"
    assert ceiling.warning is not None
    assert "ceiling" in ceiling.warning
    assert "c00/run-1" in ceiling.warning
    assert "investigations are finishing without purging" in ceiling.warning


def test_a_ceiling_purge_that_deleted_nothing_says_nothing():
    assert tb.PurgeResult(reason=tb.PURGE_CEILING, deleted=0).warning is None


def test_the_boundary_returns_the_warning_and_does_not_log_it():
    """The division of labour: this module handles identifiers in every call
    and imports no logger, so it states the fact and the caller reports it.
    `test_nothing_in_the_boundary_logs` is the other half of this."""
    import inspect

    from app.tasks import token_map_purge_task

    source = inspect.getsource(token_map_purge_task)
    assert "logger.warning" in source, "nothing surfaces the ceiling firing"
    assert "result.warning" in source


# ── encryption at rest ───────────────────────────────────────────────────


@pytest.fixture
def sealing_key(monkeypatch):
    """A key for this run only, generated rather than written down.

    It patches `from_settings` — the factory the boundary calls — because
    patching `SecretBox` instead is how `_seal` came to call the bare
    constructor, which takes no keys and is therefore never configured. A
    test that fakes the thing under test agrees with itself (rule 20).
    """
    from app.security import secret_box
    from app.security.secret_box import SecretBox, generate_key

    box = SecretBox([generate_key()])
    # The module OBJECT, not the dotted string. A string target is
    # resolved with getattr(app, "security"), and 24 of the errors in
    # docs/testing/tolerated-failures.txt are exactly that resolution
    # failing once some other test has run first.
    monkeypatch.setattr(secret_box, "from_settings", lambda: box)
    return box


def test_the_map_is_sealed_before_it_is_stored(sealing_key):
    """The column held real hostnames and accounts in readable form, which is
    the state this closes: a database read alone no longer yields them."""
    sealed, key = tb._seal({"[HOST_abc_1]": "EXPDC002"})
    assert sealed and "EXPDC002" not in sealed
    assert key
    assert tb._open_sealed(sealed) == {"[HOST_abc_1]": "EXPDC002"}


def test_an_unopenable_map_is_empty_rather_than_an_exception(sealing_key):
    """A key rotated past retirement leaves a row nothing can open. The
    investigation re-tokenises; raising would fail the run over what was only
    ever a cache of its own work."""
    assert tb._open_sealed("not-a-fernet-token") == {}
    assert tb._open_sealed(None) == {}
    assert tb._open_sealed("") == {}


def test_sealing_refuses_rather_than_writing_identifiers_in_the_clear(monkeypatch):
    """The only two honest options when no key is configured are to fail or to
    store the reverse index for every identifier in the investigation in
    readable form. It fails."""
    from app.security import secret_box
    from app.security.secret_box import SecretBox

    monkeypatch.setattr(secret_box, "from_settings", lambda: SecretBox([]))
    with pytest.raises(tb.TokenBoundaryError) as exc:
        tb._seal({"[HOST_abc_1]": "EXPDC002"})
    assert "EXPDC002" not in str(exc.value)


# ── the two sanitisers have diverged, and it is pinned ───────────────────


@pytest.mark.parametrize(
    "text, value",
    [
        ('computer="FILESERVER"', "FILESERVER"),
        ("User INT\\jdoe ran it", "INT\\jdoe"),
        ("copied \\\\EXPFS01\\finance\\q3.xlsx", "EXPFS01"),
        ("from fe80::1c2d:3e4f:5a6b:7c8d", "fe80::1c2d:3e4f:5a6b:7c8d"),
        ("powershell -User jdoe", "jdoe"),
    ],
)
def test_the_shipped_alert_pipeline_still_has_the_gaps_the_boundary_closed(text, value):
    """**This asserts the SHIPPED path is still worse than the boundary.**

    The closures on 2026-10-19 are in `token_boundary`. `AssistantService`'s
    own path — which is what analyses every real alert today — calls
    `assistant_sanitizer_service` directly and has none of them.

    That divergence is deliberate: widening detection in the shipped path
    changes what every existing report says, which needs its own evidence. But
    a deliberate divergence that nothing measures is one that widens silently,
    so this test is the measurement. **When it fails, the two paths converged
    — check which way, and update the register.**
    """
    from app.services.assistant_sanitizer_service import sanitize_entry

    shipped = sanitize_entry(text).sanitized_text
    assert value in shipped, (
        f"the shipped pipeline now tokenises {value!r}; the register says it "
        f"does not. Update the divergence row."
    )

    boundary = _boundary().tokenize(text)
    assert value not in boundary, "the boundary regressed to the shipped behaviour"


def test_the_two_paths_agree_on_what_they_both_cover():
    """The divergence is additive, not a fork. Everything the shipped path
    tokenises, the boundary tokenises too — a boundary that *stopped*
    tokenising something would be a regression hiding inside the difference.
    """
    from app.services.assistant_sanitizer_service import sanitize_entry

    text = (
        'computer="EXPDC002" srcuser="INT\\jdoe" from 10.1.2.3 '
        "mail ana.popovici@expertware.net sid S-1-5-21-1786752729-1-1001"
    )
    shipped_values = set(sanitize_entry(text).token_map.values())
    boundary = _boundary()
    boundary.tokenize(text)
    boundary_values = set(boundary.token_map.values())

    assert shipped_values, "fixture tokenised nothing in the shipped path"
    assert shipped_values <= boundary_values, (
        f"the boundary no longer covers what the shipped path does: "
        f"{shipped_values - boundary_values}"
    )


def test_sealing_goes_through_the_deployment_s_configured_key(monkeypatch):
    """The seam, not the halves.

    `_seal` and `SecretBox` were each correct and the call between them was
    not: `SecretBox()` takes its keys as an argument and defaults to none, so
    it is never configured and `_seal` raised on every call. Both unit tests
    would have passed. This one patches *settings* and lets the real
    `from_settings()` run, which is the only version that would have caught
    it.
    """
    from app import config as app_config
    from app.config import get_settings
    from app.security.secret_box import generate_key

    real = get_settings()
    key = generate_key()

    class _Settings:
        integration_encryption_key = key
        integration_encryption_keys_retired = ""

        def __getattr__(self, name):
            return getattr(real, name)

    monkeypatch.setattr(app_config, "get_settings", lambda: _Settings())

    sealed, key_id = tb._seal({"[HOST_abc_1]": "EXPDC002"})
    assert "EXPDC002" not in sealed
    assert tb._open_sealed(sealed)["[HOST_abc_1]"] == "EXPDC002"


def test_the_completion_purge_is_wired_to_the_gathering_loop():
    """**This test used to assert the opposite, and said so.**

    It pinned an absence: `purge_investigation` existed and nothing called
    it, because the loop that owns an investigation did not exist. The note
    attached to it said it would fail the day somebody wired it up, and that
    the register row claiming "unwired" would then have to be retired. The
    loop was built on 2026-10-20 and both happened.

    So today the ceiling sweep is a **backstop** rather than the only thing
    that deletes a map, and its warning means what it says again: a map that
    reaches 24 hours is one an investigation failed to purge.
    """
    import pathlib

    root = pathlib.Path(tb.__file__).resolve().parent.parent
    callers = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if path.name != "token_boundary.py" and "purge_investigation" in path.read_text()
    )
    assert callers, (
        "nothing calls purge_investigation; the completion purge is unwired "
        "again and every token map now lives to the 24-hour ceiling"
    )
    assert "services/context_gathering/loop.py" in callers, (
        f"the gathering loop no longer purges; callers are {callers}"
    )


def _modules_referencing(app_root, needles: tuple[str, ...]) -> list[str]:
    """Modules whose **code** names one of these, ignoring comments.

    Comments are stripped with `tokenize` rather than left in. The first
    version of this check grepped the raw text and failed the moment a comment
    in `db/session.py` explained *why* the sanitizer holds its own engine —
    naming the table in prose is the opposite of reaching it, and a guard that
    punishes the explanation teaches people to delete the explanation.
    """
    import io
    import pathlib
    import tokenize

    found = []
    for path in sorted(app_root.rglob("*.py")):
        source = path.read_text()
        if not any(n in source for n in needles):
            continue
        try:
            code = "".join(
                tok.string
                for tok in tokenize.generate_tokens(io.StringIO(source).readline)
                if tok.type != tokenize.COMMENT
            )
        except (tokenize.TokenError, IndentationError, SyntaxError):
            code = source          # unparseable: fall back to the strict read
        if any(n in code for n in needles):
            found.append(pathlib.Path(path).relative_to(app_root).as_posix())
    return found


def test_no_api_or_report_path_can_reach_the_token_map_table():
    """Decision C's other half, and the one that is enforced in code.

    The role separation is now real — `tip_app` has no privilege on
    `investigation_token_maps` and only `tip_sanitizer` does
    (scripts/db_roles.sql) — but a database grant is checked by
    scripts/check_db_privileges.sql, not by this suite. What this asserts is
    the application-side half: the reverse index is *named* only by the
    boundary, its mapping, its sweep and the engine it connects with.

    Docstrings count as code here, deliberately. A module that documents the
    table in its docstring is close enough to it to be listed.
    """
    import pathlib

    app_root = pathlib.Path(tb.__file__).resolve().parent.parent
    allowed = {
        "services/token_boundary.py",    # the boundary itself
        "models/database.py",            # the mapping
        "tasks/token_map_purge_task.py", # the ceiling sweep
        "db/session.py",                 # the sanitizer engine, and only it
    }
    reachable = _modules_referencing(
        app_root, ("InvestigationTokenMap", "investigation_token_maps")
    )
    assert set(reachable) <= allowed, (
        f"the token map is referenced outside the boundary: "
        f"{sorted(set(reachable) - allowed)}. It is the one table whose rows "
        f"are the identifiers everything else protects."
    )
    assert "services/token_boundary.py" in reachable, (
        "the check found nothing at all, so it is not measuring anything"
    )
