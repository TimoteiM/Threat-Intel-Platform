"""The two-way sanitisation boundary: tokens out, real values in, refusals in between.

The platform already tokenises *outbound*. `assistant_sanitizer_service`
replaces hostnames, accounts, addresses, emails and SIDs with `[HOST_1]`-style
tokens before a model sees them, and restores them in the report afterwards.
That is enough for a single-shot analysis.

It is not enough for a model that asks for queries. A query goes back out to a
platform and has to carry the *real* hostname, so there has to be a return
path — and the return path is where the mistakes are, because every one of
them fails silently:

| the mistake | what it produces |
|---|---|
| prose-style replacement in a query | a token substituted inside a field name or an operator, producing a syntactically valid query about the wrong thing |
| an invented token resolved charitably | `[HOST_7]` becomes "the affected host" and the query runs against a literal string, returning a clean zero |
| a secret placeholder resolved | we search a customer's EDR for their own password |
| a bare token across tenants | `[HOST_1]` resolves under another customer's map to **a different machine** — not an error, a wrong answer |
| the executable query logged | the identifiers the tokenisation existed to protect, in a log line |

So this module is built so that each of those is a **refusal**, and so that the
safe path is the easy one.

Three things carry the design:

**The scope is in the token.** `[HOST_a3f9c1_1]` — prefix, a fingerprint of
(tenant, investigation) under the deployment pepper, then the index. Bare
`[HOST_1]` tokens are textually identical across investigations, so a token
from one tenant *resolves* under another's map rather than failing. Putting
the scope in the token turns a silently wrong answer into an exception.

**Detokenisation is structural, not textual.** Only a complete, well-formed
token is substituted. Anything that merely *looks* like a token — a truncated
one, an old bare-format one, a token with the wrong fingerprint — stops the
whole call. There is no partial detokenisation: a query is either entirely
resolved or it is refused, because a query with one unresolved token in it is
a query that runs against a literal `[HOST_2]`.

**The executable text is hard to leak by accident.** `detokenize_query`
returns a `Detokenized`, not a `str`. Its `repr` and `str` show the shape and
never the content, so a stray `logger.info("built %s", q)` prints
`<Detokenized 2 values, 61 chars>`. Reaching the real text takes `.text`,
which is a deliberate act that shows up in review.

Detection is **not** reimplemented here. The regexes that find a hostname in a
Windows event live in `assistant_sanitizer_service` and are the hard part; a
second copy would be the stale one within a month. This module reuses them and
adds the scope, the lifetime and the return path.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Sequence

from app.services import log_secret_sanitizer as secrets
from app.services.assistant_sanitizer_service import sanitize_entries

#: How long a map lives if the caller does not say. An investigation is
#: minutes; this is generous enough to survive a retry and short enough that a
#: forgotten map is not an indefinite copy of customer identifiers.
DEFAULT_TTL = timedelta(hours=6)

#: `[HOST_a3f9c1_1]`. The fingerprint sits between the prefix and the index so
#: the prefix still reads first — a model is being asked to reason about
#: "HOST", and the scope is bookkeeping it never needs to understand.
#: Twelve hex characters, not six. At 24 bits the birthday bound puts a 50%
#: chance of a collision at roughly 4,800 scopes — and a collision is not
#: cosmetic here: two scopes sharing a fingerprint make the cross-tenant check
#: pass, which is the one check whose failure is a confident answer about
#: another customer's estate. 48 bits moves that bound to ~20 million.
FINGERPRINT_CHARS = 12

TOKEN_RE = re.compile(
    r"\[(?P<prefix>[A-Z]+)_(?P<fingerprint>[0-9a-f]{%d})_(?P<index>\d+)\]" % FINGERPRINT_CHARS
)

#: Anything bracket-shaped that could be a token. Used only to REFUSE: a
#: string that looks like a token and does not parse is the model inventing
#: one, and inventing is the case that must never be resolved charitably.
TOKEN_LIKE_RE = re.compile(r"\[[A-Za-z][A-Za-z0-9_]{0,63}\]")

#: What `assistant_sanitizer_service` emits before this module rescopes it.
BARE_TOKEN_RE = re.compile(r"\[(?P<prefix>[A-Z]+)_(?P<index>\d+)\]")

#: One-way by construction — see `log_secret_sanitizer`. Never resolvable.
SECRET_RE = re.compile(r"<SECRET:[A-Za-z0-9_]+:[0-9a-f]+>")

#: Paths in **our own normalised event shape** whose value is an identifier of
#: a known class, regardless of what it looks like.
#:
#: This exists because the detection patterns are *keyed*: they find a host in
#: `computer="EXPDC002"` by the word `computer`, and a record field carries its
#: value with the key stripped off. `agent.name` is the host of every event in
#: this platform and the bare string `"EXPREU002"` matches nothing — measured,
#: it survived a corpus pass into the model-facing output.
#:
#: `name` cannot be treated as a host by its leaf alone: `rule.name` is a
#: detection rule's description, and tokenising that would both destroy the
#: sentence and fill the map with rule text. So the map is by PATH.
#:
#: It is a declared list and therefore the thing this codebase keeps warning
#: about — but the failure mode is the safe one. An unlisted field is not
#: skipped; it falls through to the pattern pass that handles everything else.
#: A new vendor field is tokenised no worse than it is today, and listing it
#: only makes it better.
DECLARED_FIELDS: dict[str, str] = {
    "agent.name": "HOST",
    "agent.ip": "IP",
    "users": "ACCOUNT",
}

# ── the extra pass: what the keyed detectors reject ──────────────────────
#
# `assistant_sanitizer_service` gates every host match on `_is_redactable_host`,
# which requires a public or internal SUFFIX — so a single-label name is only
# tokenised when something else about it looks host-like. Measured: a name with
# no digit and no dot is never tokenised, even keyed. `computer="FILESERVER"`
# passed through whole, and `MAILGW`, `EXCHANGE` and `PRINTSRV` with it.
#
# The gate is there for a reason: it was added after a .NET crash report had 35
# stack-trace namespaces tokenised as hostnames. So this pass does not remove
# it — it runs afterwards, over the KEYED positions only, where a field name
# has already said "this is a host".
#
# **Deny-list, not allow-list.** An allow-list from an asset inventory makes
# coverage depend on the inventory being complete, and an inventory is never
# complete — the machine nobody registered is the one worth tokenising. So
# everything in a host or account position is tokenised except a short list of
# names that are identical on every Windows estate and carry analytical
# meaning: an analyst reading "[ACCOUNT_3] created a service" has lost the
# fact that it was SYSTEM.

#: Principals that mean the same thing on every estate. Matched
#: case-insensitively, and in their `DOMAIN\NAME` forms.
BUILTIN_PRINCIPALS = frozenset({
    "system", "localsystem", "local system", "local service", "network service",
    "anonymous logon", "trustedinstaller", "everyone", "authenticated users",
    "creator owner", "self", "iusr", "iwam", "nt authority", "nt service",
    "builtin", "window manager", "font driver host", "umfd-0", "umfd-1",
    "dwm-1", "dwm-2",
})

#: Authorities whose `DOMAIN\NAME` names a built-in rather than a real user.
BUILTIN_AUTHORITIES = frozenset({"nt authority", "nt service", "builtin", "window manager"})

#: Placeholders a host field carries when there is no host.
BUILTIN_HOSTS = frozenset({"localhost", "unknown", "none", "null", "n/a", "-", "127.0.0.1"})

_HOST_KEY = r"[A-Za-z0-9_]*?(?:hostname|computername|computer|host|server|device|workstation)"
_ACCOUNT_KEY = r"[A-Za-z0-9_]*?(?:username|user|accountname|samaccountname|account)"
_SEP = r'(?:(?:\\*")?\s*:\s*(?:\\*")|\s*[=:]\s*\\*"?)'

#: A keyed host whose value the existing gate rejects: single label, no dot.
KEYED_HOST_LAX_RE = re.compile(
    rf'(?P<prefix>\b{_HOST_KEY}{_SEP})(?P<value>[A-Za-z][A-Za-z0-9_-]{{1,62}})(?![\w.-])',
    re.IGNORECASE,
)

#: A keyed account, including the `DOMAIN\user` form.
KEYED_ACCOUNT_LAX_RE = re.compile(
    rf'(?P<prefix>\b{_ACCOUNT_KEY}{_SEP})'
    rf'(?P<value>(?:[A-Za-z][A-Za-z0-9_.-]{{0,30}}\\)?[A-Za-z][A-Za-z0-9_.$-]{{0,62}})(?![\w.-])',
    re.IGNORECASE,
)

#: `-User jdoe`, `/user jdoe` — a command-line SWITCH, where the separator is
#: a space rather than `=` or `:`. Measured: `powershell ... -User jdoe` leaked
#: the account out of a corpus pass.
#:
#: The leading `-` or `/` is required and is the whole safety of this pattern.
#: Without it, `user\s+VALUE` matches "the user clicked the link" and
#: tokenises `clicked` as an account — corrupting prose to hide an identifier
#: that was never there.
SWITCH_ACCOUNT_RE = re.compile(
    r"(?P<prefix>(?:^|\s)[-/]{1,2}(?:user(?:name)?|account)\s+)"
    r"(?P<value>(?:[A-Za-z][A-Za-z0-9_.-]{0,30}\\)?[A-Za-z][A-Za-z0-9_.$-]{0,62})(?![\w.-])",
    re.IGNORECASE,
)

#: `INT\jdoe` standing alone in a sentence. Not preceded by a backslash, which
#: is what separates it from a UNC share and from `C:\Users\jdoe` — in both of
#: those the candidate "domain" is itself a path segment.
BARE_DOMAIN_ACCOUNT_RE = re.compile(
    r"(?<![\\\w:.-])(?P<value>[A-Za-z][A-Za-z0-9_-]{1,20}\\[A-Za-z][A-Za-z0-9_.$-]{0,62})(?![\w.-])"
)

#: The server in `\\EXPFS01\finance\q3.xlsx`. The share and path are left
#: alone; the host is the identifier.
UNC_HOST_RE = re.compile(r"(?<=\\\\)(?P<value>[A-Za-z][A-Za-z0-9_-]{1,62})(?=\\|$)")

#: Candidates only. `ipaddress` decides — a shape-match counts `12:34:56` as an
#: address, which is a timestamp, and measuring with the loose pattern said
#: 89.5% of alert bodies carried IPv6 where validation says 1.2%.
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


#: Built-ins, as they appear in text, longest first so `NT AUTHORITY\\SYSTEM`
#: wins over `SYSTEM`. The authority-qualified form takes any name, because
#: `NT SERVICE\\MSSQLSERVER` is a service account and not a person.
_PROTECT_RE = re.compile(
    r"(?<![\w\\])(?:"
    r"(?:NT\s+AUTHORITY|NT\s+SERVICE|BUILTIN|WINDOW\s+MANAGER|FONT\s+DRIVER\s+HOST)"
    r"\\[A-Za-z0-9_.$-]{1,64}"
    r"|" + "|".join(
        re.escape(name) for name in sorted(BUILTIN_PRINCIPALS | BUILTIN_HOSTS, key=len, reverse=True)
    ).replace(r"\ ", r"\s+") +
    r")(?![\w.-])",
    re.IGNORECASE,
)

#: NUL-delimited, because nothing in the detection pipeline matches a NUL and
#: a protected span has to come back byte-identical.
_SENTINEL = "\x00P{}\x00"
_SENTINEL_RE = re.compile(r"\x00P(\d+)\x00")


def _protect_builtins(text: str) -> tuple[str, dict[str, str]]:
    """Hide built-in principals before the detectors run.

    The deny-list cannot be applied afterwards: the existing account pattern
    stops at a space, so `user="NT AUTHORITY\\SYSTEM"` is already two
    fragments — `NT` tokenised and `AUTHORITY\\SYSTEM` left — by the time any
    later pass sees it, and neither fragment is in the list. Measured: it came
    back as two separate account tokens.
    """
    held: dict[str, str] = {}

    def repl(match: "re.Match[str]") -> str:
        key = _SENTINEL.format(len(held))
        held[key] = match.group(0)
        return key

    return _PROTECT_RE.sub(repl, text), held


def _restore_builtins(text: str, held: dict[str, str]) -> str:
    if not held:
        return text
    return _SENTINEL_RE.sub(
        lambda m: held.get(_SENTINEL.format(m.group(1)), m.group(0)), text
    )


def is_builtin_principal(value: str) -> bool:
    """A name that means the same thing on every estate, in any of its forms."""
    candidate = str(value or "").strip().strip('"').casefold()
    if not candidate:
        return True
    if candidate in BUILTIN_PRINCIPALS or candidate in BUILTIN_HOSTS:
        return True
    if "\\" in candidate:
        domain, _, name = candidate.rpartition("\\")
        if domain in BUILTIN_AUTHORITIES:
            return True
        if name in BUILTIN_PRINCIPALS:
            # `EXPDC002\SYSTEM` — the name is built in, but the domain half is
            # a real machine, so only the fully built-in forms are kept.
            return domain in BUILTIN_AUTHORITIES or domain in BUILTIN_HOSTS
    # A machine account: `EXPDC002$` is the host, and is tokenised as one.
    return False


#: The minimal context each class's detector needs, synthesised around a bare
#: value so the EXISTING regexes do the work. Reusing them is the point: a
#: second set of identifier patterns here would be the stale one within a
#: month, and these are the hard part.
_CONTEXT = {
    "HOST": ('host="', '"'),
    "ACCOUNT": ('user="', '"'),
}


class TokenBoundaryError(Exception):
    """Base for every refusal. Carries tokens, never values."""


class UnknownToken(TokenBoundaryError):
    """A well-formed token this map never issued."""


class ForeignToken(TokenBoundaryError):
    """A token minted under a different tenant or investigation."""


class MalformedToken(TokenBoundaryError):
    """Something token-shaped that does not parse — an invented one."""


class SecretRefused(TokenBoundaryError):
    """A secret placeholder in a query. One-way by design."""


class MapExpired(TokenBoundaryError):
    """The map's lifetime ended. Tokens minted under it are no longer resolvable."""


@dataclass(frozen=True)
class Detokenized:
    """An executable query. Deliberately awkward to log.

    `repr` and `str` describe the shape and never the content, so the
    accidental paths — an f-string in a log line, a traceback rendering
    locals, a dict dumped into an error response — show nothing. `.text` is
    the only way to the real query and is a visible act at the call site.
    """

    _text: str
    substitutions: int
    tokens: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        """The executable query. Pass it to a client; do not store or log it."""
        return self._text

    def __repr__(self) -> str:
        return f"<Detokenized {self.substitutions} values, {len(self._text)} chars>"

    __str__ = __repr__


@dataclass
class TokenMapState:
    """The persisted half: the scope, the map and when it ends."""

    tenant_id: str
    investigation_id: str
    fingerprint: str
    token_map: dict[str, str] = field(default_factory=dict)
    expires_at: datetime | None = None


def fingerprint_for(tenant_id: str, investigation_id: str) -> str:
    """Six hex characters naming the scope a token was minted under.

    HMAC under the deployment pepper rather than a plain hash: the input is
    guessable (`c00`, a run uuid) and a fingerprint that can be computed from
    outside is one an attacker can forge onto a token.

    `FINGERPRINT_CHARS` is the width and it is load-bearing. A collision makes
    two scopes indistinguishable, which makes the cross-tenant check pass — so
    the bound is the birthday bound, not the preimage one: at 24 bits a 50%
    chance arrives at ~4,800 scopes, which an estate reaches in a month of
    investigations. At 48 bits it is ~20 million. A collision still does not
    grant access on its own, because the token index must also exist in the
    other map, but that is a second lock and not the argument.
    """
    material = f"{tenant_id}\x1f{investigation_id}".encode("utf-8", "replace")
    return hmac.new(secrets._pepper(), material, hashlib.sha256).hexdigest()[:FINGERPRINT_CHARS]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TokenBoundary:
    """Tokens out, real values in, with a scope and an end.

    Not constructed directly in production — `open()` loads or creates the
    persisted map for a scope. The in-memory constructor exists so tests can
    exercise every path without a database, which is the only reason the state
    is a plain dataclass.
    """

    def __init__(self, state: TokenMapState, *, now: Callable[[], datetime] = _now) -> None:
        self._state = state
        self._now = now
        expected = fingerprint_for(state.tenant_id, state.investigation_id)
        if state.fingerprint != expected:
            # The state was built for a different scope than it claims. Caught
            # here rather than at first use, because every token this map goes
            # on to issue would carry the wrong scope.
            raise ForeignToken(
                "this map's fingerprint does not match its own tenant and "
                "investigation, so it was not minted for the scope it claims"
            )

    # -- scope ------------------------------------------------------------

    @property
    def tenant_id(self) -> str:
        return self._state.tenant_id

    @property
    def investigation_id(self) -> str:
        return self._state.investigation_id

    @property
    def fingerprint(self) -> str:
        return self._state.fingerprint

    @property
    def token_map(self) -> dict[str, str]:
        """The scoped map. A copy: a caller mutating it would desynchronise
        the reverse index and produce tokens that resolve to the wrong value."""
        return dict(self._state.token_map)

    @property
    def expired(self) -> bool:
        return bool(self._state.expires_at and self._now() >= self._state.expires_at)

    def _require_live(self) -> None:
        if self.expired:
            raise MapExpired(
                f"the token map for investigation {self._state.investigation_id} "
                f"expired at {self._state.expires_at}; its tokens are no longer "
                f"resolvable and a new investigation must mint its own"
            )

    # -- outbound ---------------------------------------------------------

    def tokenize(self, text: str) -> str:
        """Identifiers out of `text`, tokens in, extending this map.

        Secrets are **not** handled here: they are one-way and belong to
        `tokenize_records`, which runs them first. Free text arriving by this
        path is alert body and analyst context, which the alert pipeline
        already scrubs for secrets upstream.
        """
        self._require_live()
        return self._tokenize_one(str(text or ""))

    def tokenize_records(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Results coming back, through **both** layers in the fixed order.

        Secrets first, because a command line is exactly where a `-Password`
        argument lives and a non-reversible placeholder must be in place before
        anything reversible is. Identifiers second, with **this** map — a
        result tokenised under a fresh map is one the model cannot join to the
        alert, since the host it has been calling `[HOST_a3f9c1_1]` would come
        back as `[HOST_b1c2d3_1]` and read as a second machine.
        """
        self._require_live()
        # NOT `secrets.sanitize_records`. Its default field list is
        # `full_log`, `message` and `process.command_line` — the Wazuh shape —
        # and a vendor that puts a credential anywhere else keeps it:
        # measured, `vendor_detail="password=…"` passed through untouched.
        #
        # This walks every string instead, so the field list disappears rather
        # than needing a row per vendor. `shared` carries one placeholder map
        # across the whole batch, so the same secret is the same placeholder
        # in every record — the property `sanitize_records` provides and the
        # reason it is not simply called per field.
        shared: dict[str, str] = {}
        out: list[dict[str, Any]] = []
        for record in records:
            out.append(self._tokenize_tree(record, secret_map=shared))
        return out

    def _tokenize_tree(
        self, node: Any, path: str = "", *, secret_map: dict[str, str] | None = None
    ) -> Any:
        """Every string in a record, not only the ones a field list names.

        Two passes, and the order matters. A path in `DECLARED_FIELDS` is
        tokenised as its declared class, because the detectors are keyed and a
        record field arrives with its key stripped off. Everything else gets
        the pattern pass, so an unlisted field is no worse off than it is
        today rather than being skipped.
        """
        if isinstance(node, dict):
            return {
                k: self._tokenize_tree(
                    v, f"{path}.{k}" if path else str(k), secret_map=secret_map
                )
                for k, v in node.items()
            }
        if isinstance(node, (list, tuple)):
            # A list keeps its parent's path: `users` is a list of accounts,
            # and `users.0` would match nothing.
            return [self._tokenize_tree(v, path, secret_map=secret_map) for v in node]
        if isinstance(node, str):
            text = node
            if secret_map is not None:
                # Secrets first, always. A non-reversible placeholder has to be
                # in place before anything reversible is, or a credential ends
                # up in the reversible map.
                text = secrets.sanitize_text(text, shared=secret_map).text
            declared = DECLARED_FIELDS.get(path)
            if declared:
                return self._tokenize_as(text, declared)
            return self._tokenize_one(text)
        return node

    def _tokenize_as(self, value: str, kind: str) -> str:
        """One bare value, tokenised as a known class.

        The value is wrapped in the smallest context its detector recognises,
        tokenised, and unwrapped. If the wrapper does not come back intact —
        a value containing a quote, say — the result is discarded and the
        value falls through to the pattern pass, because a half-unwrapped
        string is worse than an untokenised one.
        """
        if not value:
            return value
        if is_builtin_principal(value):
            # `agent.name = "localhost"` names no machine, and tokenising it
            # costs the reader the fact that there was no host.
            return value
        context = _CONTEXT.get(kind)
        if context is None:
            return self._tokenize_one(value)
        prefix, suffix = context
        wrapped = self._tokenize_one(f"{prefix}{value}{suffix}")
        if wrapped.startswith(prefix) and wrapped.endswith(suffix):
            return wrapped[len(prefix): len(wrapped) - len(suffix)]
        return self._tokenize_one(value)

    def _tokenize_one(self, text: str) -> str:
        if not text:
            return text
        # Built-ins out of harm's way first, restored last. They are the one
        # class that must stay readable: "[ACCOUNT_3] created a service" has
        # lost the fact that it was SYSTEM, which is most of the finding.
        text, held = _protect_builtins(text)
        # Detection is the existing service's. `existing_token_map` carries
        # this investigation's bare-form map in, so the same entity keeps the
        # same index across every call in the loop.
        bare_in = {
            self._to_bare(token): value
            for token, value in self._state.token_map.items()
        }
        result = sanitize_entries([text], existing_token_map=bare_in)
        entry = result.entries[0]
        # Rescope: bare tokens in, scoped tokens out, and the map updated with
        # anything new. Exact string replacement is safe because a bare token
        # ends in `]`, so `[HOST_1]` is never a prefix of `[HOST_10]`.
        scoped_text = entry.sanitized_text
        for bare, value in entry.token_map.items():
            scoped = self._to_scoped(bare)
            if scoped is None:
                continue
            scoped_text = scoped_text.replace(bare, scoped)
            self._state.token_map[scoped] = value
        return _restore_builtins(self._extra_pass(scoped_text), held)

    # -- the classes the keyed detectors reject ---------------------------

    def _mint(self, value: str, prefix: str) -> str:
        """A token for one value, reusing this map's existing one if any."""
        for token, existing in self._state.token_map.items():
            if existing == value:
                return token
        used = {
            int(m.group("index"))
            for m in (TOKEN_RE.fullmatch(t) for t in self._state.token_map)
            if m is not None and m.group("prefix") == prefix
        }
        index = max(used) + 1 if used else 1
        token = f"[{prefix}_{self.fingerprint}_{index}]"
        self._state.token_map[token] = value
        return token

    def _extra_pass(self, text: str) -> str:
        """Single-label names, `DOMAIN\\user`, UNC servers and IPv6.

        Runs AFTER the existing detectors, over text that already carries
        their tokens. Nothing here can match inside a token: a token has no
        backslash, no colon, and its value position cannot begin with `[`.
        """
        out = text

        def _keyed(match: "re.Match[str]", prefix: str) -> str:
            value = match.group("value")
            if is_builtin_principal(value) or TOKEN_RE.fullmatch(value):
                return match.group(0)
            return match.group("prefix") + self._mint(value, prefix)

        out = KEYED_HOST_LAX_RE.sub(lambda m: _keyed(m, "HOST"), out)
        out = KEYED_ACCOUNT_LAX_RE.sub(lambda m: _keyed(m, "ACCOUNT"), out)
        out = SWITCH_ACCOUNT_RE.sub(lambda m: _keyed(m, "ACCOUNT"), out)

        def _bare_account(match: "re.Match[str]") -> str:
            value = match.group("value")
            if is_builtin_principal(value):
                return match.group(0)
            return self._mint(value, "ACCOUNT")

        out = BARE_DOMAIN_ACCOUNT_RE.sub(_bare_account, out)

        def _unc(match: "re.Match[str]") -> str:
            value = match.group("value")
            if is_builtin_principal(value):
                return match.group(0)
            return self._mint(value, "HOST")

        out = UNC_HOST_RE.sub(_unc, out)

        def _v6(match: "re.Match[str]") -> str:
            raw = match.group(0)
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                # A timestamp, a MAC fragment, a version string. `ipaddress`
                # is the authority and a shape match is not.
                return raw
            return self._mint(raw, "IP")

        return IPV6_CANDIDATE_RE.sub(_v6, out)

    def _to_bare(self, scoped: str) -> str:
        match = TOKEN_RE.fullmatch(scoped)
        if not match:
            return scoped
        return f"[{match.group('prefix')}_{match.group('index')}]"

    def _to_scoped(self, bare: str) -> str | None:
        match = BARE_TOKEN_RE.fullmatch(bare)
        if not match:
            return None
        return f"[{match.group('prefix')}_{self.fingerprint}_{match.group('index')}]"

    # -- inbound ----------------------------------------------------------

    def detokenize_query(
        self, text: str, *, quote: Callable[[str], str] | None = None
    ) -> Detokenized:
        """Real values in place of tokens, or a refusal. Never partial.

        `quote` escapes a value for the target query language. Without one the
        value is substituted verbatim, which is correct for an argument the
        caller will bind separately and wrong for one being interpolated into
        a query string — so a caller interpolating must pass it. This boundary
        cannot know the target syntax and does not guess at it.

        Refuses, in this order, because the earlier refusals are the ones whose
        consequences are worst:

        1. a secret placeholder — one-way, and resolving it would mean
           searching a platform for a customer's password;
        2. a token-shaped string that does not parse — an invented token;
        3. a token whose fingerprint is not this scope's — another tenant's,
           or another investigation's;
        4. a well-formed, correctly scoped token this map never issued.
        """
        self._require_live()
        raw = str(text or "")

        secret = SECRET_RE.search(raw)
        if secret:
            raise SecretRefused(
                f"the query contains {secret.group(0)!r}, which is a one-way "
                f"placeholder for a secret. It has no reverse and a query "
                f"built from it would search a platform for a credential."
            )

        # Every well-formed token, and every token-shaped thing that is not.
        well_formed = {m.group(0) for m in TOKEN_RE.finditer(raw)}
        for candidate in TOKEN_LIKE_RE.finditer(raw):
            if candidate.group(0) in well_formed:
                continue
            if BARE_TOKEN_RE.fullmatch(candidate.group(0)):
                raise MalformedToken(
                    f"{candidate.group(0)!r} is an unscoped token. Tokens in "
                    f"this boundary carry the scope they were minted under, "
                    f"and one without it cannot be shown to belong to this "
                    f"investigation."
                )
            raise MalformedToken(
                f"{candidate.group(0)!r} is token-shaped and does not parse. "
                f"It was not issued by this boundary, so it is an invented "
                f"token and the query is refused rather than guessed at."
            )

        resolved: list[str] = []
        for token in sorted(well_formed):
            match = TOKEN_RE.fullmatch(token)
            assert match is not None  # from the finditer above
            if match.group("fingerprint") != self.fingerprint:
                raise ForeignToken(
                    f"{token!r} was minted under scope "
                    f"{match.group('fingerprint')!r} and this boundary is "
                    f"{self.fingerprint!r}. It belongs to another tenant or "
                    f"another investigation and is refused — resolving it "
                    f"here would answer about the wrong estate."
                )
            if token not in self._state.token_map:
                raise UnknownToken(
                    f"{token!r} is correctly scoped and this map never issued "
                    f"it. Nothing is substituted for it: a query carrying an "
                    f"unresolved token runs against the literal string and "
                    f"returns a clean zero."
                )
            resolved.append(token)

        out = raw
        for token in sorted(resolved, key=len, reverse=True):
            value = self._state.token_map[token]
            out = out.replace(token, quote(value) if quote else value)

        return Detokenized(_text=out, substitutions=len(resolved), tokens=tuple(sorted(resolved)))

    # -- restore (prose, not queries) -------------------------------------

    def restore(self, text: str) -> str:
        """Tokens back to values in **prose** — a report, not a query.

        Separate from `detokenize_query` and deliberately forgiving in the one
        way that one is not: an unknown token is left standing rather than
        raising, because a narrative with `[HOST_9]` in it is a visible defect
        a reader can report, while a refused report is no report at all. A
        query has the opposite trade: it runs, silently, against a literal.
        """
        out = str(text or "")
        for token, value in sorted(
            self._state.token_map.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            out = out.replace(token, value)
        return out


# ── persistence ──────────────────────────────────────────────────────────


def open_boundary(
    db: Any,
    *,
    tenant_id: str,
    investigation_id: str,
    ttl: timedelta = DEFAULT_TTL,
    now: Callable[[], datetime] = _now,
) -> TokenBoundary:
    """The boundary for one investigation, loaded or minted.

    `tenant_id` is required and not defaulted. A boundary that could be built
    without one is a boundary whose tokens belong to nobody, and the point of
    the scope is that it cannot be omitted.
    """
    from app.models.database import InvestigationTokenMap

    tenant = str(tenant_id or "").strip()
    investigation = str(investigation_id or "").strip()
    if not tenant:
        raise TokenBoundaryError("a token boundary needs a tenant; refusing to build an unscoped map")
    if not investigation:
        raise TokenBoundaryError("a token boundary needs an investigation id")

    row = (
        db.query(InvestigationTokenMap)
        .filter(
            InvestigationTokenMap.tenant_id == tenant,
            InvestigationTokenMap.investigation_id == investigation,
        )
        .one_or_none()
    )
    if row is None:
        row = InvestigationTokenMap(
            id=uuid.uuid4(),
            tenant_id=tenant,
            investigation_id=investigation,
            fingerprint=fingerprint_for(tenant, investigation),
            token_map={},
            expires_at=now() + ttl,
        )
        db.add(row)
        db.flush()

    return TokenBoundary(
        TokenMapState(
            tenant_id=row.tenant_id,
            investigation_id=row.investigation_id,
            fingerprint=row.fingerprint,
            token_map=dict(row.token_map or {}),
            expires_at=row.expires_at,
        ),
        now=now,
    )


def save_boundary(db: Any, boundary: TokenBoundary) -> None:
    """Persist what the boundary learned. Call after a tokenising pass."""
    from app.models.database import InvestigationTokenMap

    row = (
        db.query(InvestigationTokenMap)
        .filter(
            InvestigationTokenMap.tenant_id == boundary.tenant_id,
            InvestigationTokenMap.investigation_id == boundary.investigation_id,
        )
        .one_or_none()
    )
    if row is None:
        return
    row.token_map = boundary.token_map
    db.flush()


def purge_expired(db: Any, *, now: Callable[[], datetime] = _now) -> int:
    """Delete every map whose lifetime has ended. Returns how many.

    The lifetime is the point: this table holds real identifiers in exchange
    for reversibility, so something has to actually remove them. A TTL column
    nothing deletes on is a comment.
    """
    from app.models.database import InvestigationTokenMap

    deleted = (
        db.query(InvestigationTokenMap)
        .filter(InvestigationTokenMap.expires_at < now())
        .delete(synchronize_session=False)
    )
    db.flush()
    return int(deleted or 0)


def purge_investigation(db: Any, *, tenant_id: str, investigation_id: str) -> int:
    """Delete one investigation's map, before its TTL.

    For the end of a run: the map is only needed while the loop is running,
    and keeping it until expiry is keeping identifiers for no reason.
    """
    from app.models.database import InvestigationTokenMap

    deleted = (
        db.query(InvestigationTokenMap)
        .filter(
            InvestigationTokenMap.tenant_id == str(tenant_id or "").strip(),
            InvestigationTokenMap.investigation_id == str(investigation_id or "").strip(),
        )
        .delete(synchronize_session=False)
    )
    db.flush()
    return int(deleted or 0)


# ── for tests and callers without a database ─────────────────────────────


def in_memory(
    *, tenant_id: str, investigation_id: str, ttl: timedelta | None = DEFAULT_TTL,
    now: Callable[[], datetime] = _now,
) -> TokenBoundary:
    """A boundary with no persistence. Same rules, no row."""
    return TokenBoundary(
        TokenMapState(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            fingerprint=fingerprint_for(tenant_id, investigation_id),
            token_map={},
            expires_at=(now() + ttl) if ttl else None,
        ),
        now=now,
    )
