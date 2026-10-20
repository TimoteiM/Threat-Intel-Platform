"""The one hop the playbook cannot plan: what is still missing.

**The agent's whole contract is three sentences.** It sees what the playbook
already gathered, in tokens. It returns template *selections* — a template
name and token arguments. It never composes a query string, never names a
source, and never sees a real hostname.

**What is here is a deterministic policy, not a model**, and that is a
deliberate stage rather than a stand-in that got forgotten. The design note's
order is playbook first, instrumented, *then* measure whether a model earns
its place in the tail — so this implements the rule the note specifies and
leaves the seam a model plugs into. `default_agent` can be replaced with a
model-backed callable of the same signature without the loop changing, and
the loop's budget, refusals and fan-out cap apply identically to both, because
they are enforced on the selections rather than asked of the selector.

The rule it implements, from §3:

* pivot on an indicator the alert did **not** carry — a hash that reaches
  other hosts, an address seen elsewhere, a second account. An indicator the
  alert already named is what the playbook just queried;
* only `pivotable` templates, which are the ones whose cost is one call
  whatever the answer;
* **depth 1** — this is called once and its results are never pivoted on.

Everything it reads is tokenised, so "a hash that appears on three hosts" is
`[HASH_a3f9c1_1]` appearing beside three distinct `[HOST_…]` tokens. The
decision needs the *shape* of the evidence, not the values, which is the
property that makes the whole arrangement safe.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class Selection:
    """One thing the agent wants asked.

    `because` is carried into the record as the query's reason, so an analyst
    reading the record sees why the second hop happened rather than that it
    did.
    """

    template: str
    arguments: dict[str, str]
    because: str


#: **There is no minimum spread, and that is the correction that made the
#: second hop work at all.**
#:
#: The first rule required an indicator to appear on two or more hosts before
#: pivoting on it, reasoning that one host is the host the alert already
#: named. That rule can never fire on the case it exists for: when a
#: playbook query returns a hash from a single host, *how many hosts ran it*
#: is exactly the unknown the pivot would resolve — demanding the answer as
#: the entry condition means never asking the question. Measured on the mock
#: corpus, it produced zero pivots across every playbook-covered class,
#: including the one built to trigger it.
#:
#: What bounds the hop instead is already structural: the alert's own
#: indicators are excluded (the playbook asked), only `pivotable` templates
#: are allowed (one call whatever the answer), the fan-out is capped, and
#: depth is 1. Spread survives as the RANKING key, so when the cap bites it
#: keeps the indicator that reaches furthest.
_RANK_BY_SPREAD = True


def _token_kind(token: str) -> str:
    """`HASH` from `[HASH_a3f9c1_1]`. Empty for anything that is not a token.

    Parsed from the token grammar rather than from the value, because the
    agent has no values — the kind is the only thing it can tell about an
    indicator, and that is enough to choose a template.
    """
    from app.services import token_boundary as tb

    match = tb.TOKEN_RE.fullmatch(str(token or "").strip())
    return match.group("prefix") if match else ""


def _indicators(events: Sequence[Mapping[str, Any]]) -> dict[str, Counter]:
    """Which tokens appeared, and on how many distinct hosts.

    Returns kind -> Counter(token -> host count). The host count is the
    spread: it is what separates "an indicator this alert is about" from "an
    indicator that reaches further", and it is computable from tokens alone.
    """
    spread: dict[str, dict[str, set[str]]] = {}
    for event in events:
        host = str((event.get("agent") or {}).get("name") or "")
        for token in _tokens_in(event):
            kind = _token_kind(token)
            if not kind:
                continue
            spread.setdefault(kind, {}).setdefault(token, set()).add(host)
    return {
        kind: Counter({token: len(hosts) for token, hosts in by_token.items()})
        for kind, by_token in spread.items()
    }


#: Where an indicator lives in a normalised event, and what kind it is.
#:
#: Read by **declared field**, not by sniffing string shapes. The first
#: version looked for anything token-shaped anywhere in the event and that
#: was wrong twice over:
#:
#: * it found the reporting host's own IP — `agent.ip` is on every record by
#:   construction — and pivoted on it. An indicator true of every row cannot
#:   discriminate between rows, which is a shape this codebase has now found
#:   five times.
#: * it could not see a **hash at all**, because the boundary tokenises
#:   HOST, ACCOUNT and IP and deliberately leaves a SHA-256 alone: a file
#:   hash identifies a binary the whole industry can look up, not this
#:   customer's estate, and tokenising it would be the over-tokenisation that
#:   decision A warned about. So the one indicator worth pivoting on was
#:   invisible to a policy that only understood tokens.
#:
#: The `agent` block is excluded entirely: it says who reported the event,
#: not what the event saw. `full_log` likewise — it is a rendering of the
#: other fields, so a token in it is already counted and counting it twice
#: inflates the spread that decides whether to pivot.
INDICATOR_FIELDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("process", "sha256"), "HASH"),
    (("network", "src_ip"), "IP"),
    (("network", "dst_ip"), "IP"),
    (("users",), "ACCOUNT"),
)


def _dig(event: Mapping[str, Any], path: tuple[str, ...]) -> list[str]:
    """The value(s) at a declared path, as a list of non-empty strings."""
    node: Any = event
    for part in path:
        if not isinstance(node, Mapping):
            return []
        node = node.get(part)
    if isinstance(node, str):
        return [node] if node.strip() else []
    if isinstance(node, (list, tuple)):
        return [str(v) for v in node if isinstance(v, str) and v.strip()]
    return []


def _host_of(event: Mapping[str, Any]) -> str:
    """The reporting host, as the token it was turned into."""
    agent_block = event.get("agent")
    if isinstance(agent_block, Mapping):
        return str(agent_block.get("name") or "")
    return ""


def _indicators(events: Sequence[Mapping[str, Any]]) -> dict[str, Counter]:
    """Which indicators appeared, and on how many distinct hosts.

    Returns kind -> Counter(value -> host count). The host count is the
    spread, and it is what separates "an indicator this alert is about" from
    "an indicator that reaches further".
    """
    spread: dict[str, dict[str, set[str]]] = {}
    for event in events:
        host = _host_of(event)
        for path, kind in INDICATOR_FIELDS:
            for value in _dig(event, path):
                # A tokenised value keeps its own kind: an ACCOUNT token in a
                # users list is an account whatever the path said.
                actual = _token_kind(value) or kind
                spread.setdefault(actual, {}).setdefault(value, set()).add(host)
    return {
        kind: Counter({value: len(hosts) for value, hosts in by_value.items()})
        for kind, by_value in spread.items()
    }


#: Which template answers a question about each kind of indicator.
#:
#: A mapping rather than an if-chain, and the loop refuses anything not
#: `pivotable` regardless — so a wrong entry here costs a refused selection
#: in the record, not an unbounded query.
_TEMPLATE_FOR_KIND = {
    "HASH": ("hash_prevalence", "hash"),
    "IP": ("source_address_logons", "ip"),
    "ACCOUNT": ("user_sessions", "user"),
}


def default_agent(
    *,
    record: Any,
    selectors: Mapping[str, str],
    budget: Any,
) -> list[Selection]:
    """What is still worth asking, given what the playbook already has.

    Pure: it reads the record and returns selections. It executes nothing,
    which is what lets the loop apply the budget and the fan-out cap to its
    output rather than trusting it to respect them.
    """
    already_asked = {
        (o.template, tuple(sorted(o.arguments.items()))) for o in record.outcomes
    }
    from_alert = set(selectors.values())

    # ── the tail: no playbook row, so nothing has been gathered yet ──
    #
    # §3.3 of the design note: for the 19% of alerts in no top-ten row, the
    # agent picks which templates to run **from the same fixed set**. The
    # first version only pivoted on gathered evidence, so an alert with no
    # row got no queries at all — the tail was the case the agent exists for
    # and the one it did nothing about.
    if not record.outcomes:
        return _cold_start(selectors, already_asked)

    selections: list[tuple[int, Selection]] = []
    for kind, counts in _indicators(record.events).items():
        mapping = _TEMPLATE_FOR_KIND.get(kind)
        if mapping is None:
            continue
        template, selector = mapping
        for token, host_count in counts.most_common():
            if token in from_alert:
                # The alert already named it, so the playbook has asked.
                continue
            arguments = {selector: token}
            if (template, tuple(sorted(arguments.items()))) in already_asked:
                continue
            selections.append((host_count, Selection(
                template=template,
                arguments=arguments,
                because=(
                    f"this {kind.lower()} was not on the alert and appears on "
                    f"{host_count} host(s) in what the playbook gathered"
                ),
            )))

    # Widest spread first: when the fan-out cap bites it should keep the
    # indicator that reaches furthest, not whichever was found first.
    selections.sort(key=lambda pair: pair[0], reverse=True)
    return [selection for _, selection in selections]


def _cold_start(
    selectors: Mapping[str, str],
    already_asked: set[tuple[str, tuple[tuple[str, str], ...]]],
) -> list[Selection]:
    """Templates for an alert whose class has no playbook row.

    Every template whose selectors the alert can fill, cheapest first, and
    the loop's budget decides how many of them actually run. Choosing from
    the fixed set is the point: the tail gets the same bounded vocabulary as
    everything else, not a free hand.

    Note the asymmetry with the pivot path, which is deliberate: a pivot may
    only select `pivotable` templates because it acts on evidence the alert
    did not carry, where this acts on the alert's own selectors — the same
    keys a playbook row would have used had one existed.
    """
    from app.services.context_gathering.playbook import TEMPLATES

    out: list[Selection] = []
    for template in sorted(TEMPLATES.values(), key=lambda t: (t.declared_calls, t.name)):
        if any(not selectors.get(s) for s in template.selectors):
            continue
        arguments = {s: selectors[s] for s in template.selectors}
        if (template.name, tuple(sorted(arguments.items()))) in already_asked:
            continue
        out.append(Selection(
            template=template.name,
            arguments=arguments,
            because=(
                f"no playbook row for this event class; {template.purpose} "
                f"is available from the alert's own keys"
            ),
        ))
    return out
