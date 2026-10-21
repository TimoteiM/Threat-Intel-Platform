"""Whose estate is this? Ask, do not assume.

`c00` was called a customer's in six documents, one of them addressed
outward, while CrowdStrike's own identifiers said it is Expertware's: one
CID across 176 of 176 devices, every `machine_domain` an `expertware.net`
domain. Correcting the documents fixed the documents. This module is what
stops the next one.

**The enforcement is that there is one function for naming a population, and
it cannot return the word "customer" for an estate that is not one.** A
caller that wants to describe whose data a figure describes calls
`describe()`. A caller that hand-writes "customer c00" is not using this
module, which is why `test_no_document_can_call_an_internal_estate_a_customer`
also greps the docs.

Kinds are a closed set, checked by a database constraint in migration 074:

* `customer` — someone else's estate. The default for a tenant created by an
  arriving alert, because presuming "someone else's data" is the safer
  presumption.
* `internal_estate` — ours. Not a customer, and no figure derived from it is
  a client figure.
* `unknown` — the owner genuinely cannot be established. Both Exabeam
  credentials are in this state: their API exposes no identity and their data
  exposes no estate (backlog 47). **Not a synonym for `customer`** — that
  conflation is the thing this exists to prevent.
"""

from __future__ import annotations

from typing import Any

CUSTOMER = "customer"
INTERNAL_ESTATE = "internal_estate"
UNKNOWN = "unknown"
KINDS = (CUSTOMER, INTERNAL_ESTATE, UNKNOWN)

#: Words that may not appear in a label for a non-customer population. Held
#: here so the test and the formatter cannot drift.
CUSTOMER_WORDS = ("customer", "client")


class UnknownTenantKind(ValueError):
    """A kind outside the closed set. Fails rather than defaulting."""


def label_for(kind: str, *, tenant_id: str, name: str | None = None) -> str:
    """How to name this population in anything a person reads.

    Raises on an unrecognised kind instead of falling back to a customer
    label — falling back is how `c00` was described for six weeks.
    """
    shown = name or tenant_id
    if kind == INTERNAL_ESTATE:
        return f"{shown} — Expertware's own estate (not a customer)"
    if kind == CUSTOMER:
        return f"{shown} — customer estate"
    if kind == UNKNOWN:
        return (f"{shown} — owner not established; not attributable to a "
                f"customer or to us")
    raise UnknownTenantKind(
        f"tenant {tenant_id!r} has kind {kind!r}, which is not one of {KINDS}; "
        f"refusing to guess a population label"
    )


def is_customer(kind: str) -> bool:
    """True only for `customer`. `unknown` is not a customer."""
    if kind not in KINDS:
        raise UnknownTenantKind(f"{kind!r} is not one of {KINDS}")
    return kind == CUSTOMER


def describe(session: Any, tenant_id: str) -> str:
    """The label for a tenant, read from the row rather than inferred."""
    from sqlalchemy import text

    row = session.execute(
        text("SELECT kind, name FROM tenants WHERE tenant_id = :t"),
        {"t": tenant_id},
    ).first()
    if row is None:
        # An absence, named. Not "customer".
        return (f"{tenant_id} — no tenant row, so whose estate this is has "
                f"never been recorded")
    return label_for(row[0], tenant_id=tenant_id, name=row[1])
