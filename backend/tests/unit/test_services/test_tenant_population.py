"""An internal estate cannot be labelled a customer.

`c00` is Expertware's own — CrowdStrike reports one CID across 176 of 176
devices, every `machine_domain` an `expertware.net` domain — and six
documents had called it a customer's, one of them addressed outward.
Correcting the documents fixed the documents; this is what is supposed to
stop the next one.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.services import tenant_population as tp

REPO = pathlib.Path(__file__).resolve().parents[4]


def test_an_internal_estate_label_says_it_is_not_a_customer():
    label = tp.label_for(tp.INTERNAL_ESTATE, tenant_id="c00",
                         name="Expertware (C00)")
    assert "own estate" in label
    assert "not a customer" in label


def test_an_internal_estate_is_not_a_customer():
    assert tp.is_customer(tp.INTERNAL_ESTATE) is False


def test_unknown_is_not_a_synonym_for_customer():
    """Both Exabeam credentials are `unknown`. That is the whole point.

    Their API exposes no identity and their data exposes no estate, so they
    are attributable to nobody. Treating that as `customer` would be the
    conflation this module exists to prevent — the same shape as reading a
    skip as a result.
    """
    assert tp.is_customer(tp.UNKNOWN) is False
    label = tp.label_for(tp.UNKNOWN, tenant_id="lin", name="LIN")
    assert "not established" in label


def test_a_customer_is_still_labelled_a_customer():
    """The positive control.

    A module that refused to say "customer" about anything would pass every
    assertion above and make the word unusable — the RLS lesson, where six
    refusal tests were green while the feature denied every read.
    """
    assert tp.is_customer(tp.CUSTOMER) is True
    assert "customer estate" in tp.label_for(tp.CUSTOMER, tenant_id="acme",
                                             name="Acme")


@pytest.mark.parametrize("bad", ["client", "tenant", "internal", "", "CUSTOMER"])
def test_an_unrecognised_kind_refuses_rather_than_defaulting(bad):
    """Falling back to a customer label is how this went wrong for six weeks."""
    with pytest.raises(tp.UnknownTenantKind):
        tp.label_for(bad, tenant_id="x")
    with pytest.raises(tp.UnknownTenantKind):
        tp.is_customer(bad)


def test_the_model_and_the_migration_agree_on_the_closed_set():
    """Three places could disagree: the module, the model, the constraint."""
    migration = (REPO / "backend/alembic/versions/074_tenant_kind.py").read_text()
    for kind in tp.KINDS:
        assert f"'{kind}'" in migration, f"{kind} missing from the constraint"
    assert set(re.findall(r"'(customer|internal_estate|unknown)'", migration)) \
        == set(tp.KINDS)


def test_no_document_calls_c00_a_customer_or_a_client():
    """The grep the label function cannot replace.

    A formatter only binds callers that use it. Nothing stops someone typing
    "customer `c00`" into a markdown file — which is exactly what happened,
    in a document addressed to people outside Expertware. So the docs are
    asserted directly.
    """
    offenders: list[str] = []
    # `[ \t]+`, not `\s+`. The first version let the gap cross a newline and
    # matched a heading ending "...not a client" against the next line
    # starting "C00 is a tenant" — a document saying the right thing,
    # reported as saying the wrong one. A grep-based control's false
    # positives are its own defect, not a finding.
    pattern = re.compile(r"(customer|client)[ \t]+`?c00`?", re.IGNORECASE)
    for path in (REPO / "docs").rglob("*.md"):
        text = path.read_text(errors="replace")
        for match in pattern.finditer(text):
            line = text[:match.start()].count("\n") + 1
            context = text[max(0, match.start() - 90):match.end() + 40]
            # A line that quotes the old wording in order to correct it is
            # not an offence — the correction notes do exactly that.
            if any(word in context.lower() for word in
                   ("previously read", "had called", "corrected", "used to say",
                    "no document", "it is not", "wrongly")):
                continue
            offenders.append(f"{path.relative_to(REPO)}:{line}")
    assert offenders == [], (
        "c00 is Expertware's own estate (CID eed7e418…, 176/176 devices on an "
        f"expertware.net domain). These call it a customer's: {offenders}"
    )
