"""
The shared reasoning rules must actually reach the prompts that need them.

These rules exist because the same misreadings kept arriving from different
prompts. They live in one module and are composed in, so the risk is no longer
divergence between copies — it is a composition quietly being dropped in a
refactor, which nothing else would catch.
"""

from __future__ import annotations

import re

from app.analyst import analysis_guidance as g
from app.analyst.system_prompt import ANALYST_SYSTEM_PROMPT
from app.services.assistant_prompt_service import (
    ALERT_ANALYSIS_SYSTEM_PROMPT,
    INCIDENT_CORRELATION_SYSTEM_PROMPT,
)
from app.services.attack_ai_service import SYSTEM_PROMPT as ATTACK_SYSTEM_PROMPT


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _contains(prompt: str, block: str) -> bool:
    return _flat(block) in _flat(prompt)


# ── The blocks themselves ────────────────────────────────────────────────────

def test_ip_roles_cover_every_class_and_reject_federated_travel():
    block = _flat(g.IP_ROLE_CLASSIFICATION)
    for role in ("end-user client", "service / api backend", "cloud / cdn egress",
                 "nat / vpn / proxy egress", "external actor"):
        assert role in block, f"IP role missing: {role}"
    # The specific misreading this exists to stop.
    assert "not evidence of anomalous location or travel" in block
    assert "two or more interactive human logins" in block


def test_vendor_scores_are_inputs_not_conclusions():
    block = _flat(g.VENDOR_RISK_SCORES)
    assert "inputs to weigh, not conclusions to adopt" in block
    # The self-justifying sentence that prompted the rule.
    assert "the verified verdict is malicious" in block
    assert "in the same breath" in block


def test_benign_patterns_name_each_named_case():
    block = _flat(g.KNOWN_BENIGN_PATTERNS)
    for case in ("gpscript.exe", "silverfort", "windowsupdate.com",
                 "seloaddriverprivilege", "heur"):
        assert case in block, f"benign pattern missing: {case}"
    # Naming a pattern must not become a way to skip the alert.
    assert "not a reason to skip the alert" in block


def test_attempted_is_distinguished_from_successful():
    block = _flat(g.ATTEMPTED_VS_SUCCESSFUL)
    assert "is an attempt, not a successful connection" in block
    assert "a finding, not a reason to escalate" in block


def test_decode_promises_must_be_kept():
    assert "dangling promise" in _flat(g.FINISH_EVERY_DECODE)


def test_verdict_must_match_its_reasoning():
    block = _flat(g.VERDICT_COHERENCE)
    assert "choose one verdict" in block
    assert "no malicious payload or confirmed compromise" in block


# ── Composition into each prompt ─────────────────────────────────────────────

def test_alert_and_correlation_prompts_carry_every_rule():
    """Both interpret a whole alert, so both need all six."""
    for prompt in (ALERT_ANALYSIS_SYSTEM_PROMPT, INCIDENT_CORRELATION_SYSTEM_PROMPT):
        for block in (g.IP_ROLE_CLASSIFICATION, g.VENDOR_RISK_SCORES,
                      g.KNOWN_BENIGN_PATTERNS, g.ATTEMPTED_VS_SUCCESSFUL,
                      g.FINISH_EVERY_DECODE, g.VERDICT_COHERENCE):
            assert _contains(prompt, block)


def test_indicator_analyst_carries_the_rules_it_can_act_on():
    for block in (g.IP_ROLE_CLASSIFICATION, g.VENDOR_RISK_SCORES,
                  g.KNOWN_BENIGN_PATTERNS, g.ATTEMPTED_VS_SUCCESSFUL,
                  g.FINISH_EVERY_DECODE, g.VERDICT_COHERENCE):
        assert _contains(ANALYST_SYSTEM_PROMPT, block)


def test_attack_mapper_gets_the_rules_that_change_a_mapping():
    """
    IP roles are in here deliberately: a service backend or CDN egress address
    is not command-and-control, and mapping an exfiltration technique onto
    federated-auth traffic invents an attack out of ordinary topology.
    """
    for block in (g.IP_ROLE_CLASSIFICATION, g.KNOWN_BENIGN_PATTERNS,
                  g.ATTEMPTED_VS_SUCCESSFUL):
        assert _contains(ATTACK_SYSTEM_PROMPT, block)

    # It proposes techniques rather than a verdict, so verdict coherence would
    # be dead weight on every call.
    assert not _contains(ATTACK_SYSTEM_PROMPT, g.VERDICT_COHERENCE)


def test_attack_mapper_still_returns_only_json():
    """The guidance is appended to a prompt whose output contract is strict."""
    assert "return only json" in _flat(ATTACK_SYSTEM_PROMPT)


# ── Writing style ────────────────────────────────────────────────────────────

def test_writing_style_reaches_the_alert_prompt():
    for block in (g.PROCESS_SUMMARIZATION, g.INTERNAL_IP_COLLAPSE,
                  g.PUBLIC_IP_IDENTITY_CARD, g.OUTCOME_OVER_REPUTATION,
                  g.DROP_LOW_VALUE_DETAIL, g.LENGTH_TONE_AND_CLOSING):
        assert _contains(ALERT_ANALYSIS_SYSTEM_PROMPT, block)


def test_correlation_gets_the_style_but_not_the_resolution_length_rules():
    """
    Correlation writes a multi-section incident report with its own Timeline and
    Indicators of Compromise. The two-to-four-sentence resolution shape, ending
    on a single disposition line, would fight that structure.
    """
    for block in (g.PROCESS_SUMMARIZATION, g.INTERNAL_IP_COLLAPSE,
                  g.PUBLIC_IP_IDENTITY_CARD, g.OUTCOME_OVER_REPUTATION,
                  g.DROP_LOW_VALUE_DETAIL):
        assert _contains(INCIDENT_CORRELATION_SYSTEM_PROMPT, block)
    assert not _contains(INCIDENT_CORRELATION_SYSTEM_PROMPT, g.LENGTH_TONE_AND_CLOSING)


def test_alert_prompt_no_longer_orders_a_hash_into_every_report():
    """
    It used to say "when a file hash is available, include it once in a short
    final sentence with its algorithm", which directly contradicts dropping
    low-value forensic detail. Two contradictory orders in one prompt produce
    inconsistent reports, so the old rule was rewritten rather than buried.
    """
    flat = _flat(ALERT_ANALYSIS_SYSTEM_PROMPT)
    assert "include it once in a short final sentence" not in flat
    assert "only where it is the actionable ioc to block" in flat


def test_alert_prompt_keeps_naming_the_process_that_drives_the_verdict():
    """Summarising the cluster must not licence vagueness about what mattered."""
    flat = _flat(ALERT_ANALYSIS_SYSTEM_PROMPT)
    assert "name explicitly the one or two processes that actually drive the verdict" in flat
    # ...while everything else is reduced to a category.
    assert "reduce everything else to its category" in flat
