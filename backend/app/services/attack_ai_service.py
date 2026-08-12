"""
The constrained AI pass over ATT&CK assessment.

The deterministic pass answers what a matched command or a collected verdict
*is*. What it cannot do is read a narrative: an alert describing a user opening
an attachment that then reached out to a newly-registered domain is a chain a
model recognises and a regex does not.

So the model is allowed to propose — and then everything it says is checked
before any of it reaches a report:

    1. the technique id must be in TECHNIQUE_DB, our whitelist of techniques
       this platform can evidence. An id outside it is dropped, not repaired.
    2. it must cite `evidence_quote`, and that quote must actually appear in
       the alert body or in a finding from this run. A quote we cannot locate
       is a fabrication and the whole proposal is dropped.
    3. it may not contradict the deterministic pass: a technique already
       confirmed by a signal keeps the signal's evidence, and the model cannot
       downgrade it.
    4. anything malformed — not JSON, missing fields, wrong types — yields no
       techniques at all rather than a partial guess.

The model therefore cannot introduce a technique out of nothing; the worst it
can do is fail to propose one, which costs nothing but a missed suggestion.
Proposals are marked `source: "ai_suggested"` and carry their quote, so an
analyst can always see which claims came from a model and check them.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Sequence

from app.analyst.attack_mapping import (
    describe_technique,
    get_technique_info,
    normalize_technique_id,
)

logger = logging.getLogger(__name__)

# Only ever a suggestion — never enough to confirm a detection's claim on its own.
AI_CONFIDENCE = "low"

MAX_PROPOSALS = 6
MIN_QUOTE_CHARS = 8

SYSTEM_PROMPT = """You map security alert evidence to MITRE ATT&CK techniques.

Rules you must follow exactly:
- Only propose a technique if the supplied evidence directly shows it.
- You MUST quote the exact substring of the evidence that shows it, verbatim.
- If nothing in the evidence supports any technique, return an empty list.
- Never propose a technique because it is typical, likely, or usually seen with
  the others. Absence of evidence is not evidence.
- Return ONLY JSON: {"techniques": [{"id": "T1566.002", "evidence_quote": "...",
  "reasoning": "one sentence"}]}
"""


def propose_techniques(
    *,
    alert_body: str,
    findings_digest: str,
    already_evidenced: Sequence[str],
    call_model,
) -> list[dict[str, Any]]:
    """
    Ask the model for techniques the deterministic pass could not see.

    `call_model` is injected — a callable taking (system, user) and returning
    text — so this stays testable without a network and without binding to a
    provider. Never raises: a failed or malformed proposal yields nothing.
    """
    evidence_text = f"{alert_body}\n\n{findings_digest}"
    if not evidence_text.strip():
        return []

    user_prompt = (
        f"Evidence from the investigation:\n---\n{evidence_text[:12000]}\n---\n\n"
        f"Techniques already established from deterministic signals (do not repeat "
        f"these): {', '.join(already_evidenced) or 'none'}\n\n"
        f"Which additional ATT&CK techniques does this evidence directly show?"
    )

    try:
        raw = call_model(SYSTEM_PROMPT, user_prompt)
    except Exception as exc:
        logger.warning("ATT&CK AI proposal call failed: %s", exc)
        return []

    proposals = _parse(raw)
    if not proposals:
        return []

    established = {normalize_technique_id(t) for t in already_evidenced}
    accepted: list[dict[str, Any]] = []
    for proposal in proposals[:MAX_PROPOSALS]:
        validated = _validate(proposal, evidence_text, established)
        if validated is not None:
            accepted.append(validated)
            established.add(validated["id"])
    if len(accepted) < len(proposals):
        logger.info(
            "ATT&CK AI proposals: %d of %d accepted, the rest failed validation",
            len(accepted),
            len(proposals),
        )
    return accepted


# ── Validation ────────────────────────────────────────────────────────────────


def _parse(raw: str) -> list[dict[str, Any]]:
    """The model's JSON, or nothing. A partial parse is not attempted."""
    text = str(raw or "").strip()
    if not text:
        return []
    # Models fence JSON in markdown often enough to be worth handling.
    fenced = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        logger.info("ATT&CK AI proposal was not JSON; discarding it whole")
        return []
    techniques = payload.get("techniques") if isinstance(payload, dict) else payload
    if not isinstance(techniques, list):
        return []
    return [item for item in techniques if isinstance(item, dict)]


def _validate(
    proposal: dict[str, Any],
    evidence_text: str,
    established: set[str],
) -> dict[str, Any] | None:
    """One proposal, accepted only if every guardrail passes."""
    technique = normalize_technique_id(str(proposal.get("id") or ""))
    if not technique:
        return None

    # 1. Whitelist. An unknown id is dropped rather than reported as unknown —
    #    unlike a detection's own claim, nobody asked for this one.
    info = get_technique_info(technique)
    if info is None:
        logger.info("ATT&CK AI proposed %s, which is not in the technique whitelist", technique)
        return None

    # 3. Never override what the deterministic pass already established.
    if technique in established:
        return None

    # 2. The citation must exist in the evidence we actually hold.
    quote = str(proposal.get("evidence_quote") or "").strip()
    if len(quote) < MIN_QUOTE_CHARS or not _quote_present(quote, evidence_text):
        logger.info(
            "ATT&CK AI proposed %s citing text not found in the evidence; dropped", technique
        )
        return None

    # Whitelisted, so `describe_technique` always answers; it is used rather
    # than the whitelist entry so the tactic label matches the rest of the
    # platform's ATT&CK vocabulary.
    described = describe_technique(technique) or info
    return {
        "id": technique,
        "name": described["name"],
        "tactic": described["tactic"],
        "tactics": described.get("tactics") or [described["tactic"]],
        "url": described["url"],
        "known": True,
        "evidenceable": True,
        "status": "additional",
        "confidence": AI_CONFIDENCE,
        "source": "ai_suggested",
        "evidence": [
            {
                "signal_id": "ai_suggested",
                "signal": "Proposed by AI analysis of the alert narrative",
                "severity": "info",
                "matched": quote[:200],
                "reasoning": str(proposal.get("reasoning") or "")[:300] or None,
            }
        ],
        "explanation": (
            f"Suggested by AI from the alert narrative, quoting: \"{quote[:120]}\". "
            f"Not established by a deterministic signal — treat as a lead, not a finding."
        ),
    }


def propose_attack_techniques(
    *,
    alert_body: str,
    findings_digest: str,
    already_evidenced: Sequence[str],
    model: str | None = None,
) -> list[dict[str, Any]]:
    """
    `propose_techniques` bound to the configured provider, for the Celery worker.

    Synchronous and self-contained: the worker is not async, and a failure here
    must not touch the run. Uses the same OpenAI-primary / Anthropic-fallback
    order as the rest of the platform.
    """
    def call_model(system: str, user: str) -> str:
        return _complete(system, user, model=model)

    return propose_techniques(
        alert_body=alert_body,
        findings_digest=findings_digest,
        already_evidenced=already_evidenced,
        call_model=call_model,
    )


def _complete(system: str, user: str, *, model: str | None) -> str:
    """
    One completion, the configured provider first and Anthropic as fallback.

    Synchronous `invoke`, not `ainvoke`: this runs inside a Celery task with no event loop
    of its own.

    Never raises — every failure returns "", because a missing ATT&CK proposal must not
    touch the run. Note the primary is also abandoned on *empty* text, which
    `.with_fallbacks()` could not express because it only fires on exceptions.
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    from app.analyst.models import (
        build_anthropic_model,
        build_model,
        configured_model_id,
        message_text,
        primary_model_configured,
    )
    from app.config import get_settings
    from app.services.provider_usage_metrics import record_provider_request

    settings = get_settings()
    # Resolved from the configured provider, so a local deployment does not ask its server
    # for settings.openai_model.
    chosen = (model or configured_model_id(settings) or "").strip()
    messages = [SystemMessage(system), HumanMessage(user)]

    if primary_model_configured(settings) and not chosen.startswith("claude-"):
        try:
            record_provider_request("openai", scope="attack_assessment")
            text = message_text(build_model(chosen or None, max_tokens=1024).invoke(messages))
            if text.strip():
                return text
        except Exception as exc:
            logger.warning("ATT&CK AI: primary call failed (%s), trying fallback", exc)

    if not settings.anthropic_api_key:
        return ""
    try:
        record_provider_request("anthropic", scope="attack_assessment")
        # Preserved quirk: the fallback uses settings.anthropic_model and ignores the
        # caller's `model`. Changing that is a behaviour change, so it is left alone rather
        # than fixed as a side effect of the provider migration.
        return message_text(build_anthropic_model(max_tokens=1024).invoke(messages))
    except Exception as exc:
        logger.warning("ATT&CK AI: fallback call failed (%s)", exc)
        return ""


def _quote_present(quote: str, evidence_text: str) -> bool:
    """
    Whether the model's quote really appears in the evidence.

    Compared on collapsed whitespace and case, because a model reflows what it
    quotes; anything looser would defeat the point of asking for a quote.
    """
    haystack = re.sub(r"\s+", " ", evidence_text).lower()
    needle = re.sub(r"\s+", " ", quote).lower()
    return needle in haystack
