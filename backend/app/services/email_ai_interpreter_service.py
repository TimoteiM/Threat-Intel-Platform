"""
Single-shot AI interpretation for email investigation results.

Uses one model call after all deterministic indicator checks are complete.
The AI only receives suspicious/malicious URLs and attachments — clean items are skipped.
The AI does NOT produce formatted_resolution; that is built by _render_template_resolution
using AI-provided narratives woven into the bullet-point template.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
from app.services.provider_usage_metrics import record_provider_request

logger = logging.getLogger(__name__)

PRIMARY_MODEL = "gpt-5.6-luna"
FALLBACK_MODEL = "claude-haiku-4-5-20251001"


# ── Tier-1 structured output ─────────────────────────────────────────────────────
#
# Mirrors the JSON shape the system prompt asks for. It exists to make the model's
# *output well-formed*, not to define this service's output contract — that is
# `_parse_interpreter_output`, which every caller downstream depends on, so a validated
# result is serialized straight back to JSON text and fed through it.
#
# Enums are Literal rather than str so the provider constrains them at generation time;
# `_parse_interpreter_output` clamps them again for the free-text tier.

class _Strict(BaseModel):
    # Providers running strict structured output require additionalProperties:false on
    # every nested object, and Pydantic only emits it for models that forbid extras.
    model_config = ConfigDict(extra="forbid")


class SenderCompany(_Strict):
    name: str
    description: str


class DomainFinding(_Strict):
    title: str
    severity: Literal["low", "medium", "high"]
    description: str


class SenderDomainAnalysis(_Strict):
    classification: Literal["benign", "suspicious", "malicious", "unknown"]
    primary_reasoning: str
    findings: list[DomainFinding] = []


class UrlAssessment(_Strict):
    url: str
    where_it_points: str
    legitimacy: Literal["legitimate", "suspicious", "malicious", "unknown"]
    narrative: str


class AttachmentNarrative(_Strict):
    filename: str
    sha256: Optional[str] = None
    narrative: str


class EmailInterpretation(_Strict):
    overall_verdict: Literal["clean", "suspicious", "malicious", "inconclusive"]
    confidence: Literal["low", "medium", "high"]
    primary_signals: list[str] = []
    url_summary: str
    sender_company: SenderCompany
    sender_domain_analysis: SenderDomainAnalysis
    url_assessments: list[UrlAssessment] = []
    attachment_narratives: list[AttachmentNarrative] = []


SYSTEM_PROMPT = """You are a Senior SOC Analyst AI performing structured email threat investigations.

Rules:
- Use only evidence provided. Never invent data.
- If data is missing, output exactly: "Not present in the provided evidence."
- Do NOT speculate. Do NOT assume legitimacy without evidence.
- Classify malicious only when attacker-controlled infrastructure is required.
- Be concise and factual.

Email-specific classification rules (apply strictly):
- If SPF=fail AND DMARC policy is none or absent: sender_domain classification is at minimum "suspicious".
- Missing/none SPF, DKIM, or DMARC alone is an authentication gap only; it is NOT enough to classify
  the email, sender domain, or overall verdict as suspicious.
- If domain_age_days < 30: HIGH-severity signal; include prominently in findings.
- If domain_age_days < 7: EXTREME signal; overall_verdict must be at minimum "suspicious".
- If any URL has credential_form_present=true: overall_verdict is at minimum "suspicious".
- If any attachment vt.malicious_count > 0: overall_verdict = "malicious", confidence = "high".
- If AnyRun verdict is "malicious" for any item AND threat_score >= 95: overall_verdict = "malicious".
- If AnyRun verdict is "malicious" for any item AND threat_score < 95: treat as suspicious signal only — do NOT set overall_verdict = "malicious" on this alone.
- If spoofability_score is "high": mention the domain can be trivially spoofed, but do NOT raise
  overall_verdict to suspicious unless another concrete risk signal is present.

You will receive:
- ONLY suspicious or malicious URLs and attachments (clean ones are excluded from url_assessments/attachment_narratives).
- A list of ALL unique URL domains found in the email (all_url_domains) — use this for url_summary only.

Your job is to provide:
1. A url_summary — one sentence describing where the email's URLs lead, using plain company/service names (e.g. "The URLs redirect to the official pages of Microsoft, Caseware, and a Sendinblue email tracking platform."). Base this on all_url_domains.
2. What each suspicious/malicious URL actually does — where it leads, what happens.
3. What each suspicious/malicious attachment does — what the file is, what it executes or delivers.
4. A classification and findings for the sender domain.
5. An overall verdict.

Output format — return ONLY a valid JSON object:
{
  "overall_verdict": "clean|suspicious|malicious|inconclusive",
  "confidence": "low|medium|high",
  "primary_signals": ["2-5 decisive evidence strings that drove the verdict"],
  "url_summary": "One sentence describing where the email URLs lead, using recognizable service/company names. If no URLs: 'No URLs were found in the email.' If all clean: 'The URLs redirect to legitimate services including X, Y, Z.' If risky: mention the suspicious destination briefly.",
  "sender_company": {
    "name": "company/entity tied to sender domain or Not present in the provided evidence.",
    "description": "one short plain-English sentence describing what the company/organization does (e.g. 'Caseware is an audit and accounting software provider.'). Do NOT include registrar, WHOIS, domain age, or technical metadata. If unknown: Not present in the provided evidence."
  },
  "sender_domain_analysis": {
    "classification": "benign|suspicious|malicious|unknown",
    "primary_reasoning": "2-3 sentences as a senior SOC analyst case note. Include: what the domain is, the decisive risk signal, and the verdict inline (e.g. 'SUSPICIOUS — medium confidence'). No headings, no labels.",
    "findings": [
      {
        "title": "short finding title",
        "severity": "low|medium|high",
        "description": "evidence-based finding text"
      }
    ]
  },
  "url_assessments": [
    {
      "url": "original extracted URL",
      "where_it_points": "resolved destination/final URL or Not present in the provided evidence.",
      "legitimacy": "legitimate|suspicious|malicious|unknown",
      "narrative": "1-3 sentences describing what this URL does, where it leads, what the user experiences. Write as an analyst would in a report — e.g. 'This URL redirects to a credential harvesting page mimicking Microsoft login. The redirect chain passes through two intermediary domains before landing on the phishing page.'"
    }
  ],
  "attachment_narratives": [
    {
      "filename": "original attachment filename",
      "sha256": "hash or Not present in the provided evidence.",
      "narrative": "1-3 sentences describing what this attachment is and what it does — e.g. 'This HTML file presents a fake document preview and prompts the user to enter credentials. The form POSTs to an attacker-controlled endpoint regardless of input.'"
    }
  ]
}

Requirements for url_summary:
- Write as a plain analyst sentence, naming services/companies — not raw domains or URLs.
- If all_url_domains is empty: "No URLs were found in the email."
- If risky URLs exist, briefly note the suspicious destination in the same sentence.

Requirements for sender_domain_analysis:
- findings must include 2-6 items when enough evidence exists.
- When WHOIS evidence is present: at least one finding covering registrar, age, and status.
- When email_security evidence is present: findings for DMARC, SPF, DKIM, spoofability.
- If sender domain evidence is missing: primary_reasoning = "Not present in the provided evidence.", findings = [].

Requirements for url_assessments:
- Include ONLY the suspicious/malicious URLs provided (do not invent URLs).
- narrative must describe observable behavior, not just restate the verdict.

Requirements for attachment_narratives:
- Include ONLY the suspicious/malicious attachments provided.
- narrative must explain what the file does, not just state its VT verdict.
- If no suspicious attachments were provided, return an empty array [].
"""


async def interpret_email_results_with_ai(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return structured email interpretation with analyst narratives for suspicious items."""
    settings = get_settings()
    user_text = (
        "Analyze the following email investigation evidence.\n"
        "Only suspicious/malicious URLs and attachments are included — clean items were excluded.\n\n"
        f"```json\n{json.dumps(payload, ensure_ascii=True, indent=2)}\n```"
    )

    from app.analyst.models import configured_model_id, primary_model_configured

    text = ""
    # From the configured provider, not openai_model: under openai_compatible the latter
    # would ask the local server for a model it does not serve.
    primary_model = (configured_model_id(settings) or PRIMARY_MODEL).strip() or PRIMARY_MODEL
    fallback_model = (settings.anthropic_model or FALLBACK_MODEL).strip() or FALLBACK_MODEL
    if primary_model_configured(settings):
        try:
            text = await _call_openai(
                api_key=settings.openai_api_key,
                model=primary_model,
                system=SYSTEM_PROMPT,
                user_text=user_text,
            )
            if not (text or "").strip():
                logger.warning("Primary email interpretation returned empty output. Falling back to Anthropic.")
                text = ""
        except Exception as openai_err:
            logger.warning(
                "Primary email interpretation failed (%s: %s). Falling back to Anthropic.",
                type(openai_err).__name__,
                openai_err,
            )
            text = ""

    if not (text or "").strip():
        if not settings.anthropic_api_key:
            raise ValueError(
                "Primary and fallback AI providers are unavailable. Configure a primary "
                "(LLM_PROVIDER=openai_compatible with LLM_MODEL and LLM_BASE_URL, or "
                "OPENAI_API_KEY), or set ANTHROPIC_API_KEY as the fallback."
            )
        text = await _call_claude(
            api_key=settings.anthropic_api_key,
            model=fallback_model,
            system=SYSTEM_PROMPT,
            user_text=user_text,
        )

    return _parse_interpreter_output((text or "").strip())


def _parse_interpreter_output(text: str) -> dict[str, Any]:
    fallback: dict[str, Any] = {
        "overall_verdict": "inconclusive",
        "confidence": "low",
        "primary_signals": [],
        "url_summary": "",
        "sender_company": {
            "name": "Not present in the provided evidence.",
            "description": "Not present in the provided evidence.",
        },
        "url_assessments": [],
        "attachment_narratives": [],
        "sender_domain_analysis": {
            "classification": "unknown",
            "primary_reasoning": "Not present in the provided evidence.",
            "findings": [],
        },
    }
    if not text:
        return fallback

    parsed: dict[str, Any] | None = None
    try:
        parsed = json.loads(text)
    except Exception:
        cleaned = text
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1]
        if "```" in cleaned:
            cleaned = cleaned.split("```", 1)[0]
        cleaned = cleaned.strip()
        try:
            parsed = json.loads(cleaned)
        except Exception:
            return fallback

    if not isinstance(parsed, dict):
        return fallback

    overall_verdict = str(parsed.get("overall_verdict") or "inconclusive").lower().strip()
    if overall_verdict not in {"clean", "suspicious", "malicious", "inconclusive"}:
        overall_verdict = "inconclusive"

    confidence = str(parsed.get("confidence") or "low").lower().strip()
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"

    raw_signals = parsed.get("primary_signals")
    primary_signals: list[str] = []
    if isinstance(raw_signals, list):
        for s in raw_signals:
            if s and str(s).strip():
                primary_signals.append(str(s).strip())

    sender_company = parsed.get("sender_company")
    if not isinstance(sender_company, dict):
        sender_company = {}

    # url_assessments
    raw_urls = parsed.get("url_assessments")
    url_assessments: list[dict[str, Any]] = []
    if isinstance(raw_urls, list):
        for item in raw_urls:
            if not isinstance(item, dict):
                continue
            url_assessments.append(
                {
                    "url": str(item.get("url") or "Not present in the provided evidence."),
                    "where_it_points": str(item.get("where_it_points") or "Not present in the provided evidence."),
                    "legitimacy": str(item.get("legitimacy") or "unknown").lower(),
                    "narrative": str(item.get("narrative") or "Not present in the provided evidence."),
                    # keep reasoning as alias for backward compat with frontend
                    "reasoning": str(item.get("narrative") or item.get("reasoning") or "Not present in the provided evidence."),
                }
            )

    # attachment_narratives
    raw_atts = parsed.get("attachment_narratives")
    attachment_narratives: list[dict[str, Any]] = []
    if isinstance(raw_atts, list):
        for item in raw_atts:
            if not isinstance(item, dict):
                continue
            attachment_narratives.append(
                {
                    "filename": str(item.get("filename") or "unknown"),
                    "sha256": str(item.get("sha256") or "Not present in the provided evidence."),
                    "narrative": str(item.get("narrative") or "Not present in the provided evidence."),
                }
            )

    # sender_domain_analysis
    sda = parsed.get("sender_domain_analysis")
    if not isinstance(sda, dict):
        sda = {}
    findings = sda.get("findings")
    if not isinstance(findings, list):
        findings = []
    normalized_findings: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        normalized_findings.append(
            {
                "title": str(item.get("title") or "Untitled finding"),
                "severity": str(item.get("severity") or "medium").lower(),
                "description": str(item.get("description") or "Not present in the provided evidence."),
            }
        )

    url_summary = str(parsed.get("url_summary") or "").strip()

    return {
        "overall_verdict": overall_verdict,
        "confidence": confidence,
        "primary_signals": primary_signals,
        "url_summary": url_summary,
        "sender_company": {
            "name": str(sender_company.get("name") or "Not present in the provided evidence."),
            "description": str(sender_company.get("description") or "Not present in the provided evidence."),
        },
        "url_assessments": url_assessments,
        "attachment_narratives": attachment_narratives,
        "sender_domain_analysis": {
            "classification": str(sda.get("classification") or "unknown").lower(),
            "primary_reasoning": str(sda.get("primary_reasoning") or "Not present in the provided evidence."),
            "findings": normalized_findings,
        },
    }


async def _call_openai(api_key: str, model: str, system: str, user_text: str) -> str:
    """
    Primary interpretation, through the configured provider.

    `api_key` is now unused — build_model reads the key and the provider from settings —
    but the parameter stays so the two call sites above keep their shape and so an
    LLM_PROVIDER=openai_compatible deployment reaches this path unchanged.

    Returns JSON *text*, not a dict: `_parse_interpreter_output` owns the output contract
    and every caller downstream depends on the exact shape it produces. Tier 1 asks for
    structured output so the text is well-formed; when the model cannot hold the schema we
    fall back to free text and let the tolerant parser do its job.
    """
    from app.analyst.models import build_model, message_text

    record_provider_request("openai")
    chat = build_model(model, max_tokens=3000)
    messages = [SystemMessage(system), HumanMessage(user_text)]

    try:
        parsed = await chat.with_structured_output(EmailInterpretation).ainvoke(messages)
    except Exception as exc:
        # Small local models frequently cannot hold an 8-field nested schema. Free text
        # plus the tolerant parser is the retry they need.
        logger.info(
            "Email interpretation structured output unavailable (%s: %s); retrying as text",
            type(exc).__name__, exc,
        )
        return message_text(await chat.ainvoke(messages))

    if parsed is None:
        return ""
    return json.dumps(
        parsed.model_dump() if hasattr(parsed, "model_dump") else parsed,
        ensure_ascii=True,
    )


async def _call_claude(api_key: str, model: str, system: str, user_text: str) -> str:
    """
    Anthropic fallback. `api_key` is unused; see `_call_openai`.

    Explicitly Anthropic rather than build_model, because this is the *fallback* — routing
    it by LLM_PROVIDER would retry the same server that just failed.
    """
    from app.analyst.models import build_anthropic_model, message_text

    record_provider_request("anthropic")
    response = await build_anthropic_model(model, max_tokens=3000).ainvoke(
        [SystemMessage(system), HumanMessage(user_text)]
    )
    return message_text(response)
