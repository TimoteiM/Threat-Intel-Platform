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
from typing import Any

import anthropic
from openai import AsyncOpenAI

from app.config import get_settings

logger = logging.getLogger(__name__)

PRIMARY_MODEL = "claude-haiku-4-5-20251001"
FALLBACK_MODEL = "gpt-5-mini"


SYSTEM_PROMPT = """You are a Senior SOC Analyst AI performing structured email threat investigations.

Rules:
- Use only evidence provided. Never invent data.
- If data is missing, output exactly: "Not present in the provided evidence."
- Do NOT speculate. Do NOT assume legitimacy without evidence.
- Classify malicious only when attacker-controlled infrastructure is required.
- Be concise and factual.

Email-specific classification rules (apply strictly):
- If SPF=fail AND DMARC policy is none or absent: sender_domain classification is at minimum "suspicious".
- If domain_age_days < 30: HIGH-severity signal; include prominently in findings.
- If domain_age_days < 7: EXTREME signal; overall_verdict must be at minimum "suspicious".
- If any URL has credential_form_present=true: overall_verdict is at minimum "suspicious".
- If any attachment vt.malicious_count > 0: overall_verdict = "malicious", confidence = "high".
- If AnyRun verdict is "malicious" for any item AND threat_score >= 95: overall_verdict = "malicious".
- If AnyRun verdict is "malicious" for any item AND threat_score < 95: treat as suspicious signal only — do NOT set overall_verdict = "malicious" on this alone.
- If spoofability_score is "high": mention the domain can be trivially spoofed.

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

    text = ""
    if settings.anthropic_api_key:
        try:
            text = await _call_claude(
                api_key=settings.anthropic_api_key,
                model=PRIMARY_MODEL,
                system=SYSTEM_PROMPT,
                user_text=user_text,
            )
            if not (text or "").strip():
                logger.warning("Claude Haiku email interpretation returned empty output. Falling back to GPT-5 Mini.")
                text = ""
        except Exception as anthropic_err:
            logger.warning(
                "Claude Haiku email interpretation failed (%s: %s). Falling back to GPT-5 Mini.",
                type(anthropic_err).__name__,
                anthropic_err,
            )
            text = ""

    if not (text or "").strip():
        if not settings.openai_api_key:
            raise ValueError(
                "Both primary (Haiku) and fallback (GPT-5 Mini) are unavailable: "
                "ANTHROPIC_API_KEY and OPENAI_API_KEY are both unset."
            )
        text = await _call_openai(
            api_key=settings.openai_api_key,
            model=FALLBACK_MODEL,
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
    client = AsyncOpenAI(api_key=api_key)
    response = await client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        ],
        max_output_tokens=3000,
    )
    text = getattr(response, "output_text", None) or ""
    if text:
        return text
    chunks: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            part = getattr(content, "text", None)
            if part:
                chunks.append(part)
    return "\n".join(chunks).strip()


async def _call_claude(api_key: str, model: str, system: str, user_text: str) -> str:
    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model,
        max_tokens=3000,
        system=system,
        messages=[{"role": "user", "content": user_text}],
    )
    return response.content[0].text if response and response.content else ""
