"""
Single-shot AI interpretation for email investigation results.

Uses one model call after all deterministic indicator checks are complete.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic
from openai import AsyncOpenAI

from app.config import get_settings

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Senior SOC Analyst AI performing structured email threat investigations.

Rules:
- Use only evidence provided by the user.
- Never invent data.
- If data is missing, output exactly: "Not present in the provided evidence."
- Do NOT speculate.
- Do NOT assume legitimacy without evidence.
- Do NOT classify malicious unless attacker-controlled infrastructure is required.
- Keep output concise and factual.

Output format:
Return ONLY a valid JSON object with this shape:
{
  "formatted_resolution": "full human-readable investigation summary",
  "sender_company": {
    "name": "company/entity tied to sender domain or Not present in the provided evidence.",
    "description": "what that domain/company is about in one short sentence or Not present in the provided evidence."
  },
  "url_assessments": [
    {
      "url": "original extracted URL",
      "where_it_points": "resolved destination/final URL or Not present in the provided evidence.",
      "legitimacy": "legitimate|suspicious|malicious|unknown",
      "reasoning": "1-2 short evidence-based sentences"
    }
  ],
  "sender_domain_analysis": {
    "classification": "benign|suspicious|malicious|unknown",
    "primary_reasoning": "2-5 evidence-based sentences focused on sender domain",
    "findings": [
      {
        "title": "short finding title",
        "severity": "low|medium|high",
        "description": "evidence-based finding text"
      }
    ]
  }
}

Requirements for sender_domain_analysis:
- Must be specifically about sender domain evidence.
- findings must include 2-6 items when enough evidence exists.
- When WHOIS evidence is present, include at least one finding explicitly covering
  domain registration context (registrar, age/created date, and relevant status).
- If sender domain evidence is missing, use:
  "primary_reasoning": "Not present in the provided evidence."
  "findings": []

Requirements for sender_company:
- Prefer evidence-backed domain/company mapping from domain, registrant org, or well-known infrastructure ownership.
- Keep description short and factual.
- If not inferable from evidence, set both fields to "Not present in the provided evidence."

Requirements for url_assessments:
- Include one entry for each URL in evidence when URL evidence exists.
- Use only provided evidence (VT verdict, final URL, etc.).
- If destination is unavailable, use "Not present in the provided evidence."
"""


async def interpret_email_results_with_ai(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return structured email interpretation with sender-domain analyst details."""
    settings = get_settings()
    user_text = (
        "Analyze the following structured email investigation evidence and provide the required formatted output.\n\n"
        f"```json\n{json.dumps(payload, ensure_ascii=True, indent=2)}\n```"
    )

    try:
        text = await _call_openai(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            system=SYSTEM_PROMPT,
            user_text=user_text,
        )
    except Exception as openai_err:
        if settings.anthropic_api_key and settings.anthropic_model:
            logger.warning(
                "OpenAI email interpretation failed (%s: %s). Falling back to Claude.",
                type(openai_err).__name__,
                openai_err,
            )
            text = await _call_claude(
                api_key=settings.anthropic_api_key,
                model=settings.anthropic_model,
                system=SYSTEM_PROMPT,
                user_text=user_text,
            )
        else:
            raise

    return _parse_interpreter_output((text or "").strip())


def _parse_interpreter_output(text: str) -> dict[str, Any]:
    fallback = {
        "formatted_resolution": text,
        "sender_company": {
            "name": "Not present in the provided evidence.",
            "description": "Not present in the provided evidence.",
        },
        "url_assessments": [],
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

    formatted_resolution = str(parsed.get("formatted_resolution") or text).strip()
    sender_company = parsed.get("sender_company")
    if not isinstance(sender_company, dict):
        sender_company = {}
    raw_url_assessments = parsed.get("url_assessments")
    normalized_url_assessments: list[dict[str, Any]] = []
    if isinstance(raw_url_assessments, list):
        for item in raw_url_assessments:
            if not isinstance(item, dict):
                continue
            normalized_url_assessments.append(
                {
                    "url": str(item.get("url") or "Not present in the provided evidence."),
                    "where_it_points": str(
                        item.get("where_it_points") or "Not present in the provided evidence."
                    ),
                    "legitimacy": str(item.get("legitimacy") or "unknown").lower(),
                    "reasoning": str(
                        item.get("reasoning") or "Not present in the provided evidence."
                    ),
                }
            )
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

    return {
        "formatted_resolution": formatted_resolution,
        "sender_company": {
            "name": str(sender_company.get("name") or "Not present in the provided evidence."),
            "description": str(
                sender_company.get("description") or "Not present in the provided evidence."
            ),
        },
        "url_assessments": normalized_url_assessments,
        "sender_domain_analysis": {
            "classification": str(sda.get("classification") or "unknown").lower(),
            "primary_reasoning": str(
                sda.get("primary_reasoning") or "Not present in the provided evidence."
            ),
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
        max_output_tokens=2500,
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
        max_tokens=2500,
        system=system,
        messages=[{"role": "user", "content": user_text}],
    )
    return response.content[0].text if response and response.content else ""
