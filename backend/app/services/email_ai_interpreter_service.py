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

Output format (must follow exactly):
Email subject: "{email_subject}"

Sender Email Domain Analysis:
The sender domain {sender_domain} is {legitimate/suspicious/malicious/unknown}.
Domain description: {text}.
Domain reputation summary: {text}.

Sender IP Analysis:
The sender IP address {ip_address} (ISP: {isp}, Usage Type: {usage_type}) was analyzed.
Reputation findings: {text}.
Hosting environment assessment: {shared hosting/dedicated/cloud/CDN/unknown}.

Attachment Analysis:
Attachments present: {yes/no}.
If present: {hash values or "Not present in the provided evidence."}.
VirusTotal detection summary: {text}.
Final attachment assessment: {safe/suspicious/malicious/inconclusive}.

URL Analysis:
Total URLs identified: {count}.
Domains involved: {list or "Not present in the provided evidence."}.
Redirect behavior: {text}.
Reputation findings: {text}.
Final URL assessment: {safe/suspicious/malicious}.

Email Authentication & Security:
SPF result: {pass/fail/none}.
DKIM result: {pass/fail/none}.
DMARC result: {pass/fail/none}.
Spoofing risk assessment: {low/medium/high}.

Machine Learning Signal (if provided):
Phishing probability: {value or "Not present in the provided evidence."}.
Contextual interpretation: {text or "Not present in the provided evidence."}.

Conclusion:
Provide a final classification:
benign
suspicious
malicious
inconclusive

Justify using infrastructure, reputation, authentication, and behavioral signals.

Confidence Level:
low
medium
high
"""


async def interpret_email_results_with_ai(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return {"formatted_resolution": "..."} using one LLM call."""
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

    return {"formatted_resolution": (text or "").strip()}


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

