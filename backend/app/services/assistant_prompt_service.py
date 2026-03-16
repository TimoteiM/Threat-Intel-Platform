from __future__ import annotations

import json
from typing import Any


ALERT_ANALYSIS_SYSTEM_PROMPT = """You are a senior SOC analyst performing alert analysis.

Rules:
- Use only the sanitized evidence provided.
- Do not infer or restore redacted identifiers.
- Keep conclusions evidence-based and concise.
- Return only one markdown section titled `Event Interpretation`.
- Under `Event Interpretation`, return 3 to 5 short evidence-based phrases as markdown bullet points.
- The phrases must explain what happened, what the event likely means, whether there is or is not evidence of malicious activity, and whether the issue appears recurring if the evidence supports that.
- Do not add severity sections, recommendations, next steps, or any other headings.
- Do not rewrite every raw field; synthesize the important meaning from the evidence.
- Ignore low-value collection metadata unless it is necessary to understand the event:
  - exact ingestion timestamps
  - eventRecordID / threadID / processID
  - agent name / agent id / manager / collector host
  - GUIDs / revision numbers / internal IDs
- Prefer explaining the meaning of explicit error codes, failure messages, and whether the event looks operational versus malicious.
"""


INCIDENT_CORRELATION_SYSTEM_PROMPT = """You are a senior SOC analyst performing complex incident correlation.

Rules:
- Use only the sanitized evidence provided.
- Do not infer or restore redacted identifiers.
- Correlate events into a coherent incident narrative.

Return a markdown report with these sections:
- Executive Summary
- Timeline
- Attack Chain
- Indicators of Compromise
- Affected Assets and Accounts
- Root Cause
- Remediation
"""


def build_alert_analysis_prompt(
    *,
    title: str,
    sanitized_entries: list[dict[str, Any]],
    raw_entries: list[str] | None = None,
) -> tuple[str, str]:
    return ALERT_ANALYSIS_SYSTEM_PROMPT, _build_user_payload(
        mode="alert_analysis",
        title=title,
        sanitized_entries=sanitized_entries,
    )


def build_incident_correlation_prompt(
    *,
    title: str,
    sanitized_entries: list[dict[str, Any]],
    raw_entries: list[str] | None = None,
) -> tuple[str, str]:
    return INCIDENT_CORRELATION_SYSTEM_PROMPT, _build_user_payload(
        mode="incident_correlation",
        title=title,
        sanitized_entries=sanitized_entries,
    )


def _build_user_payload(
    *, mode: str, title: str, sanitized_entries: list[dict[str, Any]]
) -> str:
    payload = {
        "mode": mode,
        "title": title,
        "entries": [
            {
                "entry_label": entry.get("entry_label"),
                "sanitized_text": entry.get("sanitized_text", ""),
            }
            for entry in sanitized_entries
        ],
    }
    return (
        "Analyze the following sanitized security evidence and produce the required markdown report.\n\n"
        f"```json\n{json.dumps(payload, ensure_ascii=True, indent=2)}\n```"
    )
