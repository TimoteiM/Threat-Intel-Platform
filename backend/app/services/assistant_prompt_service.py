from __future__ import annotations

import json
from typing import Any


ALERT_ANALYSIS_SYSTEM_PROMPT = """You are a senior SOC analyst performing alert analysis.

The evidence you receive has been pre-processed: sensitive identifiers (IP addresses, hostnames, \
usernames, email addresses) have been replaced with placeholder tokens such as [IP_1], [HOST_2], \
[ACCOUNT_1]. These tokens are intentional — do not describe or paraphrase them. When your analysis \
references a source, destination, account, or asset, use the exact token (e.g. "[IP_1]", not \
"the internal host"). The tokens will be resolved for the analyst after your response.

Rules:
- Use only the sanitized evidence provided.
- Reference identifiers using their exact token names ([IP_1], [HOST_1], [ACCOUNT_1], etc.).
- Never add the original value after a token — no parenthetical, no colon, no inline expansion \
(e.g. write "[HOST_2]", never "[HOST_2] (onvmbp01.onenet.be)" or "[HOST_2]: onvmbp01.onenet.be"). \
If a raw value appears in the evidence alongside a token, ignore the raw value and use only the token.
- Keep conclusions evidence-based and concise.
- Return only one markdown section titled `Event Interpretation`.
- Under `Event Interpretation`, return 3 to 5 short evidence-based phrases as markdown bullet points.
- The phrases must explain what happened, what the event likely means, whether there is or is not \
evidence of malicious activity, and whether the issue appears recurring if the evidence supports that.
- Do not add severity sections, recommendations, next steps, or any other headings.
- Do not rewrite every raw field; synthesize the important meaning from the evidence.
- Ignore low-value collection metadata unless it is necessary to understand the event:
  - exact ingestion timestamps
  - eventRecordID / threadID / processID
  - agent name / agent id / manager / collector host
  - GUIDs / revision numbers / internal IDs
- Prefer explaining the meaning of explicit error codes, failure messages, and whether the event \
looks operational versus malicious.
- Base64 decoding: if the evidence contains a base64-encoded string (e.g. in PowerShell -EncodedCommand, \
cmd /c, or any script field), decode it and include the decoded plaintext in your analysis. \
Clearly label it as "Decoded payload:" followed by the actual decoded content in a code block. \
Do not just describe the encoding pattern — always show what it decodes to.
"""


INCIDENT_CORRELATION_SYSTEM_PROMPT = """You are a senior SOC analyst performing complex incident correlation.

The evidence you receive has been pre-processed: sensitive identifiers (IP addresses, hostnames, \
usernames, email addresses) have been replaced with placeholder tokens such as [IP_1], [HOST_2], \
[ACCOUNT_1]. These tokens are intentional — do not describe or paraphrase them. When your analysis \
references a source, destination, account, or asset, use the exact token. The tokens will be \
resolved for the analyst after your response.

Rules:
- Use only the sanitized evidence provided.
- Reference identifiers using their exact token names ([IP_1], [HOST_1], [ACCOUNT_1], etc.).
- Never add the original value after a token — no parenthetical, no colon, no inline expansion \
(e.g. write "[HOST_2]", never "[HOST_2] (onvmbp01.onenet.be)"). If a raw value appears in the \
evidence alongside a token, ignore the raw value and use only the token.
- Correlate events into a coherent incident narrative.
- Base64 decoding: if the evidence contains any base64-encoded string (e.g. PowerShell -EncodedCommand, \
script fields, or obfuscated command arguments), decode it and include the decoded plaintext. \
Label it as "Decoded payload:" followed by the actual content in a code block. Never just describe \
the encoding — always show what it decodes to.

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
    token_map: dict[str, str] | None = None,
) -> tuple[str, str]:
    return ALERT_ANALYSIS_SYSTEM_PROMPT, _build_user_payload(
        mode="alert_analysis",
        title=title,
        entries=sanitized_entries,
        token_map=token_map,
    )


def build_incident_correlation_prompt(
    *,
    title: str,
    sanitized_entries: list[dict[str, Any]],
    raw_entries: list[str] | None = None,
    token_map: dict[str, str] | None = None,
) -> tuple[str, str]:
    return INCIDENT_CORRELATION_SYSTEM_PROMPT, _build_user_payload(
        mode="incident_correlation",
        title=title,
        entries=sanitized_entries,
        token_map=token_map,
    )


def _build_user_payload(
    *,
    mode: str,
    title: str,
    entries: list[dict[str, Any]],
    token_map: dict[str, str] | None = None,
) -> str:
    payload = {
        "mode": mode,
        "title": title,
        "entries": [
            {
                "entry_label": entry.get("entry_label"),
                "sanitized_text": entry.get("sanitized_text", ""),
            }
            for entry in entries
        ],
    }
    parts = [
        "Analyze the following sanitized security evidence and produce the required markdown report.\n",
        f"```json\n{json.dumps(payload, ensure_ascii=True, indent=2)}\n```",
        (
            "\nFortiGate field reference (do not conflate these):\n"
            "- srcip/dstip — original source/destination IP (two separate addresses, never combined)\n"
            "- tranip — translated destination IP (DNAT target, separate from transip)\n"
            "- transip — translated source IP (SNAT origin, separate from tranip)\n"
            "- tranport/transport — translated destination/source port numbers (integers, not IPs)"
        ),
    ]
    if token_map:
        legend_lines = [
            f"- {token}"
            for token in sorted(token_map.keys())
        ]
        if legend_lines:
            parts.append(
                "\nTokens present in the evidence above (use these exact strings in your output):\n"
                + "\n".join(legend_lines)
            )
    return "\n".join(parts)
