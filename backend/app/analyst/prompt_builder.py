"""
Prompt Builder — constructs the Claude API message array from evidence.

Handles first-pass and follow-up iterations.
"""

from __future__ import annotations

from typing import Optional

from app.analyst.system_prompt import ANALYST_SYSTEM_PROMPT
from app.models.schemas import CollectedEvidence


def build_messages(
    evidence: CollectedEvidence,
    iteration: int = 0,
    max_iterations: int = 3,
    previous_response: Optional[str] = None,
) -> tuple[str, list[dict[str, str]]]:
    """
    Build the system prompt + message array for the Claude API call.

    Args:
        evidence: The collected evidence object
        iteration: Current iteration (0 = first pass)
        max_iterations: Cap on follow-up rounds
        previous_response: Claude's previous output (for follow-ups)

    Returns:
        (system_prompt, messages_list)
    """
    system = ANALYST_SYSTEM_PROMPT.replace("{max_iterations}", str(max_iterations))

    evidence_json = evidence.model_dump_json(indent=2, exclude_none=True)

    user_message = f"""Analyze the following domain investigation evidence and produce your assessment.

<investigation>
<domain>{evidence.domain}</domain>
<investigation_id>{evidence.investigation_id}</investigation_id>
<iteration>{iteration} of {max_iterations}</iteration>

<evidence>
{evidence_json}
</evidence>
</investigation>

Produce your structured JSON assessment followed by the human-readable report.
Follow your methodology strictly. Do not skip any step."""

    messages = []

    if iteration > 0 and previous_response:
        # Follow-up: include the conversation history
        messages.append({"role": "user", "content": user_message})
        messages.append({"role": "assistant", "content": previous_response})
        messages.append({
            "role": "user",
            "content": (
                f"This is iteration {iteration} of {max_iterations}. "
                "The evidence object above has been updated with any additionally "
                "collected data. Please re-evaluate and produce your final assessment."
            ),
        })
    else:
        messages.append({"role": "user", "content": user_message})

    return system, messages
