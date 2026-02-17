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

    # Build client domain context if similarity analysis was performed
    similarity_context = ""
    if evidence.domain_similarity:
        sim = evidence.domain_similarity
        similarity_context = f"""
<client_domain_comparison>
This investigation includes a CLIENT DOMAIN COMPARISON. The investigated domain is being
compared against the client's legitimate domain '{sim.client_domain}' to detect potential
impersonation, typosquatting, or visual lookalike attacks.

You MUST include domain similarity analysis in your assessment. The domain_similarity
section in the evidence contains computed algorithmic metrics — treat these as factual
measurements, not speculation.
</client_domain_comparison>
"""

    # Build visual comparison context if screenshot analysis was performed
    visual_context = ""
    if evidence.visual_comparison:
        vc = evidence.visual_comparison
        overall = vc.overall_visual_similarity
        if overall is not None:
            visual_context = f"""
<visual_comparison_context>
Automated SCREENSHOT COMPARISON was performed between the investigated domain and
client domain '{vc.client_domain}'.

Visual similarity: {overall:.0%} | Clone: {vc.is_visual_clone} | Partial clone: {vc.is_partial_clone}
{"Reference image was used (uploaded by analyst)." if vc.reference_image_used else "Live screenshots were captured."}

You MUST include visual comparison findings in your Technical Evidence Analysis section.
The visual_comparison metrics are computed from actual page screenshots — treat them as
objective measurements.
</visual_comparison_context>
"""
        elif vc.investigated_capture_error or vc.client_capture_error:
            visual_context = f"""
<visual_comparison_context>
Screenshot comparison was attempted but partially failed:
{f"- Investigated domain capture error: {vc.investigated_capture_error}" if vc.investigated_capture_error else ""}
{f"- Client domain capture error: {vc.client_capture_error}" if vc.client_capture_error else ""}
Note this as a data gap in your analysis.
</visual_comparison_context>
"""

    user_message = f"""Analyze the following domain investigation evidence and produce your assessment.

<investigation>
<domain>{evidence.domain}</domain>
<investigation_id>{evidence.investigation_id}</investigation_id>
<iteration>{iteration} of {max_iterations}</iteration>
{similarity_context}{visual_context}
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
