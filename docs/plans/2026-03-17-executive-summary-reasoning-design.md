# Executive Summary Reasoning Enrichment Design

## Goal
Improve the `Executive Summary` tab for `domain`, `url`, and `email` investigations so `Primary Reasoning` explains both what the observable appears to be and whether it is malicious, suspicious, or benign based on the collected evidence.

## Current Problem
The current analyst prompt constrains `primary_reasoning` to a very short SOC-style summary (1-2 sentences, ~220 chars), which suppresses useful context. As a result, the Executive Summary often lacks:
- business/service context for the domain or URL
- plain-language explanation of what the entity appears to do
- a direct security conclusion tied to evidence

## Approved Direction
Keep the existing `primary_reasoning` field, but make it richer for only these observable types:
- `domain`
- `url`
- `email`

For those types, `primary_reasoning` should contain two compact parts:
1. what the observable appears to be / what the associated company, brand, or service appears to do
2. whether it appears malicious, suspicious, or benign based on the collected evidence

`ip`, `hash`, and `file` investigations remain concise.

## Behavior Design

### Domain / URL / Email
The reasoning should answer both:
- `What is this?`
- `What does the evidence say about its risk?`

Expected shape:
- first sentence: service/entity context
- second sentence: explicit security assessment with evidence grounding

Examples:
- `This domain appears to belong to a cloud communications or marketing delivery service used for email routing and campaign infrastructure. Based on the collected evidence, it appears benign, with no strong malicious indicators across reputation, hosting, and behavioral analysis.`
- `This URL appears to imitate a retail brand and likely serves as a storefront or phishing destination. Based on the collected evidence, it is likely malicious due to recent domain age, suspicious content, and corroborating detections from external intelligence sources.`

### IP / Hash / File
No change in style. These should remain concise and technical.

## Technical Design

### Prompting
Update the analyst prompt in `backend/app/analyst/system_prompt.py` so that:
- `primary_reasoning` for `domain`/`url`/`email` is not constrained to the current short 220-char format
- the model is explicitly told to include:
  - inferred purpose / company or service context when defensible from evidence
  - evidence-based security conclusion
- the model must avoid unsupported speculation

### Normalization / Fallbacks
Review `backend/app/tasks/analysis_task.py` logic that simplifies or replaces `primary_reasoning`.
If simplification rules are too aggressive, they should preserve the richer structure for `domain`/`url`/`email` while still protecting terse fallback behavior for other types.

### Frontend
Keep the same `Primary Reasoning` section in `frontend/src/components/report/ExecutiveSummaryTab.tsx`, but allow it to display richer reasoning cleanly. The existing block may be enough unless line breaks or paragraph handling need a light polish.

## Constraints
- Do not add a new schema field unless truly necessary.
- Do not change reasoning style for `ip`, `hash`, or `file`.
- The context sentence must be grounded in evidence or high-confidence inference, not generic filler.
- The security assessment sentence must explicitly state whether the observable appears benign, suspicious, or malicious based on collected evidence.

## Verification
We will consider this complete when:
- new `domain`, `url`, and `email` reports produce richer `primary_reasoning`
- `ip`, `hash`, and `file` reports remain concise
- the Executive Summary tab renders the richer reasoning cleanly
- prompt/fallback changes do not break report parsing
