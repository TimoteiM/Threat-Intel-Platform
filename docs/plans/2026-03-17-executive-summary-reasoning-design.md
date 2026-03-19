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

For those types, `primary_reasoning` should stay in one field, but follow a more analyst-oriented structure:
1. a one-line SOC-style conclusion
2. if defensible from evidence, what the domain/URL/email appears to be or what the associated company/service does
3. a short analysis explaining why the observable appears benign, suspicious, or malicious based on correlated evidence
4. an explicit verdict with confidence

`ip`, `hash`, and `file` investigations remain concise.

## Behavior Design

### Domain / URL / Email
The reasoning should read like a senior SOC analyst conclusion rather than a parser dump. It should answer:
- `What is this?`
- `What is it associated with?`
- `Why does the evidence support the risk conclusion?`

Expected shape inside the single `primary_reasoning` field:
- `One-line Summary:` concise SOC-style conclusion in one sentence
- `Associated With:` if known, what the company/service/domain appears to be about
- `Analysis:` explain the risk interpretation by correlating signals instead of listing raw data
- `Verdict:` explicit benign/suspicious/malicious conclusion with confidence

Examples:
- `Summary: Domain shows strong indicators of phishing infrastructure rather than a legitimate standalone service. Associated With: The observed branding and workflow suggest it is posing as a retail login or storefront property rather than operating as a real business domain. Analysis: The evidence correlates impersonation behavior, suspicious redirect/content patterns, and corroborating external detections, which is more consistent with attacker-controlled infrastructure than with a benign site. Verdict: MALICIOUS (HIGH confidence).`
- `Summary: Domain appears to support a legitimate communications or corporate web service. Associated With: The observable aligns with a real business or cloud delivery service used for normal messaging or web operations. Analysis: The collected evidence does not show strong malicious indicators, and the observed reputation, hosting, and behavior are more consistent with benign infrastructure. Verdict: BENIGN (MEDIUM confidence).`

### IP / Hash / File
No change in style. These should remain concise and technical.

## Technical Design

### Prompting
Update the analyst prompt in `backend/app/analyst/system_prompt.py` so that:
- `primary_reasoning` for `domain`/`url`/`email` is not constrained to the current short 220-char format
- the model is explicitly told to produce a single richer reasoning block containing:
  - a one-line summary
  - associated company/service/domain context when defensible from evidence
  - a short analysis focused on interpretation rather than raw data repetition
  - a verdict with confidence
- the model must avoid unsupported speculation and raw IOC copying unless strictly necessary

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
