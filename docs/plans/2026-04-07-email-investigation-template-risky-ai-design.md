# Email Investigation Template-First Risky-URL AI Design

## Goal

Restore the email investigation experience so it feels like the earlier analyst-friendly template output, while keeping the stronger evidence collection now in place. Reduce AI time and cost by sending only suspicious or malicious URLs for AI interpretation instead of every extracted URL. Clarify the email-level AnyRun result so empty dynamic output reads as a valid investigation outcome rather than a broken or missing result.

## Problem Summary

The current email investigation flow is doing three things that work against the intended analyst experience:

1. The page reads as AI-first and tool-dump-heavy instead of leading with a concise investigation template.
2. The AI path receives every URL, even when many are clearly clean or low-value, which slows investigations and spends tokens on weak signals.
3. The AnyRun panel can appear empty or inconclusive even when the uploaded email sample was analyzed successfully, because a checked-but-empty response is not clearly normalized for the UI.

The result is a slower workflow and a report that does not match the concise style analysts preferred, such as:

- identify the sender and whether it appears legitimate
- summarize sender IP reputation
- describe suspicious attachments or links
- explain likely user impact
- recommend action

## Desired Outcome

Email investigations should produce a report-first experience:

- a short narrative summary using analyst prose and evidence-backed bullets
- structured sections for sender/domain, sender IP, URLs, attachments, and AnyRun
- AI reasoning only where it adds value, especially on risky URLs
- clear handling of AnyRun runs that complete but do not surface dynamic indicators

## Recommended Approach

### 1. Keep deterministic analysis broad, but AI analysis selective

Continue extracting and checking all indicators with deterministic services so the report still has full evidence coverage. However, only pass URLs into the AI interpretation payload when they meet a risk threshold.

Recommended risky URL criteria:

- `effective_verdict` is `malicious` or `suspicious`
- VirusTotal verdict is `malicious` or `suspicious`
- AnyRun TI verdict is `malicious` or `suspicious`
- URL behavior shows a credential form
- lexical ML label is `high`
- URL behavior score or equivalent strong redirect/phishing signal exceeds a defined threshold

URLs that do not meet the threshold remain visible in the report, but without expensive AI commentary.

### 2. Treat email-level AnyRun as the primary email sandbox artifact

For email investigations, AnyRun should be modeled and described as analysis of the uploaded `.eml` or `.msg` sample, not as fan-out checks across every extracted indicator. The page copy and empty states should reflect this.

If AnyRun returns:

- `checked=false`: show it as unavailable, failed, or disabled
- `checked=true` with surfaced indicators: show domains, hosts, URLs, files, and summary details
- `checked=true` with no surfaced indicators: show a deliberate analyst-facing message stating that AnyRun analyzed the email sample but did not extract meaningful dynamic indicators from this run

This avoids the current impression that “no result” means the feature is broken.

### 3. Make the template summary the primary report artifact again

The top of the email investigation page should lead with a template-style summary in the analyst voice. AI remains optional enrichment, not the primary renderer of the page.

Target structure:

`After our investigation, we found:`

- sender identity/domain legitimacy
- sender IP reputation
- suspicious URLs, if present
- suspicious attachments, if present
- AnyRun email-level findings, if relevant
- likely user impact

This summary should always be available, even if AI is disabled or fails.

## Frontend Design

The page should remain richer than the original template, but the reading order should be template-first.

### Top-of-page report layout

Place the following at the top:

- overall verdict and confidence banner
- template-style summary block with concise bullets
- recommended analyst action

Below that, preserve structured evidence sections for deeper review:

- sender and domain profile
- sender IP checks
- URL evidence
- attachment evidence
- AnyRun email analysis

### URL section behavior

Show all URLs, but split the presentation by importance:

- risky URLs get expanded cards with stronger evidence and AI reasoning
- clean or low-signal URLs stay compact and deterministic

This keeps evidence complete without overwhelming the analyst.

### AnyRun section behavior

Retitle and describe this section as email-sample analysis rather than per-URL checking. Use empty-state copy that explicitly distinguishes:

- not run
- failed/unavailable
- analyzed successfully but surfaced no dynamic indicators

## Backend Design

### AI payload filtering

Update the email interpretation payload builder so it includes:

- all non-URL high-level evidence needed for overall interpretation
- only risky URLs for URL-specific AI analysis

The response merge logic should continue to preserve deterministic URL coverage for all URLs, even when AI assessed only a subset.

### Template rendering

Preserve and strengthen the existing template rendering path so it becomes the default main report body. The template should synthesize:

- sender domain context
- sender IP context
- suspicious URL findings
- suspicious attachment findings
- AnyRun findings
- user-impact language

### AnyRun normalization

Add a normalized email AnyRun status model so the frontend can reliably distinguish:

- disabled
- unavailable/error
- completed with findings
- completed without meaningful findings

## Error Handling

- If AI fails, the template summary still renders in full.
- If AnyRun fails, the report should state that the email sample could not be analyzed dynamically and continue with deterministic findings.
- If no risky URLs exist, the AI URL-assessment section should be omitted instead of filled with weak content.
- If sender/domain/IP evidence is missing, the template should say so plainly rather than implying certainty.

## Testing

Add or update tests for:

- risky URL filtering before AI interpretation
- deterministic coverage preserved for all URLs after AI merge
- email-level AnyRun result with surfaced indicators
- email-level AnyRun checked-but-empty result
- AI-disabled and AI-failure fallback template rendering
- frontend rendering for compact clean URLs versus expanded risky URLs

## Tradeoffs

### Recommended: template-first with selective AI

Pros:

- fastest to read
- lower token and latency cost
- aligns with the preferred analyst experience
- keeps AI where it adds the most value

Cons:

- less free-form than a fully AI-authored report

### Alternative: AI-first report with template fallback

Pros:

- more flexible language

Cons:

- slower
- less consistent
- harder to keep aligned with the old template style

## Recommendation

Use a template-first investigation report, send only risky URLs to AI, and reframe AnyRun around a single email-sample analysis with explicit empty-state normalization. This keeps the report concise and analyst-friendly while preserving the richer evidence model and reducing unnecessary AI latency.
