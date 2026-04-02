# Analyst Prompt Too Long Retry Design

## Goal
Preserve detailed analyst reasoning for `domain` and `url` investigations even when the primary LLM prompt exceeds the model input limit.

## Current Problem
The analyst path compacts evidence only lightly before embedding the serialized evidence object into the model prompt. In oversized investigations, the OpenAI Responses API rejects the request with `invalid_request_error` and a message like `prompt is too long: 205366 tokens > 200000 maximum`.

Today that error is treated like any other analyst exception in `backend/app/tasks/analysis_task.py`, which means the investigation falls back to a low-value generic analyst error instead of attempting a smaller but still evidence-rich prompt.

## Approved Direction
Treat prompt-overflow as a recoverable input-sizing issue, not as a reasoning failure.

The analyst flow should:
- keep the current rich prompt as the first attempt
- retry automatically when the error is specifically a prompt-length invalid request
- apply progressively stronger evidence compaction tiers on each retry
- preserve high-signal investigative facts so `primary_reasoning` can remain detailed
- fall back to the existing automated report only after compact retries are exhausted

## Approach Options Considered

### Option 1: Shorten `primary_reasoning`
Reduce the requested output detail so the model uses fewer tokens overall.

Trade-off:
- does not address the actual failure, which happens before generation
- directly conflicts with the requirement to keep primary reasoning detailed

### Option 2: Tiered evidence compaction with retry
Retry the analyst call with smaller prompt payloads that preserve high-signal evidence and remove low-signal raw detail.

Trade-off:
- slightly more implementation complexity
- best matches the real failure mode and preserves analyst value

### Option 3: Replace raw evidence with a synthesized digest only
Always generate an evidence digest before calling the analyst.

Trade-off:
- simplest long-term prompt footprint
- larger behavior change and higher risk of losing nuance for normal-sized investigations

## Chosen Design
Use Option 2.

The first attempt keeps the current behavior. If the analyst call fails with a prompt-length invalid request, the system retries with stronger compact tiers. If the final compact tier still exceeds the limit, the pipeline falls back to the existing automated report path with an explicit note that compact retries were exhausted.

## Technical Design

### Compaction tiers
Add a tier parameter to the analyst-input evidence builder in `backend/app/tasks/analysis_task.py`.

Tier behavior:
- `standard`: current trimming behavior with only light compaction
- `compact`: stronger list trimming, shorter nested text truncation, and removal of bulky low-signal fields
- `digest`: keep only high-signal fields and short summaries for bulky sections

High-signal evidence to preserve:
- observable identity and type
- WHOIS/domain age
- DNS resolution and core records
- HTTP final URL, title, reachability, redirect summary
- TLS issuer, SAN summary, validity indicators
- VT detection counts and key verdict summaries
- threat-feed hit counts and verified matches
- domain similarity / visual comparison scores
- redirect-analysis summary values
- JS credential-harvesting indicators and key POST endpoints summary
- signals and data gaps in shortened form
- external context in existing bounded form

Low-signal evidence to shrink or drop in aggressive tiers:
- long raw request lists
- large related URL/subdomain lists
- verbose certificate timelines
- large artifact hash lists
- repetitive or bulky text blobs
- raw screenshot or browser sandbox details that are not needed for classification

### Retry behavior
Add a helper around the analyst call path in `backend/app/tasks/analysis_task.py` that:
- tries `standard`
- catches prompt-too-long errors only
- retries with `compact`
- retries with `digest`
- re-raises other analyst errors unchanged

The helper should also return metadata about which tier succeeded so the report can be annotated if compact mode was required.

### Error detection
Implement a narrow detector for prompt overflow by checking for:
- `invalid_request_error`
- `prompt is too long`

This should avoid masking unrelated model or provider failures.

### Report annotation
If a compact tier succeeds, prepend a short note to `primary_reasoning` and `executive_summary` indicating the analyst used compact evidence due to prompt size limits. Keep the note brief so it does not degrade the final report.

### Tests
Add tests covering:
- standard compaction still keeps existing behavior
- compact tiers reduce evidence more aggressively
- prompt-too-long errors trigger retries across tiers
- non-size-related exceptions do not retry
- successful retry annotates the resulting report

## Constraints
- Do not reduce requested reasoning richness in the analyst prompt.
- Do not convert all investigations to digest-only mode.
- Do not swallow unrelated analyst failures.
- Preserve the existing automated-report fallback for the terminal failure case.

## Verification
We will consider this complete when:
- prompt-too-long failures no longer surface as immediate analyst errors when compact retries can succeed
- detailed `primary_reasoning` is still produced after compact retries
- unrelated analyst exceptions still behave normally
- targeted unit tests pass
