# Email AnyRun Concurrency Design

## Goal

Reduce email investigation wall-clock time by starting the email-level AnyRun submission at the same time as the deterministic URL and attachment checks.

## Current Problem

The current email investigation flow runs `run_email_indicator_checks(...)` first and only then submits the uploaded `.eml` or `.msg` to AnyRun. Even though per-URL AnyRun fan-out is gone, the single AnyRun submission is still blocked behind the full VT and URL-behavior pipeline.

## Options Considered

### 1. Recommended: run deterministic checks and email-level AnyRun concurrently

Launch both blocking operations through `asyncio.to_thread(...)` and await them with `asyncio.gather(...)`.

Pros:
- Lowest-risk change
- Preserves existing result shape
- Reduces total time to the slower of the two branches instead of the sum

Cons:
- Slightly more coordination logic in the email processing helper

### 2. Submit AnyRun first, then run deterministic checks

Pros:
- Simpler than true concurrency

Cons:
- Still leaves the total time mostly additive

### 3. Move the AnyRun submission into a separate Celery task

Pros:
- Most flexible long-term

Cons:
- More orchestration complexity than needed for this improvement

## Approved Design

Use option 1.

## Behavior

- After IOC extraction, `process_email_investigation(...)` starts:
  - `run_email_indicator_checks(...)`
  - `_lookup_email_anyrun(...)`
- Both run concurrently in worker threads.
- Result merging stays the same after both complete.
- If AnyRun is disabled, the AnyRun branch still returns `None` and does not affect output.

## Testing

- Add a unit test proving both branches start before either one finishes.
- Keep the existing test that verifies a single email-level AnyRun submission.
