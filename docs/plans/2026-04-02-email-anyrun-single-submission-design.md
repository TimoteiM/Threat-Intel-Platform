# Email AnyRun Single Submission Design

## Goal

Make email investigations that enable AnyRun analyze the uploaded `.eml` or `.msg` sample once, instead of triggering AnyRun lookups or sandbox submissions for each extracted URL or attachment hash.

## Current Problem

The existing email investigation flow extracts URLs and attachments, then passes `run_anyrun=True` into indicator-level checks. That causes repeated AnyRun and Hybrid lookups inside the URL and attachment loops, which makes investigations slow and changes the meaning of "run AnyRun" from "analyze this email" to "fan out dynamic analysis across extracted indicators."

## Options Considered

### 1. Recommended: redefine `run_anyrun` for email investigations only

When a user enables AnyRun on an email investigation, the backend submits the original uploaded email payload to AnyRun one time and stores that result as the dynamic-analysis block for the investigation. Deterministic sender, URL, and attachment checks still run, but they no longer call AnyRun from the email workflow.

Pros:
- Matches user expectation
- Eliminates repeated AnyRun latency
- Keeps existing URL/hash investigation flows unchanged

Cons:
- Changes semantics of `run_anyrun` specifically in the email investigation path

### 2. Add an explicit AnyRun mode switch

Support `email` vs `indicator` modes for email investigations.

Pros:
- Most explicit

Cons:
- More UI and API complexity
- Keeps the slow path alive

### 3. Submit email first, then fall back to indicator fan-out

Pros:
- Most exhaustive

Cons:
- Still inefficient
- Harder to reason about results

## Approved Design

Use option 1.

## Behavior

- `process_email_investigation(...)` will submit the uploaded `.eml` or `.msg` payload to AnyRun once when `run_anyrun=True`.
- The AnyRun result will be stored in a dedicated email-level block under `indicator_checks`.
- Deterministic URL checks will still do VirusTotal, final URL resolution, lexical ML, URL behavior, and optional URLScan/screenshot work.
- Deterministic attachment checks will still do hash extraction, VirusTotal hash checks, and static attachment analysis.
- Email investigations will no longer perform AnyRun lookups or sandbox submissions per URL or per attachment hash.
- Standalone URL/hash investigation behavior will remain unchanged.

## Data Shape

Add `indicator_checks["email_anyrun"]`:

```python
{
    "checked": bool,
    "indicator_type": "file",
    "verdict": str,
    "analysis_id": str | None,
    "analysis_link": str | None,
    "threat_score": float | None,
    "raw_summary": dict[str, Any],
    "dynamic_io_summary": dict[str, Any],
    "file_name": str,
}
```

If AnyRun is disabled, omit the block or mark it as not checked.

## Risk Aggregation

Email-level AnyRun output becomes the primary dynamic-analysis input in the final email risk aggregation. Existing hybrid aggregation built from per-URL/per-hash AnyRun results will be empty in this workflow, which is expected.

## Testing

- Add a failing unit test proving `process_email_investigation(...)` submits the raw email once and passes filename/bytes through.
- Add a failing unit test proving email indicator checks do not call `lookup_hybrid_analysis(...)` when `run_anyrun=True`.
- Verify existing AnyRun standalone URL/hash tests still pass.
