# Domain Investigation Full AnyRun Completion Design

**Problem**

Domain investigations can conclude before Any.Run finishes assembling its full result set. The current pipeline allows `hybrid_analysis` to be marked `deferred`, computes the final report and risk score without the late Any.Run lookup/live result, and only then merges the finished Any.Run evidence into the investigation afterward.

This creates two analyst-visible problems:

- the initial report and risk score can be materially wrong because they exclude late Any.Run verdicts
- the collector timing panel shows a "Total" wall-clock number that looks like a sum of collector durations, even though the row durations are parallel per-collector timings

**Root Cause**

In `backend/app/tasks/investigation_task.py`, Any.Run has a 90-second soft deadline in the main collector phase. When it exceeds that deadline, the investigation proceeds to `run_analysis(...)` immediately and Any.Run is updated later in `_anyrun_background_update(...)`.

Risk scoring is calculated only once during report generation in `backend/app/tasks/analysis_task.py`, so any late Any.Run result does not affect the concluded report. On the frontend, the timing panel's "Total" value is sourced from total elapsed wall-clock time since the investigation started, not from the sum of collector row durations.

**Goal**

For domain investigations, the investigation should conclude and compute risk only after the full Any.Run collector result is available. Any.Run's internal lookup and sandbox branches should still run in parallel, but the investigation should not be considered complete until that combined collector finishes.

**Recommended Approach**

1. Keep the current parallel execution model for fast collectors.
2. Keep Any.Run lookup and sandbox parallelism inside the Any.Run path.
3. Remove the deferred-Any.Run completion path for domain investigations so `run_analysis(...)` waits for the completed Any.Run collector result.
4. Preserve the deferred behavior for other observable types if needed, unless the investigation type also requires fully synchronized Any.Run scoring.
5. Update the timing UI label so it clearly reads as total elapsed wall-clock time rather than implied summed collector time.

**Backend Data Flow**

1. `run_investigation(...)` starts all collectors.
2. Fast collectors still complete in parallel.
3. `hybrid_analysis` still runs on its own executor, but for domain investigations the orchestrator must wait for the Any.Run future to complete instead of treating it as optional background work.
4. Only after all required collectors are complete should the task transition to `evaluating` and call `run_analysis(...)`.
5. The resulting risk score and report are therefore based on the final Any.Run evidence set.

**Timing Semantics**

- Collector row durations remain per-collector wall-clock durations.
- Total elapsed should be presented as total investigation elapsed wall-clock time.
- The UI label should be adjusted so it no longer suggests that the total should equal the sum of the rows.

**Error Handling**

- If Any.Run fails terminally, the collector should still complete with a failed status and explicit error payload so the investigation can proceed with that known failure state.
- The orchestrator should only skip waiting when the Any.Run future has already completed or failed, not when it is merely slow.

**Testing**

Add regression coverage for:

- domain investigations waiting for Any.Run before calling `run_analysis(...)`
- non-domain investigations retaining current behavior if we intentionally scope the wait to domains only
- collector timing UI showing total elapsed terminology instead of ambiguous "Total"

**Out of Scope**

- splitting Any.Run into separate platform-level collectors
- changing risk weights
- reworking the entire SSE status model
