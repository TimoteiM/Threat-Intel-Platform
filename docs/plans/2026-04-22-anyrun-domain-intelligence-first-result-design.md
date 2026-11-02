# AnyRun Domain Intelligence First Result Design

**Problem**

Domain investigations can finish their first Any.Run collection with only the URL/sandbox portion visible. After a manual rerun, the result may include the separate `domain_intelligence` payload from `app.any.run`. Analysts expect both views in the initial result, not only after cache eviction and rerun.

**Root Cause**

The current backend already starts a parallel domain-intelligence lookup inside `backend/app/services/anyrun_service.py` while collecting the primary URL result. However:

- the domain-intelligence future is bounded by the normal URL timeout and silently dropped on timeout or exception
- cached Any.Run results can be accepted without requiring `domain_intelligence`
- rerun explicitly evicts the Any.Run cache layers, which can expose the missing domain-intelligence path on a second attempt

The frontend is not the bottleneck here. `frontend/src/components/report/AnyRunInteractiveEvidence.tsx` already renders both the primary item and the `domain_intelligence` block together when the payload contains both.

**Goal**

For domain investigations, the initial Any.Run result should include both:

- the primary URL/sandbox or lookup result
- the separate domain-intelligence payload when available

If domain intelligence genuinely fails, the result should still make that failure explicit rather than silently omitting the block.

**Recommended Approach**

Treat domain-investigation Any.Run as a combined backend result with stricter completeness rules.

1. In `backend/app/services/anyrun_service.py`, keep collecting URL and domain intelligence together, but do not silently drop the domain-intelligence branch for domain investigations.
2. In `backend/app/services/hybrid_analysis_service.py`, reject cached Any.Run entries for domain investigations when they do not include a usable `domain_intelligence` payload.
3. Preserve the existing response shape so the frontend can continue rendering without special-case changes.
4. If domain intelligence fails, attach a structured error payload so analysts can distinguish "lookup failed" from "not attempted" or "missing due to timing."

**Data Flow**

1. `HybridAnalysisCollector` normalizes domain observables into URL Any.Run lookups.
2. `lookup_anyrun()` performs the primary URL lookup and a parallel domain-intelligence lookup.
3. For domain investigations, the collector should only return a cacheable "complete" Any.Run payload when the `domain_intelligence` branch has either:
   - succeeded with `checked=true`, or
   - finished with an explicit error state
4. `lookup_hybrid_analysis()` should consider cache entries incomplete if the primary Any.Run record is domain-oriented but lacks `domain_intelligence`.

**Error Handling**

- If the primary URL/sandbox result succeeds and domain intelligence also succeeds, return both as one payload.
- If the primary result succeeds and domain intelligence fails, return the primary result plus `domain_intelligence: { checked: false, error: ... }`.
- If the primary result fails, keep existing failure behavior.
- Avoid returning "success without domain intelligence" for domain investigations unless the attached domain-intelligence block explicitly explains why it failed.

**Testing**

Add backend regression coverage for:

- domain Any.Run result includes `domain_intelligence` on the first pass
- incomplete cached Any.Run domain result is not reused
- domain-intelligence failures produce an attached error payload instead of disappearing

**Out of Scope**

- frontend redesign of the Any.Run panel
- email-investigation Any.Run flow
- changing non-domain investigation behavior
