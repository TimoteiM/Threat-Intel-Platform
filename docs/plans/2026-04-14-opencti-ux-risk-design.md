# OpenCTI UX and Risk Design

**Date:** 2026-04-14

**Goal:** Improve how OpenCTI intelligence is presented in the investigation UI and make trusted OpenCTI findings materially influence investigation risk scoring.

## Context

OpenCTI evidence is currently rendered as a mostly raw set of tables in the technical evidence view. It is useful, but it does not read like a designed intelligence summary and does not make the trustworthiness or severity of the intelligence obvious at a glance.

On the backend, OpenCTI is also not treated as a first-class risk signal in `risk_aggregator.py`, even though it is a high-trust intelligence source and should be able to meaningfully raise the investigation risk score.

## Approved Direction

Use a hybrid approach:

- Redesign the OpenCTI evidence section into a structured, analyst-friendly summary with clear severity and trust cues.
- Add OpenCTI as a dedicated risk component.
- Introduce threshold-based risk floors so strong OpenCTI evidence can raise the minimum overall risk level.

## UI Design

### Summary Card

Replace the current flat OpenCTI-first impression with a compact summary card that emphasizes:

- matched observable
- observable type
- OpenCTI score
- severity badge derived from the score
- trust cue such as `Trusted Threat Intel Source`
- a one-line analyst summary assembled from the most important linked intel

The summary card should feel visually stronger than the current table rendering and should behave more like an executive intelligence panel than a raw evidence dump.

### Stat Row

Add a compact stat row below the summary card with counts for:

- indicators
- reports
- threat actors
- malware families
- ATT&CK patterns
- campaigns / intrusion sets where available

This gives the analyst a quick sense of evidence density and confidence.

### Structured Evidence Sections

Render the detailed OpenCTI evidence in grouped blocks instead of a single generic layout:

- `Threat Context`
  - threat actors
  - malware families
  - campaigns
  - intrusion sets
- `Detection Logic`
  - indicators and STIX patterns
- `Reports`
  - published reports and descriptions
- `ATT&CK Context`
  - attack patterns and MITRE IDs
- `Collector Notes`
  - fallback notes, enrichment gaps, and schema-related warnings

The intent is to preserve the underlying evidence while making it easier to scan and understand.

### Empty / Partial States

If OpenCTI does not find a match:

- show a softer, intentional empty-state card rather than a plain text note

If OpenCTI finds a match but some enrichment fails:

- show the found observable and available intelligence first
- move enrichment issues into secondary notes
- do not visually downgrade the whole section to a failure state

## Risk Model Design

### New Risk Component

Add `opencti_score` as a dedicated component in `backend/app/services/risk_aggregator.py`.

This component should be derived from:

- OpenCTI `score`
- whether a matching observable was found
- linked intelligence richness such as:
  - threat actors
  - malware families
  - ATT&CK patterns
  - reports
  - campaigns / intrusion sets

### Weighted Contribution

OpenCTI should contribute numerically to the total risk score, not just as a boolean flag.

The weights should be rebalanced rather than simply increasing the total sum. The likely approach is to slightly reduce existing component weights and reserve a dedicated slice for OpenCTI.

### Risk Floors

Use threshold-based floors because OpenCTI is a trusted source.

Approved policy:

- strong OpenCTI evidence can force at least `medium`
- very strong OpenCTI evidence can force at least `high`

Suggested interpretation:

- `high` floor when OpenCTI score is very high or when a high score is paired with strong linked intel such as malware / threat actor / report context
- `medium` floor when OpenCTI score is moderate and the observable is clearly known in OpenCTI with supporting context

This ensures OpenCTI meaningfully affects the final investigation assessment without letting weak or sparse hits dominate the whole model.

### Explainability

The returned risk payload should explicitly expose:

- `opencti_score` in components
- rationale entries describing when OpenCTI influenced the score
- rationale entries describing when an OpenCTI risk floor was applied

This is important so the frontend can explain why an investigation score increased.

## Non-Goals

- No full OpenCTI relationship graph redesign in this change
- No broad redesign of every evidence section
- No replacement of analyst judgment with OpenCTI-only logic

## Testing Expectations

Implementation should include:

- backend unit tests for OpenCTI scoring and floor behavior
- frontend validation that the OpenCTI section renders correctly for:
  - not found
  - found with sparse intel
  - found with rich intel
- verification that investigation risk rationale includes OpenCTI-driven explanations
