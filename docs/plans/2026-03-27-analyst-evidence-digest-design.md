# Analyst Evidence Digest Design

## Goal
Preserve detailed SOC-style analyst reasoning, including a grounded statement about what a domain appears to be about, while keeping analyst prompts safely below model input limits.

## Problem
The current analyst flow still serializes too much raw collector evidence. Even with list trimming, large nested sections such as `hybrid_analysis`, `brave_osint`, `js_analysis`, and other collector payloads can push the prompt beyond the model input limit. When that happens, the system falls back to automated reporting, which loses the richer SOC narrative.

## Approved Direction
Introduce a deterministic `analyst_digest` layer for LLM input.

The analyst should receive:
- a compact structured digest summarizing high-signal evidence
- a grounded "about / associated with" section derived from evidence
- much smaller raw collector payloads for the remaining schema fields

The full evidence remains unchanged for persistence and UI rendering.

## Design

### Analyst digest
Add `analyst_digest` to the analyst evidence schema and prompt. This digest should contain:
- `observable_summary`: observable, type, and normalized focus
- `associated_with`: a grounded inference about what the domain or URL appears to be about
- `association_basis`: the specific clues supporting that inference
- `collector_summaries`: per-collector summaries with only high-signal fields
- `top_signals`: top investigative signals
- `top_data_gaps`: highest-impact missing data

### Grounded "what is this domain about" inference
The digest builder should infer the domain’s apparent purpose only from evidence such as:
- `http.title`
- `urlscan.page_title`
- `http.brand_indicators`
- `http.phishing_indicators`
- redirect destination host / final URL
- `whois.registrant_org`
- `brave_osint.top_hits` titles and snippets
- domain similarity and visual comparison summaries

This inference should be conservative. It may say:
- "appears to impersonate a PayPal login flow"
- "appears associated with a parked landing page"
- "appears associated with a corporate real-estate brand"

It should not invent a company or purpose that is not supported by evidence.

### Raw evidence reduction
For analyst input only, shrink heavy sections aggressively:
- `hybrid_analysis`: keep only verdict, score, analysis id, top behavior summary, and a few top network indicators
- `brave_osint`: keep top 3 hits, summary, score, risk level
- `js_analysis`: keep counts, credential POST endpoints, a few request domains, and top suspicious scripts
- `vt`: keep counts, top vendors, categories, and tags; trim `vendor_results`
- `intel`: keep hits, notes, and a few related items; drop `cert_entries_raw`
- `artifact_hashes`, `screenshot`, and similar bulky metadata should be minimized or dropped in compact tiers

### Prompt construction
Update the prompt builder so `analyst_digest` is provided in a clearly labeled block before the machine-collected evidence JSON. The machine evidence block should still be present, but much smaller.

### Size budget
Add a preflight size estimate for the final prompt payload. If the standard digest payload is still large, compact tiers should reduce both the raw evidence and the digest detail before the API call is attempted.

## Verification
Complete when:
- analyst input includes a grounded `associated_with`/about summary
- analyst payloads are substantially smaller than current raw evidence payloads
- oversized investigations produce analyst-generated SOC reasoning more often instead of automated fallback
- targeted unit tests pass
