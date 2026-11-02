# Brave OSINT UX Simplification Design

## Goal
Make `Brave OSINT` feel like a standard first-class collector, visible by default alongside `VT` and `URLScan`, while reducing UI noise and cleaning up the local Docker environment created by earlier worktree-based development.

## Problem
The collector itself is already implemented as a normal backend collector, but the analyst experience still feels heavier than `VT`/`WHOIS`/`URLScan` because:
- the report presentation can expose more detail than needed for low-signal results
- the investigation form and report surface need to emphasize Brave as a normal analyzer, not a special-case feature
- local Docker images from multiple worktrees make the feature feel operationally more complex than it is

## Approved Direction
Keep `Brave OSINT` visible in the analyzer picker by default like `VT` and `URLScan`, and simplify its report presence so it behaves like a compact collector:
- visible by default in the analyzer picker
- visible as a normal collector row in timings/metadata
- visible in Technical Evidence as a compact summary-first section
- only emphasize it in Findings when there is medium/high signal
- clean old worktree Docker images so the local environment reflects the final product more clearly

## UI / UX Design

### Investigation Input
`Brave OSINT` remains a standard analyzer tile in the main analyzer grid for `domain` and `url` observables. It is not hidden behind an advanced or OSINT-only subgroup.

### Collector Timings / Metadata
`BRAVE OSINT` remains a standard collector row with the same visual treatment as `VT`, `URLSCAN`, and `THREAT FEEDS`.

### Technical Evidence
The `Brave OSINT` section should default to a compact layout:
- `Risk Level`
- `Score`
- `Summary`
- top 3 relevant hits
- optional expander for generated queries and additional result detail

For no-signal cases, the section should still appear if the collector ran, but should show a short, low-noise summary such as:
`No high-confidence public abuse references found.`

### Findings
Only emit a dedicated Brave finding when there is meaningful signal (for example medium/high score or strong filtered hits). Quiet runs should not get disproportionate emphasis.

## Docker Cleanup Design
This is a local environment cleanup only. We should remove stale worktree-built images that are no longer needed for the active localhost stack, specifically older `ai-assistant-gpt5-mini-*`, `brave-osint-collector-*`, and `local-fast-edits-*` images if they are not backing running containers.

Cleanup must be conservative:
- inspect running containers first
- only remove images not currently in use
- keep the active `threat-intel-*` images
- do not touch base images like `postgres`, `redis`, or `alpine` unless explicitly requested

## Risks / Constraints
- We must not accidentally remove an image that backs a currently running container.
- We must not hide Brave collector execution completely for low-signal cases; analysts should still be able to confirm it ran.
- The current workspace has unrelated local modifications, so Brave UX changes should be kept isolated from AnyRun/debug work.

## Verification
We will consider this complete when:
- `Brave OSINT` appears in the analyzer picker by default for supported observable types
- new investigations show `BRAVE OSINT` in collector metadata/timings when selected or enabled by default
- Technical Evidence shows a compact Brave section instead of an overly verbose one
- Findings only include Brave highlights when the collector found meaningful signal
- stale non-running worktree Docker images are removed without affecting the active localhost stack
