# AnyRun Process Relevance Filter Design

## Goal
Reduce AnyRun process graph noise by keeping only analyst-relevant processes and their required execution chain, while preserving enough context to highlight likely attack flow.

## Problem
The current AnyRun graph builder emits a broad process/network graph. The frontend compensates with local pruning, but the result still includes many low-value Windows/system processes that distract from the likely malicious path.

Analysts need:
- a short process chain that highlights execution flow
- minimal system noise
- preserved ancestry/root context for suspicious processes

## Approved Direction
Move process relevance filtering into the backend graph builder and optimize for analyst readability.

## Relevance Scoring
For each process:
- `+3` if network activity
- `+2` if file write
- `+2` if registry modification
- `+2` if spawns child processes
- `+3` if suspicious command line
- `+2` if parent is suspicious
- `-3` if process name is one of:
  - `svchost.exe`
  - `explorer.exe`
  - `runtimebroker.exe`
  - `lsass.exe`

Keep only processes with score `>= 3`.

Always keep:
- initial/root process
- any process in the execution chain of suspicious processes

Collapse repeated system processes:
- Example: `svchost -> svchost -> svchost`
- Render as `svchost (3 instances)`

## Output Shape
The simplified graph should contain:
- `nodes`: relevant process nodes only
- `edges`: execution chain only

The graph should not include network/domain/url nodes in the simplified analyst view. Network, file, registry, and threat detail remain in per-process detail payloads.

## Design

### Backend scoring and filtering
Add helpers in `backend/app/services/anyrun_service.py` to:
- normalize process rows with parent/child relationships
- compute relevance score
- identify suspicious processes
- include required ancestry/descendency
- collapse repeated low-signal system processes

### Simplified graph
Update `_build_behavior_graph` to emit a process-only simplified graph:
- root analysis node
- filtered process nodes
- execution-chain edges only

### Process details
Keep existing per-process details and event counts. Add relevance metadata when useful:
- `relevance_score`
- `kept_reason`
- `collapsed_instances`

### Behavior grouping
Do not implement behavior grouping yet in this change. The new filter should make later grouping easier by reducing graph noise first.

## Verification
Complete when:
- noisy common Windows processes are filtered unless needed for the chain
- suspicious process chains remain visible from root to final process
- repeated system-process runs collapse into single graph nodes
- targeted unit tests pass
