# Dagre Process Graph Design

## Goal

Replace the current manually positioned ANY.RUN-style process graph fallback with a structured Dagre-based layout that emphasizes the entry point, suspicious chain, and relevant child processes while reducing system noise.

## Current Problem

The current graph logic in `AnyRunInteractiveEvidence.tsx` manually shapes process nodes and positions them in a custom tree. It works for small samples, but larger browser-heavy trees become messy, uneven, and hard to read. The rendering layer is mixed with filtering, grouping, and fallback graph construction, which makes the layout brittle.

## Options Considered

### 1. Recommended: rebuild the fallback graph pipeline with Dagre

Use frontend process-detail rows as the source of truth, apply relevance filtering and repeated-process grouping, then feed the remaining nodes and edges through Dagre with `rankdir="LR"`.

Pros:
- Produces a clean left-to-right attack chain
- Keeps existing React Flow rendering and click-to-details behavior
- Gives us full control over grouping and relevance filtering

Cons:
- Requires refactoring the current graph builder

### 2. Layout the backend graph only

Pros:
- Lowest code churn

Cons:
- Backend graph is already compacted and can be too sparse or degenerate for analyst readability

### 3. Move graph shaping fully into the backend

Pros:
- Centralized graph semantics

Cons:
- More backend/frontend coordination than needed for this UI-focused fix

## Approved Design

Use option 1.

## Behavior

- Source data: `behavior_details.process_details`
- Filter out low-signal system noise such as `svchost.exe`, `runtimebroker.exe`, and `lsass.exe` unless required to preserve the suspicious chain or entry path
- Group repeated sibling/parallel processes with the same executable signature into nodes like `msedge.exe (16)`
- Style:
  - entry point: cyan highlight/glow
  - suspicious nodes: red border
  - default nodes: neutral blue
  - suspicious edges/chains: highlighted
- Layout all nodes through Dagre with `rankdir="LR"`
- Keep React Flow auto-fit, zoom, pan, and node-click details

## Testing

- Verify the graph still builds and renders in production with `npm run build`
- Manually validate the process graph page and advanced AnyRun modal with a browser-heavy sample
