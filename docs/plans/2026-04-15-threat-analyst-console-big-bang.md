# Threat Analyst Console Big Bang Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Redesign the full frontend to use the Threat Analyst Console visual system established in the OpenCTI Intelligence experience.

**Architecture:** Build the redesign from shared tokens and reusable UI primitives first, then migrate page shells and feature surfaces in a controlled order. Investigation, reporting, dashboard, and assistant views receive the strongest console treatment, while CRUD and form-heavy pages stay aligned but calmer.

**Tech Stack:** Next.js app router, React, TypeScript, inline styles with shared CSS variables, existing frontend component library in `frontend/src/components`, existing app pages in `frontend/src/app`.

---

### Task 1: Audit and Define Shared Visual Foundations

**Files:**
- Modify: `frontend/src/app/globals.css`
- Modify: `frontend/src/lib/constants.ts`
- Review: `frontend/src/app/layout.tsx`
- Review: `frontend/src/components/**`

**Step 1: Inventory the current global tokens and app shell**

Review the current definitions for:
- colors
- background variables
- text tokens
- radii
- spacing assumptions
- page shell defaults

Document gaps inline in notes before editing.

**Step 2: Add the missing Threat Analyst Console tokens**

Introduce or normalize variables for:
- root background
- panel background
- module background
- elevated/inset background
- strong border
- dim border
- CTI blue
- severity red
- suspicious amber
- trusted green
- relationship violet

Keep names compatible with existing usage where possible.

**Step 3: Add global utility classes only where they reduce duplication**

Add small, reusable classes such as:
- page hero container
- module shell
- eyebrow text
- console grid

Do not add a large utility framework.

**Step 4: Verify the frontend still compiles**

Run: `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: exit code `0`

**Step 5: Commit**

```bash
git add frontend/src/app/globals.css frontend/src/lib/constants.ts frontend/src/app/layout.tsx
git commit -m "feat: add threat analyst console foundation tokens"
```

### Task 2: Build Shared Console Primitives

**Files:**
- Create: `frontend/src/components/ui/ConsoleModule.tsx`
- Create: `frontend/src/components/ui/SignalCard.tsx`
- Create: `frontend/src/components/ui/PageHero.tsx`
- Create: `frontend/src/components/ui/MetadataGrid.tsx`
- Create: `frontend/src/components/ui/StatusPill.tsx`
- Create: `frontend/src/components/ui/IntelTable.tsx`
- Modify: `frontend/src/components/evidence/EvidenceTable.tsx`
- Test: frontend typecheck

**Step 1: Create the reusable module shell**

Build `ConsoleModule.tsx` with:
- eyebrow
- title
- accent
- child content
- consistent border/background treatment

**Step 2: Create reusable stat and signal components**

Build:
- `SignalCard.tsx`
- `StatusPill.tsx`

These should replace repeated inline stat box patterns.

**Step 3: Create hero and metadata primitives**

Build:
- `PageHero.tsx`
- `MetadataGrid.tsx`

These must support long technical values.

**Step 4: Create or refactor a table primitive for console views**

Either evolve `EvidenceTable.tsx` or create `IntelTable.tsx` so dense data views share:
- header styling
- row spacing
- empty handling
- severity highlighting

**Step 5: Verify the frontend compiles**

Run: `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: exit code `0`

**Step 6: Commit**

```bash
git add frontend/src/components/ui frontend/src/components/evidence/EvidenceTable.tsx
git commit -m "feat: add reusable threat console primitives"
```

### Task 3: Redesign the Dashboard

**Files:**
- Modify: `frontend/src/app/dashboard/page.tsx`
- Reuse: `frontend/src/components/ui/*`
- Test: frontend typecheck

**Step 1: Replace the simple page title with a page hero**

Add a hero that frames the dashboard as operational mission control.

**Step 2: Refactor top stat cards to use the new signal card system**

Ensure malicious, suspicious, total, and concluded counts have clear hierarchy.

**Step 3: Move charts into console modules**

Wrap chart sections in consistent console modules with improved subtitles and legends.

**Step 4: Improve empty and loading states**

Make both states visually consistent with the new shell.

**Step 5: Verify the frontend compiles**

Run the standard `tsc --noEmit` command.

**Step 6: Commit**

```bash
git add frontend/src/app/dashboard/page.tsx
git commit -m "feat: redesign dashboard with threat console layout"
```

### Task 4: Redesign Investigation Detail and Report Surfaces

**Files:**
- Modify: `frontend/src/app/investigations/[id]/page.tsx`
- Modify: `frontend/src/components/report/TechnicalEvidenceTab.tsx`
- Modify: related report components under `frontend/src/components/report/`
- Test: frontend typecheck

**Step 1: Refactor the investigation page shell**

Apply:
- page hero
- stronger section grouping
- better tab framing

**Step 2: Align report modules with the OpenCTI console language**

Refactor report sections to use the shared console module and metadata primitives instead of isolated styling.

**Step 3: Normalize evidence section hierarchy**

Make all major evidence sections feel like siblings in one system, not separate mini apps.

**Step 4: Verify the frontend compiles**

Run the standard `tsc --noEmit` command.

**Step 5: Commit**

```bash
git add frontend/src/app/investigations/[id]/page.tsx frontend/src/components/report
git commit -m "feat: redesign investigation detail and report surfaces"
```

### Task 5: Redesign Assistant Experience

**Files:**
- Modify: `frontend/src/components/assistant/AssistantResult.tsx`
- Modify: `frontend/src/app/assistant/**` if needed
- Test: frontend typecheck

**Step 1: Replace flat panels with console modules**

Refactor sanitization summary, generated report, and error state into console modules.

**Step 2: Improve the generated report presentation**

Make the report feel like an analyst brief rather than a plain preformatted block.

**Step 3: Improve empty and error states**

Use the same visual hierarchy as investigations.

**Step 4: Verify the frontend compiles**

Run the standard `tsc --noEmit` command.

**Step 5: Commit**

```bash
git add frontend/src/components/assistant/AssistantResult.tsx frontend/src/app/assistant
git commit -m "feat: redesign assistant console experience"
```

### Task 6: Redesign Email Investigation Surfaces

**Files:**
- Modify: `frontend/src/app/email-investigations/page.tsx`
- Modify: relevant components under `frontend/src/components/investigation/`
- Test: frontend typecheck

**Step 1: Update page shell and framing**

Apply the shared page hero and section structure.

**Step 2: Preserve calm input ergonomics**

Keep forms readable and efficient while aligning colors, modules, and status treatments with the console system.

**Step 3: Improve result and history presentation**

Bring investigation outputs in line with the redesigned evidence/report experience.

**Step 4: Verify the frontend compiles**

Run the standard `tsc --noEmit` command.

**Step 5: Commit**

```bash
git add frontend/src/app/email-investigations/page.tsx frontend/src/components/investigation
git commit -m "feat: redesign email investigation workspace"
```

### Task 7: Align Supporting Operational Pages

**Files:**
- Modify: `frontend/src/app/alerts/page.tsx`
- Modify: `frontend/src/app/batches/**`
- Modify: `frontend/src/app/clients/**`
- Modify: `frontend/src/app/watchlist/page.tsx`
- Modify: any shared list/table components these pages use
- Test: frontend typecheck

**Step 1: Apply shell and module consistency**

Update headings, panels, and empty states to use shared primitives.

**Step 2: Upgrade shared list and table styling**

Make operational pages feel like part of the same application without over-styling them.

**Step 3: Verify the frontend compiles**

Run the standard `tsc --noEmit` command.

**Step 4: Commit**

```bash
git add frontend/src/app/alerts frontend/src/app/batches frontend/src/app/clients frontend/src/app/watchlist
git commit -m "feat: align operational pages with threat console design"
```

### Task 8: Full Regression Pass and Cleanup

**Files:**
- Review: `frontend/src/**`
- Optional cleanup in files touched above
- Test: frontend typecheck
- Test: Docker frontend build

**Step 1: Review for duplicate styles and drift**

Remove obvious duplicated inline structures where shared primitives now exist.

**Step 2: Run frontend typecheck**

Run: `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: exit code `0`

**Step 3: Rebuild the frontend image**

Run: `docker compose build frontend`

Expected: successful production build

**Step 4: Recreate the frontend container**

Run: `docker compose up -d --force-recreate frontend`

Expected: container starts successfully

**Step 5: Commit**

```bash
git add frontend
git commit -m "chore: finish threat analyst console redesign"
```
