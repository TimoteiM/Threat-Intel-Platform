# Brave OSINT UX Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Brave OSINT behave like a standard collector in the UI while safely removing stale local Docker images from old development worktrees.

**Architecture:** Keep the existing Brave backend collector unchanged and focus implementation on frontend presentation, investigation input wiring, and local Docker hygiene. Treat low-signal Brave runs as compact evidence, not as absent collectors.

**Tech Stack:** React/Next.js frontend, TypeScript, Docker Compose, PowerShell, existing collector/report infrastructure.

---

### Task 1: Lock in analyzer picker visibility

**Files:**
- Modify: `frontend/src/components/investigation/InvestigationInput.tsx`
- Test: manual UI verification

**Step 1: Write the minimal change**
Ensure `COLLECTOR_DESCRIPTORS` contains `brave_osint` and `COLLECTORS_PER_TYPE` includes `brave_osint` for `domain` and `url`.

**Step 2: Run frontend build to verify no type/runtime build failure**

Run: `docker compose build frontend`
Expected: successful frontend image build

**Step 3: Recreate frontend container**

Run: `docker compose up -d --force-recreate frontend`
Expected: frontend container starts successfully

**Step 4: Manual verification**
Open the investigation form and confirm `Brave OSINT` appears alongside `VT` and `URLScan` by default.

**Step 5: Commit**

```bash
git add frontend/src/components/investigation/InvestigationInput.tsx
git commit -m "feat: expose brave osint in analyzer picker"
```

### Task 2: Simplify Brave technical evidence presentation

**Files:**
- Modify: `frontend/src/components/report/TechnicalEvidenceTab.tsx`
- Test: manual investigation report verification

**Step 1: Write the minimal UI change**
Adjust the `Brave OSINT` section to show a compact summary-first layout:
- risk level
- score
- summary
- top 3 hits
- optional expandable details for queries and additional hits

**Step 2: Keep low-signal runs visible but quiet**
If Brave ran with score `0` or no strong hits, render a short summary line instead of verbose details.

**Step 3: Build frontend**

Run: `docker compose build frontend`
Expected: successful frontend image build

**Step 4: Recreate frontend container**

Run: `docker compose up -d --force-recreate frontend`
Expected: frontend container restarts successfully

**Step 5: Manual verification**
Use one low-signal domain and one positive-signal domain to confirm the section is compact and readable.

**Step 6: Commit**

```bash
git add frontend/src/components/report/TechnicalEvidenceTab.tsx
git commit -m "feat: simplify brave osint evidence presentation"
```

### Task 3: Limit Brave findings emphasis to meaningful signal

**Files:**
- Modify: `frontend/src/components/report/FindingsTab.tsx`
- Test: manual report verification

**Step 1: Write the minimal change**
Ensure `Brave OSINT Highlights` only renders when the collector has medium/high score or meaningful filtered hits.

**Step 2: Build frontend**

Run: `docker compose build frontend`
Expected: successful frontend image build

**Step 3: Recreate frontend container**

Run: `docker compose up -d --force-recreate frontend`
Expected: frontend container restarts successfully

**Step 4: Manual verification**
Check one investigation with Brave score `0` and one with Brave medium/high signal.

**Step 5: Commit**

```bash
git add frontend/src/components/report/FindingsTab.tsx
git commit -m "feat: gate brave osint findings by signal strength"
```

### Task 4: Safely clean stale worktree Docker images

**Files:**
- No code changes
- Test: Docker image/container inspection

**Step 1: Inspect running containers**

Run: `docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"`
Expected: identify active containers and their backing images

**Step 2: Inspect local images**

Run: `docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}"`
Expected: identify stale `ai-assistant-gpt5-mini-*`, `brave-osint-collector-*`, and `local-fast-edits-*` images

**Step 3: Remove only images not in use**

Run: `docker rmi <image ids>`
Expected: stale images removed, active `threat-intel-*` images preserved

**Step 4: Verify stack remains healthy**

Run: `docker compose ps`
Expected: active localhost stack still running normally

**Step 5: No commit**
This is local environment hygiene only.

### Task 5: Final verification

**Files:**
- Verify modified files from previous tasks

**Step 1: Run final frontend build**

Run: `docker compose build frontend`
Expected: success

**Step 2: Verify active app routes**

Run: `Invoke-WebRequest -UseBasicParsing http://localhost:3000 | Select-Object -ExpandProperty StatusCode`
Expected: `200`

**Step 3: Verify Brave collector UX manually**
Confirm:
- analyzer picker shows Brave by default
- collector metadata shows `BRAVE OSINT`
- Technical Evidence Brave section is compact
- Findings only emphasize Brave when signal exists

**Step 4: Commit remaining frontend changes**

```bash
git add frontend/src/components/investigation/InvestigationInput.tsx frontend/src/components/report/TechnicalEvidenceTab.tsx frontend/src/components/report/FindingsTab.tsx
git commit -m "feat: streamline brave osint collector ux"
```
