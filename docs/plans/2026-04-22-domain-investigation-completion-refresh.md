# Domain Investigation Completion Refresh Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Automatically refresh the domain investigation detail page when live progress reaches completion so the final report appears without a manual browser refresh.

**Architecture:** Extract the domain-only completion refresh decision into a small helper that can be tested without adding a new frontend test framework. Then update the investigation page to run a bounded follow-up refresh loop when a domain investigation reaches `concluded` or `100%` progress but the report is not yet loaded.

**Tech Stack:** Next.js, React, TypeScript, plain Node.js

---

### Task 1: Add a failing regression for completion refresh gating

**Files:**
- Create: `frontend/src/app/investigations/[id]/completionRefresh.js`
- Create: `frontend/scripts/test-domain-completion-refresh.cjs`

**Step 1: Write the failing test**

```javascript
assert.equal(
  shouldTriggerDomainCompletionRefresh({
    observableType: "domain",
    reportReady: false,
    sseDone: true,
    ssePercent: 100,
    liveState: "concluded",
    hasPendingRefresh: false,
  }),
  true,
);
```

**Step 2: Run test to verify it fails**

Run: `node frontend/scripts/test-domain-completion-refresh.cjs`
Expected: FAIL because the helper does not exist yet.

**Step 3: Write minimal implementation**

```javascript
function shouldTriggerDomainCompletionRefresh(input) {
  ...
}
```

**Step 4: Run test to verify it passes**

Run: `node frontend/scripts/test-domain-completion-refresh.cjs`
Expected: PASS

### Task 2: Wire domain-only completion refresh into the page

**Files:**
- Modify: `frontend/src/app/investigations/[id]/page.tsx`
- Modify: `frontend/src/app/investigations/[id]/completionRefresh.js`

**Step 1: Track in-flight refresh attempts**

```typescript
const completionRefreshInFlight = React.useRef(false);
```

**Step 2: Add bounded follow-up refresh loop**

```typescript
for (let attempt = 0; attempt < 5; attempt += 1) {
  await fetchData({ silent: true });
  if (report now exists) break;
}
```

**Step 3: Trigger only for domain investigations**

```typescript
if (observableType !== "domain") return;
```

**Step 4: Run the regression script again**

Run: `node frontend/scripts/test-domain-completion-refresh.cjs`
Expected: PASS
