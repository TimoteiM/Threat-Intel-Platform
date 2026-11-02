# Any.Run Sandbox-First Design

## Goal
Prefer real ANY.RUN sandbox execution for domain and URL investigations when the current evidence does not already contain meaningful behavior detail, while skipping sandbox when rich behavior evidence is already available.

## Problem
The current pipeline can return lookup-only ANY.RUN intelligence with minimal enrichment, which leads to messages like:

`This result comes from Any.Run lookup intelligence only...`

That is useful as fallback, but it does not satisfy the expectation for rich process, DNS, connection, and HTTP behavior when a sandbox could have been executed.

## Approved Direction
Make sandbox execution conditional on evidence richness:
- if meaningful behavior data already exists, skip sandbox
- if behavior detail is missing or shallow, try sandbox first
- if sandbox cannot complete, preserve lookup intelligence and label it clearly

## Design

### Behavior sufficiency gate
Introduce a deterministic helper that decides whether existing evidence is already rich enough to skip sandbox.

For `url` and `domain`, treat sandbox as unnecessary when evidence already includes meaningful behavior such as:
- concrete HTTP behavior beyond simple reachability
- JS analysis with request/post endpoint detail
- existing ANY.RUN or Hybrid sandbox network/process detail
- URLScan or other sources only when they provide real behavior context, not just a verdict

### Sandbox-first execution rules
- `url`: default to sandbox-first unless the behavior sufficiency gate says existing evidence is already rich
- `domain`: sandbox-first only when the domain can be meaningfully analyzed as web content and behavior sufficiency is not met
- `hash/file`: keep current sandbox-oriented behavior

### Service flow change
Update the hybrid/ANY.RUN service so URL/domain requests can be called with explicit intent:
- `prefer_anyrun`: keep ANY.RUN as the primary provider when enabled
- `submit_on_not_found`: existing behavior
- new flag or condition: `sandbox_first`

When `sandbox_first=True`, the service should:
1. try a real ANY.RUN sandbox task first
2. if it completes, return sandbox detail
3. if it is deferred / not ready / unavailable, preserve lookup intelligence when available or fall back to Hybrid Analysis

### Constraints
- Do not force sandbox when existing evidence is already rich
- Do not break current fallback behavior for provider limits or deferred reports
- Keep timeout and retry budgets intact

## Verification
Complete when:
- URL/domain investigations with thin evidence attempt sandbox first
- investigations with rich behavior evidence skip sandbox
- deferred/plan-limit sandbox cases still preserve lookup results
- targeted unit tests pass
