# Agent Playbook

## Why this exists
Use this playbook to route common tasks to the right agent workflow quickly.

## 1) Investigation stuck in `created`
Recommended workflow:
1. `systematic-debugging`
2. `verification-before-completion`

Checklist:
1. Confirm single runtime mode (local-only or docker-only).
2. Check API port owner (`:8000`).
3. Check Celery node list (`inspect ping`).
4. Verify queue names and broker URL match.
5. Submit one known-good hash investigation and watch worker logs.

## 2) Collector or pipeline behavior changes
Recommended workflow:
1. `writing-plans`
2. `executing-plans`
3. `requesting-code-review`

Checklist:
1. Define observable types affected (`domain`, `url`, `ip`, `hash`, `file`).
2. Update schema/types and API behavior together.
3. Add/adjust tests for the changed flow.
4. Verify no regression for unaffected observables.

## 3) Infra migrations (Valkey/Postgres/Celery)
Recommended workflow:
1. `writing-plans`
2. `executing-plans`
3. `verification-before-completion`

Checklist:
1. Validate compose config.
2. Pull/start containers.
3. Validate healthchecks.
4. Validate app + worker startup.
5. Run one end-to-end investigation smoke test.
6. Document upgrade caveats (e.g., major Postgres volume migration).

## 4) New feature with uncertain scope
Recommended workflow:
1. `brainstorming`
2. `writing-plans`
3. `subagent-driven-development` (if multi-step)

Checklist:
1. Lock success criteria first.
2. Keep first implementation minimal.
3. Ship behind deterministic behavior and tests.

## Prompt snippets you can reuse
1. "Use systematic debugging. Root-cause first, then fix with verification."
2. "Write a decision-complete plan before editing code."
3. "Execute in verified batches and run code review before final output."
4. "Prioritize technical evidence for hash/file/ip. Avoid narrative-only output."
