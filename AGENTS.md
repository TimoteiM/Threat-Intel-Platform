# AGENTS.md

## Purpose
This project uses agent-driven workflows (Superpowers + Codex skills) to keep delivery consistent, fast, and testable.

This file defines how agents should work in this repository.

## Default Workflow
For non-trivial work, agents should follow this sequence:

1. `brainstorming`
2. `writing-plans`
3. `executing-plans` (or `subagent-driven-development` for larger tasks)
4. `requesting-code-review`
5. `verification-before-completion`
6. `finishing-a-development-branch`

## Project Rules
1. Prefer local-only runtime while developing (`uvicorn` + local Celery) OR docker-only runtime, but never mixed.
2. Keep queue/config compatibility keys unchanged unless explicitly requested:
   - `REDIS_URL`
   - `CELERY_BROKER_URL`
   - `CELERY_RESULT_BACKEND`
3. For observable-specific behavior:
   - `domain` may use analyst interpretation.
   - `hash`, `file`, and `ip` should prioritize technical evidence and deterministic outputs.
4. Any infra/version migration (Valkey/Postgres/Celery) must include:
   - compose validation
   - startup validation
   - one end-to-end investigation smoke test
5. No completion claim without command-level verification evidence.

## High-Value Agent Triggers
Use these phrases in agent prompts when useful:

- "Use systematic debugging for this issue."
- "Write a detailed implementation plan first."
- "Execute plan in small verified batches."
- "Run verification-before-completion."
- "Do a code review pass before finalizing."

## Standard Validation Commands
Run these before finalizing code changes:

```powershell
# Backend syntax sanity (adjust file list as needed)
python -m py_compile backend/app/config.py backend/app/tasks/analysis_task.py

# Frontend type/build sanity
cd frontend
npm run -s build
```

## Runtime Sanity Checks (Windows)
```powershell
# Who listens on API port
Get-NetTCPConnection -LocalPort 8000 -State Listen

# Active Celery nodes
cd backend
.\venv\Scripts\celery.exe -A app.tasks.celery_app inspect ping
```

## Branching Policy
1. Create a dedicated branch per scoped change.
2. Keep infra migrations isolated from feature logic when possible.
3. Capture migration risk and rollback steps in the PR summary.

## Security/Secrets
1. Never print or commit API keys.
2. Use `.env` locally; use `.env.example` for documented defaults only.
3. Redact sensitive values in logs and screenshots.
