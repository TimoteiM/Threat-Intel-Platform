# Threat Intel Runbook (Docker + Migration)

This guide is for:
- colleagues who need to run the full app stack
- moving the project to a different/personal computer

This project currently uses **FastAPI + Celery + Redis + PostgreSQL + Next.js**.

## 1. Services in this application

`docker-compose.yml` starts these services:
- `postgres` (DB, port `5432`)
- `redis` (broker/result backend, port `6379`)
- `api` (FastAPI, port `8000`)
- `worker` (Celery worker)
- `beat` (Celery scheduler)
- `frontend` (Next.js, port `3000`)

## 2. Prerequisites

Install on each machine:
1. Docker Desktop (with Compose v2)
2. Git

Optional for local non-docker frontend/backend workflows:
1. Python 3.11+
2. Node.js 18+

## 3. First-time setup

From project root:

```powershell
cd C:\path\to\threat-intel
copy .env.example .env
```

Edit `.env` and set at least:
1. `OPENAI_API_KEY`
2. `OPENAI_MODEL=gpt-5-mini`
3. `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` (fallback)
4. Any intel keys you use (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, etc.)

Do not commit `.env`.

## 4. Run full stack with Docker (recommended)

From project root:

```powershell
docker compose up -d --build
```

Check status:

```powershell
docker compose ps
```

Follow logs:

```powershell
docker compose logs -f api worker frontend
```

Open:
1. Frontend: `http://localhost:3000`
2. API health: `http://localhost:8000/api/health`

## 5. Operational commands

Restart one service:

```powershell
docker compose restart api
docker compose restart worker
docker compose restart frontend
```

Stop stack:

```powershell
docker compose down
```

Stop and remove DB volume (destructive):

```powershell
docker compose down -v
```

## 6. Celery visibility and checks

Check worker ping:

```powershell
docker compose exec worker celery -A app.tasks.celery_app inspect ping
```

Inspect queue quickly:

```powershell
docker compose exec worker celery -A app.tasks.celery_app inspect active
docker compose exec worker celery -A app.tasks.celery_app inspect reserved
```

## 7. Colleague handoff checklist

Give colleagues:
1. Repo URL/branch
2. This runbook
3. `.env` template (without real secrets)
4. Secret delivery path (password manager)

Colleague startup flow:
1. Clone repo
2. Create `.env`
3. `docker compose up -d --build`
4. Validate `http://localhost:3000` and `/api/health`

## 8. Move project to personal computer

## Option A: clean migration (code + new empty data)

1. Clone repo on personal PC
2. Create new `.env`
3. Start with `docker compose up -d --build`

## Option B: full migration (code + existing investigations/history)

On old machine (from project root):

```powershell
docker compose exec -T postgres pg_dump -U threatintel threatintel > threatintel_backup.sql
```

Also copy artifacts folder if you need screenshots/files:
- Docker volume stores artifacts in named volume `artifacts`
- If you also have local artifacts under `backend/artifacts`, copy that folder too

On new machine:
1. Clone repo and create `.env`
2. Start stack once: `docker compose up -d --build`
3. Restore DB:

```powershell
Get-Content .\threatintel_backup.sql | docker compose exec -T postgres psql -U threatintel -d threatintel
```

4. If you exported artifact files, copy them into the runtime artifact path used by API/worker.

## 9. Hosted/server deployment baseline

For a server/VM deployment:
1. Install Docker + Docker Compose
2. Clone repo
3. Create production `.env` (real secrets, strict CORS)
4. Run `docker compose up -d --build`
5. Put reverse proxy (Nginx/Caddy/Traefik) in front for HTTPS and public access
6. Restrict exposed ports to only required ingress (`80/443` via proxy)

Minimum hardening before production:
1. Strong DB/Redis passwords (not defaults)
2. Non-development app settings in `.env`
3. Backup plan for Postgres + artifacts
4. Centralized logs/monitoring

## 10. Troubleshooting

`500` on `/api/email-investigations/history`:
1. Restart API after latest pull
2. Check logs: `docker compose logs -f api`

Frontend cannot call API:
1. Check frontend rewrite target from compose (`API_PROXY_TARGET=http://api:8000`)
2. Confirm API health endpoint works from host

Worker not processing:
1. `docker compose logs -f worker`
2. `docker compose exec worker celery -A app.tasks.celery_app inspect ping`

## 11. Optional local (non-docker) run

If needed for development on Windows:
1. Start infra with Docker only:
```powershell
docker compose up -d postgres redis
```
2. Start backend + worker from `backend\`:
```powershell
.\run_celery_local.ps1 -CleanStart
```
3. Start frontend from `frontend\`:
```powershell
npm install
npm run dev
```

Do not mix arbitrary runtime combinations in shared environments.
