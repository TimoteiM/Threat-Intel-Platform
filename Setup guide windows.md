# Setup Guide — Windows

This walks you through getting the full stack running on Windows.
You need **4 terminal windows** running simultaneously.

---

## Prerequisites

Install these if you don't have them:

- **Python 3.11+**: https://python.org/downloads
- **Node.js 18+**: https://nodejs.org
- **PostgreSQL 16**: https://www.postgresql.org/download/windows/
- **Redis**: Use Memurai (Redis for Windows) → https://www.memurai.com/get-memurai
  OR use Docker: `docker run -d -p 6379:6379 redis:7-alpine`
- **Git**: https://git-scm.com/download/win

**Alternative**: If you have Docker Desktop, skip Postgres/Redis installs and use:
```powershell
docker run -d --name ti-postgres -e POSTGRES_USER=threatintel -e POSTGRES_PASSWORD=threatintel -e POSTGRES_DB=threatintel -p 5432:5432 postgres:16-alpine
docker run -d --name ti-redis -p 6379:6379 redis:7-alpine
```

---

## Step 1: Create the Database

Open a terminal and connect to PostgreSQL:

```powershell
# If using native install (psql should be in PATH):
psql -U postgres

# If using Docker:
docker exec -it ti-postgres psql -U threatintel
```

In the psql prompt:
```sql
-- Skip these if you used Docker (already created)
CREATE USER threatintel WITH PASSWORD 'threatintel';
CREATE DATABASE threatintel OWNER threatintel;
GRANT ALL PRIVILEGES ON DATABASE threatintel TO threatintel;
\q
```

---

## Step 2: Configure Environment

In the project root (`threat-intel/`), copy and edit the env file:

```powershell
cd C:\Users\tmoscaliuc\Downloads\script\threat-investigator\threat-intel
copy .env.example .env
```

Now edit `.env` with your settings:

```env
# ─── API Keys ───
ANTHROPIC_API_KEY=YOUR-KEY-HERE
ANTHROPIC_MODEL=claude-sonnet-4-20250514

# ─── Database ───
# For native PostgreSQL install:
DATABASE_URL=postgresql+asyncpg://threatintel:threatintel@localhost:5432/threatintel
DATABASE_SYNC_URL=postgresql://threatintel:threatintel@localhost:5432/threatintel

# ─── Redis ───
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# ─── Storage ───
ARTIFACT_STORAGE=local
ARTIFACT_LOCAL_PATH=./artifacts

# ─── App ───
APP_ENV=development
APP_DEBUG=true
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
LOG_LEVEL=INFO

# ─── Investigation Defaults ───
MAX_ANALYST_ITERATIONS=3
COLLECTOR_TIMEOUT=30
DEFAULT_COLLECTORS=dns,http,tls,whois,asn
```

**IMPORTANT**: Replace `YOUR-KEY-HERE` with your actual Anthropic API key.
Get one at: https://console.anthropic.com/settings/keys

---

## Step 3: Install Backend Dependencies

```powershell
# Terminal 1: Backend setup
cd C:\Users\tmoscaliuc\Downloads\script\threat-investigator\threat-intel\backend

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Also install aiofiles (needed by local storage)
pip install aiofiles
```

If `pip install` fails on `cryptography` or `asyncpg`, you may need:
```powershell
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

---

## Step 4: Run Database Migrations

With the venv still activated:

```powershell
# Terminal 1 (still in backend/)
# Make sure Postgres is running first!

cd C:\Users\tmoscaliuc\Downloads\script\threat-investigator\threat-intel\backend
alembic upgrade head
```

You should see:
```
INFO  [alembic.runtime.migration] Running upgrade  -> 001, initial schema
```

If you get a connection error, check:
- PostgreSQL is running (`pg_isready` or check Services)
- The DATABASE_SYNC_URL in `.env` is correct
- The user/password/database exist

---

## Step 5: Start the Backend API

```powershell
# Terminal 1 (still in backend/, venv activated)
# The .env file must be in the parent directory (threat-intel/)
# OR copy it to backend/

copy ..\.env .env

uvicorn app.main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
```

**Test it**: Open http://localhost:8000/api/health in your browser.
You should see: `{"status":"ok","timestamp":"...","version":"1.0.0"}`

---

## Step 6: Start the Celery Worker

```powershell
# Terminal 2: New PowerShell window
cd C:\Users\tmoscaliuc\Downloads\script\threat-investigator\threat-intel\backend
.\venv\Scripts\Activate.ps1

copy ..\.env .env

# Windows needs --pool=solo (no fork support)
celery -A app.tasks.celery_app worker --loglevel=info --pool=solo
```

You should see:
```
[config]
.> app:         threat_intel
.> transport:   redis://localhost:6379/0
...
[2026-02-12 ...] Ready.
```

**Note**: `--pool=solo` is required on Windows because Windows doesn't support `fork()`.
For better performance, use `--pool=threads --concurrency=4` or run via WSL/Docker.

---

## Step 7: Start the Frontend

```powershell
# Terminal 3: New PowerShell window
cd C:\Users\tmoscaliuc\Downloads\script\threat-investigator\threat-intel\frontend

npm install
npm run dev
```

You should see:
```
  ▲ Next.js 14.x
  - Local: http://localhost:3000
  ✓ Ready
```

**Use `npm run dev`** (not `npm start`) — `npm start` requires a production build first.

---

## Step 8: Test the Full Pipeline

1. Open **http://localhost:3000** in your browser
2. Enter a domain (e.g., `example.com`) and click **INVESTIGATE**
3. You should be redirected to the investigation page
4. Watch the Celery worker terminal — you'll see collectors running
5. After ~10-30 seconds, the report should appear

---

## Verification Checklist

| Component   | Check                                           | Expected                          |
|-------------|------------------------------------------------|-----------------------------------|
| PostgreSQL  | `psql -U threatintel -d threatintel -c '\dt'`  | Lists 7 tables                    |
| Redis       | `redis-cli ping`                                | `PONG`                            |
| API         | http://localhost:8000/api/health                | `{"status":"ok",...}`             |
| API         | http://localhost:8000/docs                       | Swagger UI                        |
| Worker      | Check terminal output                           | `Ready.`                          |
| Frontend    | http://localhost:3000                            | Investigation input form          |

---

## Troubleshooting

### "ECONNREFUSED port 8000"
The backend API isn't running. Start it first (Step 5).

### "relation does not exist"
Database migrations haven't run. Run `alembic upgrade head` (Step 4).

### "ANTHROPIC_API_KEY not set" or 401 from Claude
Check your `.env` file has a valid API key. Make sure you copied `.env` to `backend/`.

### Celery won't start on Windows
Use `--pool=solo` flag. Windows doesn't support the default prefork pool.

### "Module not found" errors
Make sure your virtual environment is activated (`.\venv\Scripts\Activate.ps1`).

### Redis connection refused
Start Redis/Memurai. On Windows with Docker: `docker start ti-redis`

### Alembic can't find models
Run alembic from the `backend/` directory, not from `backend/app/`.

---

## Architecture — What Connects to What

```
Browser (localhost:3000)
    │
    ├── Static pages ──→ Next.js (frontend)
    │
    └── /api/* ──proxy──→ FastAPI (localhost:8000)
                              │
                              ├── Reads/writes ──→ PostgreSQL (localhost:5432)
                              │
                              ├── Dispatches tasks ──→ Redis (localhost:6379)
                              │                           │
                              │                           └──→ Celery Worker
                              │                                    │
                              │                                    ├── Runs collectors (DNS/HTTP/TLS/WHOIS/ASN)
                              │                                    ├── Calls Claude API (anthropic.com)
                              │                                    ├── Writes results → PostgreSQL
                              │                                    └── Publishes progress → Redis pub/sub
                              │
                              └── SSE stream ←── Redis pub/sub (live progress)
```

---

## Running Order (every time)

1. PostgreSQL (service or Docker container)
2. Redis (service or Docker container)
3. Backend API: `uvicorn app.main:app --reload --port 8000`
4. Celery Worker: `celery -A app.tasks.celery_app worker --loglevel=info --pool=solo`
5. Frontend: `npm run dev`