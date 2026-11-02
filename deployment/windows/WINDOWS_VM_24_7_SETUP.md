# Threat Intel 24/7 Deployment on Windows VM

This guide installs and runs the application on a Windows VM as persistent Windows Services, without requiring an interactive terminal session.

## 1. Target Architecture

- `ThreatIntelBackend` (FastAPI/Uvicorn) on `0.0.0.0:8000`
- `ThreatIntelCelery` (Celery worker)
- `ThreatIntelFrontend` (Next.js production server) on `0.0.0.0:3000`
- `PostgreSQL` Windows service
- `Redis` Windows service (Memurai recommended on Windows)

All application services are created with auto-start and auto-restart on failure.

## 2. Prerequisites

Install these on the VM:

1. Git
2. Python 3.12 (or your project-required Python version)
3. Node.js LTS
4. PostgreSQL 16+
5. Memurai (Redis-compatible Windows service) or equivalent Redis Windows service
6. NSSM (`nssm.exe`) from https://nssm.cc/download

Validation commands:

```powershell
git --version
python --version
node --version
npm --version
```

## 3. OS Preparation

Open an elevated PowerShell terminal (`Run as Administrator`).

Create deployment directory:

```powershell
New-Item -ItemType Directory -Force -Path C:\apps | Out-Null
cd C:\apps
```

Optional but recommended for servers:

1. Assign a static IP to VM.
2. Restrict inbound ports with Windows Firewall.
3. Expose only required ports (typically 3000 through reverse proxy, and optionally 8000 only internally).

## 4. Clone Project

```powershell
cd C:\apps
git clone <YOUR_REPO_URL> threat-intel
cd C:\apps\threat-intel
```

## 5. Configure Environment

Create `.env` in project root:

```powershell
Copy-Item .env.example .env -Force
```

Edit `C:\apps\threat-intel\.env` and set real values for:

1. `OPENAI_API_KEY`
2. `OPENAI_MODEL=gpt-5.6-luna` (primary)
3. `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL=claude-haiku-4-5-20251001` (fallback)
4. `VIRUSTOTAL_API_KEY`
5. `ABUSEIPDB_API_KEY`
6. `DATABASE_URL`
7. `DATABASE_SYNC_URL`
8. `REDIS_URL`
9. `CELERY_BROKER_URL`
10. `CELERY_RESULT_BACKEND`

Example local-service values:

```env
DATABASE_URL=postgresql+asyncpg://threatintel:threatintel@localhost:5432/threatintel
DATABASE_SYNC_URL=postgresql://threatintel:threatintel@localhost:5432/threatintel
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Do not commit `.env`.

## 6. Prepare PostgreSQL

Create DB and user (if not existing):

```powershell
psql -U postgres
```

```sql
CREATE USER threatintel WITH PASSWORD 'threatintel';
CREATE DATABASE threatintel OWNER threatintel;
GRANT ALL PRIVILEGES ON DATABASE threatintel TO threatintel;
\q
```

Ensure PostgreSQL service is running:

```powershell
Get-Service | Where-Object { $_.Name -match "postgres" } | Format-Table Name,Status,StartType
```

## 7. Prepare Redis (Memurai)

Install Memurai and ensure service is running:

```powershell
Get-Service | Where-Object { $_.Name -match "memurai|redis" } | Format-Table Name,Status,StartType
```

## 8. Install Backend Dependencies

```powershell
cd C:\apps\threat-intel\backend
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run migrations:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

## 9. Install Frontend Dependencies

```powershell
cd C:\apps\threat-intel\frontend
npm ci
npm run build
```

## 10. Add NSSM to PATH

Place `nssm.exe` in one of:

1. `C:\Windows\System32\nssm.exe`
2. Any folder already in `PATH`

Validate:

```powershell
nssm version
```

## 11. Install Application Services

Run installer script (elevated PowerShell):

```powershell
cd C:\apps\threat-intel
.\deployment\windows\install_services.ps1 `
  -ProjectRoot "C:\apps\threat-intel" `
  -ApiPort 8000 `
  -FrontendPort 3000 `
  -CeleryPool solo `
  -CeleryConcurrency 1 `
  -StartAfterInstall
```

If you need periodic scheduled tasks via Celery beat:

```powershell
.\deployment\windows\install_services.ps1 `
  -ProjectRoot "C:\apps\threat-intel" `
  -InstallBeat `
  -StartAfterInstall
```

## 12. Verify Services and Endpoints

Check service state:

```powershell
.\deployment\windows\service_control.ps1 -Action status
```

Health checks:

```powershell
curl.exe -i http://127.0.0.1:8000/api/health
curl.exe -i http://127.0.0.1:3000
curl.exe -i "http://127.0.0.1:8000/api/email-investigations/history?limit=1&offset=0"
```

Celery node check:

```powershell
cd C:\apps\threat-intel\backend
.\venv\Scripts\python.exe -m celery -A app.tasks.celery_app inspect ping
```

## 13. Log Locations

Backend service logs:

- `C:\apps\threat-intel\backend\logs\services\backend.out.log`
- `C:\apps\threat-intel\backend\logs\services\backend.err.log`

Celery service logs:

- `C:\apps\threat-intel\backend\logs\services\celery.out.log`
- `C:\apps\threat-intel\backend\logs\services\celery.err.log`

Frontend service logs:

- `C:\apps\threat-intel\frontend\logs\frontend.out.log`
- `C:\apps\threat-intel\frontend\logs\frontend.err.log`

## 14. Day-2 Operations

Start/stop/restart/status:

```powershell
cd C:\apps\threat-intel
.\deployment\windows\service_control.ps1 -Action status
.\deployment\windows\service_control.ps1 -Action restart
.\deployment\windows\service_control.ps1 -Action stop
.\deployment\windows\service_control.ps1 -Action start
```

Tail logs:

```powershell
Get-Content C:\apps\threat-intel\backend\logs\services\backend.err.log -Tail 100 -Wait
Get-Content C:\apps\threat-intel\backend\logs\services\celery.err.log -Tail 100 -Wait
Get-Content C:\apps\threat-intel\frontend\logs\frontend.err.log -Tail 100 -Wait
```

## 15. Upgrade Procedure

1. Stop services.
2. Pull latest code.
3. Update backend dependencies.
4. Run migrations.
5. Update frontend dependencies and rebuild.
6. Start services.
7. Verify health and Celery ping.

Commands:

```powershell
cd C:\apps\threat-intel
.\deployment\windows\service_control.ps1 -Action stop
git fetch --all
git checkout <BRANCH>
git pull

cd C:\apps\threat-intel\backend
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m alembic upgrade head

cd C:\apps\threat-intel\frontend
npm ci
npm run build

cd C:\apps\threat-intel
.\deployment\windows\service_control.ps1 -Action start
.\deployment\windows\service_control.ps1 -Action status
```

## 16. Rollback Procedure

1. Stop services.
2. Checkout previous known-good commit/tag.
3. Reinstall dependencies if required.
4. Rebuild frontend.
5. Start services.
6. Validate endpoints.

## 17. Uninstall Services

```powershell
cd C:\apps\threat-intel
.\deployment\windows\uninstall_services.ps1
```

## 18. Troubleshooting

### `ERR_CONNECTION_REFUSED` to backend

Backend service is down or listening on a different port.

```powershell
.\deployment\windows\service_control.ps1 -Action status
Get-NetTCPConnection -LocalPort 8000 -State Listen
```

### Celery shows no active nodes

Check Redis, Celery logs, and exact app import path.

```powershell
Get-Service | Where-Object { $_.Name -match "memurai|redis" }
Get-Content C:\apps\threat-intel\backend\logs\services\celery.err.log -Tail 200
```

### Frontend returns 500 on `/api/*`

Check backend health and frontend proxy target behavior.

```powershell
curl.exe -i http://127.0.0.1:8000/api/health
Get-Content C:\apps\threat-intel\frontend\logs\frontend.err.log -Tail 200
```

### `nssm` not found

Put `nssm.exe` in `PATH` or pass explicit path:

```powershell
.\deployment\windows\install_services.ps1 -NssmPath "C:\tools\nssm\nssm.exe"
```

## 19. Security Checklist

1. Keep `.env` restricted (NTFS ACL only for admins/service account).
2. Store secrets outside Git.
3. Restrict inbound access with firewall.
4. Use HTTPS reverse proxy (IIS/Nginx) in front of frontend for external access.
5. Rotate API keys periodically.
