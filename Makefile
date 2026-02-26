.PHONY: dev up down infra api worker migrate migration test investigate seed doctor ci-smoke frontend-dev

# Start everything
up:
	docker-compose up -d

# Stop everything
down:
	docker-compose down

# Start infrastructure only (Postgres + Valkey)
infra:
	docker-compose up -d postgres redis

# Run API locally (requires infra running)
api:
	cd backend && uvicorn app.main:app --reload --port 8000

# Run Celery worker locally
worker:
	cd backend && celery -A app.tasks.celery_app worker --loglevel=info

# Run database migrations
migrate:
	cd backend && alembic upgrade head

# Create a new migration
migration:
	cd backend && alembic revision --autogenerate -m "$(msg)"

# Run tests
test:
	cd backend && python -m pytest tests/ -v

# Run a single domain investigation (CLI)
investigate:
	cd backend && python -m scripts.run_single_investigation $(domain)

# Seed test data
seed:
	cd backend && python -m scripts.seed_test_data

# Run runtime diagnostics (non-mutating)
doctor:
	@echo "== Threat Intel Doctor =="
	@echo ""
	@echo "-- Docker compose config --"
	@docker compose config -q && echo "OK: compose config valid" || echo "WARN: compose config invalid"
	@echo ""
	@echo "-- Docker services (postgres/redis) --"
	@docker compose ps postgres redis || echo "WARN: could not query docker compose services"
	@echo ""
	@echo "-- Valkey ping (redis service) --"
	@docker exec threat-intel-redis-1 sh -lc "valkey-cli ping || redis-cli ping" || echo "WARN: valkey/redis not reachable"
	@echo ""
	@echo "-- API health (http://localhost:8000/api/health) --"
	@python - <<'PY'
import json, urllib.request
url = "http://localhost:8000/api/health"
try:
    with urllib.request.urlopen(url, timeout=2) as r:
        print("OK:", json.loads(r.read().decode()))
except Exception as e:
    print("WARN: API health check failed:", e)
PY

# Fast backend quality gate for local/CI validation
ci-smoke:
	cd backend && python -m compileall app
	cd backend && python -m pytest tests/unit/test_collectors/test_vt_file_intel.py tests/unit/test_tasks/test_investigation_task.py -q

# Start frontend with portable Node 20 runtime (PowerShell)
frontend-dev:
	powershell -ExecutionPolicy Bypass -File .\scripts\frontend-dev.ps1 -Clean
	@echo ""
	@echo "-- Celery inspect ping (backend worker nodes) --"
	@cd backend && \
	( \
		if [ -x "venv/Scripts/celery.exe" ]; then \
			venv/Scripts/celery.exe -A app.tasks.celery_app inspect ping; \
		elif command -v celery >/dev/null 2>&1; then \
			celery -A app.tasks.celery_app inspect ping; \
		else \
			echo "WARN: celery executable not found"; \
		fi \
	) || echo "WARN: celery inspect ping failed"
	@echo ""
	@echo "-- Listening check on :8000 --"
	@python - <<'PY'
import socket
s=socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", 8000))
    print("OK: port 8000 is listening")
except Exception as e:
    print("WARN: port 8000 not reachable:", e)
finally:
    s.close()
PY
