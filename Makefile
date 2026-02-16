.PHONY: dev up down migrate test lint

# Start everything
up:
	docker-compose up -d

# Stop everything
down:
	docker-compose down

# Start infrastructure only (Postgres + Redis)
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
