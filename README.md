# Domain Threat Investigation Platform

Automated domain threat investigation with evidence-based analysis powered by Claude.

## Architecture

**Collectors** gather facts (DNS, TLS, HTTP, WHOIS, ASN) →  
**Analyst** (Claude) reasons from evidence → produces structured report →  
**API** serves results with real-time progress → **UI** displays investigation

## Quick Start

```bash
# 1. Copy environment config
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

# 2. Start infrastructure
docker-compose up -d postgres redis

# 3. Run database migrations
cd backend
pip install -r requirements.txt
alembic upgrade head

# 4. Start API server
uvicorn app.main:app --reload --port 8000

# 5. Start Celery worker (separate terminal)
celery -A app.tasks.celery_app worker --loglevel=info

# 6. Start frontend (separate terminal)
cd frontend
npm install && npm run dev
```

## Project Structure

```
backend/app/
  models/     → Pydantic schemas + SQLAlchemy ORM
  collectors/ → DNS, HTTP, TLS, WHOIS, ASN fact-gathering
  analyst/    → Claude system prompt + orchestrator
  services/   → Business logic layer
  tasks/      → Celery async pipeline
  api/        → FastAPI endpoints + SSE
  db/         → Database session + queries
  storage/    → Artifact storage (local / S3)
  utils/      → Domain validation, hashing, rate limiting
```

