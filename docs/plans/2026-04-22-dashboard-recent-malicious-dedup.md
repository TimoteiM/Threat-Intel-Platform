# Dashboard Recent Malicious Dedup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Show the top 10 most recent malicious domains on the dashboard without duplicates, keeping only the newest malicious investigation per domain.

**Architecture:** Keep the dashboard page unchanged and fix the behavior in the backend `GET /api/dashboard/stats` endpoint. The endpoint will deduplicate malicious investigations by normalized domain, preserve the newest row for each domain, sort those unique rows by `created_at` descending, and return the top 10.

**Tech Stack:** FastAPI, SQLAlchemy, pytest

---

### Task 1: Add the failing dashboard regression test

**Files:**
- Modify: `backend/tests/unit/test_api/test_dashboard.py`
- Test: `backend/tests/unit/test_api/test_dashboard.py`

**Step 1: Write the failing test**

```python
async def test_dashboard_recent_malicious_returns_newest_unique_domains(...):
    ...
    assert [item["domain"] for item in data["recent_malicious"]] == [...]
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_api/test_dashboard.py -k recent_malicious -v`
Expected: FAIL because the endpoint currently returns duplicate domains.

**Step 3: Write minimal implementation**

```python
recent_malicious = _dedupe_recent_malicious(rows)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_api/test_dashboard.py -k recent_malicious -v`
Expected: PASS

### Task 2: Implement newest-per-domain deduplication in the API

**Files:**
- Modify: `backend/app/api/dashboard.py`
- Test: `backend/tests/unit/test_api/test_dashboard.py`

**Step 1: Fetch enough malicious rows for post-query dedupe**

```python
recent_result = await session.execute(...)
rows = recent_result.all()
```

**Step 2: Keep only the newest row for each normalized domain**

```python
seen: set[str] = set()
for row in rows:
    key = (row.domain or "").strip().lower()
```

**Step 3: Cap response at 10 unique domains**

```python
if len(recent_malicious) == 10:
    break
```

**Step 4: Run focused test file**

Run: `python -m pytest tests/unit/test_api/test_dashboard.py -v`
Expected: PASS
