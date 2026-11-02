# Sensitive Hostname Sanitizer Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stop generic words like `release` from being sanitized as hostnames while continuing to sanitize real FQDNs and bare internal hostnames such as `srv-01`.

**Architecture:** Keep the current regex-based extraction flow in the assistant sanitizer, but add a hostname plausibility validator before replacing matched values. This keeps the change localized and preserves existing keyed and freeform extraction patterns while reducing false positives.

**Tech Stack:** Python, `re`, pytest

---

### Task 1: Add regression tests for hostname plausibility

**Files:**
- Modify: `backend/tests/unit/test_services/test_assistant_sanitizer_service.py`
- Test: `backend/tests/unit/test_services/test_assistant_sanitizer_service.py`

**Step 1: Write the failing test**

```python
def test_sanitize_entry_prefers_real_hostname_over_generic_release_word() -> None:
    text = (
        'agentOsRevision":"Oracle Server release 8.10 5.15.0-317.197.5.1.el8uek.x86_64" '
        'agentComputerName":"onvmbp01.onenet.be"'
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "release" in result.sanitized_text
    assert "onvmbp01.onenet.be" not in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "onvmbp01.onenet.be"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest backend/tests/unit/test_services/test_assistant_sanitizer_service.py -k release -v`
Expected: FAIL because the current sanitizer is too permissive.

**Step 3: Write minimal implementation**

```python
def _looks_like_host(value: str) -> bool:
    ...
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest backend/tests/unit/test_services/test_assistant_sanitizer_service.py -k release -v`
Expected: PASS

### Task 2: Implement hostname plausibility validation

**Files:**
- Modify: `backend/app/services/assistant_sanitizer_service.py`
- Test: `backend/tests/unit/test_services/test_assistant_sanitizer_service.py`

**Step 1: Add validator rules**

```python
def _looks_like_host(value: str) -> bool:
    # Accept dotted hosts and internal names with digits/hyphens.
    ...
```

**Step 2: Use the validator in host replacement**

```python
if not _looks_like_host(original):
    return match.group(0)
```

**Step 3: Run focused tests**

Run: `python -m pytest backend/tests/unit/test_services/test_assistant_sanitizer_service.py -v`
Expected: PASS

### Task 3: Verify no regression in existing host masking

**Files:**
- Test: `backend/tests/unit/test_services/test_assistant_sanitizer_service.py`

**Step 1: Confirm existing bare-host masking still works**

Run: `python -m pytest backend/tests/unit/test_services/test_assistant_sanitizer_service.py -k host -v`
Expected: PASS with `srv-01` still masked.
