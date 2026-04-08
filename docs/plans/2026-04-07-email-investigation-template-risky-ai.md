# Email Investigation Template-First Risky-URL AI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restore the email investigation report to a template-first analyst format, send only risky URLs to AI for URL-level reasoning, and normalize email-level AnyRun empty results so the UI reads clearly.

**Architecture:** Tighten the backend email-processing path so deterministic checks still cover all extracted indicators, but the AI payload only includes suspicious or malicious URLs. Keep the existing email-level AnyRun submission, add a normalized empty-result status/message, and update the Next.js email investigation page so the template-style report becomes the main reading path while risky URLs and AnyRun details remain available below.

**Tech Stack:** Python, pytest, FastAPI service helpers, Next.js App Router, React, TypeScript.

---

### Task 1: Add backend tests for risky URL filtering and AnyRun empty-result normalization

**Files:**
- Modify: `backend/tests/unit/test_services/test_email_investigations_helpers.py`
- Test target: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Write a failing test for selective AI URL payload filtering**

Add a test that feeds `_compact_checks_for_ai(...)` a mixed URL list and asserts only risky URLs remain in the AI-oriented URL payload.

```python
def test_compact_checks_for_ai_keeps_only_risky_urls() -> None:
    checks = {
        "urls": [
            {
                "url": "https://clean.example",
                "vt": {"verdict": "clean"},
                "effective_verdict": "clean",
                "anyrun": {"verdict": "unknown"},
                "lexical_ml": {"label": "low"},
                "url_behavior": {"credential_form_present": False, "behavior_score": 0.0},
                "screenshot": {"captured": False, "final_url": None, "error": "Not requested"},
            },
            {
                "url": "https://risky.example",
                "vt": {"verdict": "suspicious"},
                "effective_verdict": "suspicious",
                "anyrun": {"verdict": "unknown"},
                "lexical_ml": {"label": "medium"},
                "url_behavior": {"credential_form_present": True, "behavior_score": 0.8},
                "screenshot": {"captured": False, "final_url": None, "error": "Not requested"},
            },
        ]
    }
    compact = processing_svc._compact_checks_for_ai(checks)
    assert [item["url"] for item in compact["urls"]] == ["https://risky.example"]
```

**Step 2: Write a failing test for checked-but-empty AnyRun email results**

Add a test for `_lookup_email_anyrun(...)` or its normalized result shape asserting that a successful AnyRun email submission with no surfaced indicators produces a clear empty-result status/message instead of a blank payload.

```python
def test_lookup_email_anyrun_marks_checked_empty_results(monkeypatch) -> None:
    monkeypatch.setattr(
        processing_svc,
        "lookup_anyrun",
        lambda **kwargs: {
            "checked": True,
            "verdict": "unknown",
            "analysis_id": "task-123",
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
            "dynamic_io_summary": {"domains": [], "hosts": [], "mitre_attcks": []},
        },
    )
    result = processing_svc._lookup_email_anyrun(b"payload", "sample.eml", run_anyrun=True)
    assert result["checked"] is True
    assert result["email_analysis_state"] == "completed_no_artifacts"
```

**Step 3: Run the targeted tests to confirm failure**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k "compact_checks_for_ai_keeps_only_risky_urls or lookup_email_anyrun_marks_checked_empty_results" -v`

Expected: FAIL because the filtering and normalized AnyRun empty-result fields are not implemented yet.

**Step 4: Commit the tests after they pass later**

```bash
git add backend/tests/unit/test_services/test_email_investigations_helpers.py
git commit -m "test: cover selective AI URLs and AnyRun empty results"
```

### Task 2: Implement backend risky URL filtering for AI payloads

**Files:**
- Modify: `backend/app/services/email_investigation_processing_service.py`
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Add a helper that decides whether a URL is AI-worthy**

Add a small helper in `backend/app/services/email_investigation_processing_service.py` that returns `True` when a URL has strong risk signals.

```python
def _should_send_url_to_ai(item: dict[str, Any]) -> bool:
    vt_verdict = str((item.get("vt") or {}).get("verdict") or "").lower()
    effective_verdict = str(item.get("effective_verdict") or "").lower()
    anyrun_verdict = str((item.get("anyrun") or {}).get("verdict") or "").lower()
    lexical_label = str((item.get("lexical_ml") or {}).get("label") or "").lower()
    behavior = item.get("url_behavior") or {}
    if vt_verdict in {"malicious", "suspicious"}:
        return True
    if effective_verdict in {"malicious", "suspicious"}:
        return True
    if anyrun_verdict in {"malicious", "suspicious"}:
        return True
    if lexical_label == "high":
        return True
    if bool(behavior.get("credential_form_present")):
        return True
    return float(behavior.get("behavior_score") or 0.0) >= 0.7
```

**Step 2: Filter URL items inside `_compact_checks_for_ai(...)`**

Update `_compact_checks_for_ai(...)` so it still includes all other evidence, but only appends URLs that pass `_should_send_url_to_ai(...)`.

**Step 3: Keep fallback URL coverage intact**

Do not change `_build_url_assessments_fallback(...)` or `_merge_url_assessments(...)` to only risky URLs. The selective filtering should affect the AI prompt payload, not the final deterministic report coverage.

**Step 4: Run the targeted tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k "compact_checks_for_ai_keeps_only_risky_urls or compact_checks_keeps_lexical_ml_section" -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/email_investigation_processing_service.py backend/tests/unit/test_services/test_email_investigations_helpers.py
git commit -m "feat: limit email AI URL payloads to risky URLs"
```

### Task 3: Normalize email-level AnyRun empty results

**Files:**
- Modify: `backend/app/services/email_investigation_processing_service.py`
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Add a helper that classifies the email AnyRun result**

Create a helper such as `_normalize_email_anyrun_result(...)` that enriches the raw AnyRun response with:

- `email_analysis_state`
- `email_analysis_message`
- `has_surfaced_artifacts`

Use a shape like:

```python
{
    "email_analysis_state": "completed_with_artifacts" | "completed_no_artifacts" | "failed" | "disabled",
    "email_analysis_message": "...",
    "has_surfaced_artifacts": True | False,
}
```

**Step 2: Call the helper from `_lookup_email_anyrun(...)`**

Return the normalized result so the frontend no longer has to guess whether “no data” means “not run” or “ran successfully but found nothing meaningful.”

**Step 3: Re-run the AnyRun normalization tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k "lookup_email_anyrun_marks_checked_empty_results or process_email_investigation_submits_email_to_anyrun_once" -v`

Expected: PASS

**Step 4: Commit**

```bash
git add backend/app/services/email_investigation_processing_service.py backend/tests/unit/test_services/test_email_investigations_helpers.py
git commit -m "feat: normalize email AnyRun empty results"
```

### Task 4: Strengthen the template-first resolution output

**Files:**
- Modify: `backend/app/services/email_investigation_processing_service.py`
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Write a failing test for the restored analyst-style summary**

Add a test asserting that `_render_template_resolution(...)` emphasizes concise analyst bullets for sender, IP, suspicious URLs or attachments, and likely impact.

```python
def test_render_email_template_resolution_highlights_sender_ip_and_attachment_findings() -> None:
    ...
    text = processing_svc._render_template_resolution(...)
    assert "After our investigation, we found:" in text
    assert "The sender's email address" in text
    assert "The sender's IP address" in text
    assert "One suspicious attachment was found" in text
```

**Step 2: Update `_render_template_resolution(...)` to use the restored report voice**

Keep the content evidence-based and concise, closer to the example summary the user provided. Preserve graceful fallback for missing fields by using `NOT_PRESENT`.

**Step 3: Ensure AI remains optional enrichment**

Do not make the template depend on AI-generated prose. The template should remain complete when `run_ai=False` or the AI call fails.

**Step 4: Run the targeted template tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k "render_email_template_resolution" -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/email_investigation_processing_service.py backend/tests/unit/test_services/test_email_investigations_helpers.py
git commit -m "feat: restore template-first email investigation summary"
```

### Task 5: Update frontend copy and layout for template-first email investigations

**Files:**
- Modify: `frontend/src/app/email-investigations/page.tsx`
- Modify: `frontend/src/lib/types.ts`

**Step 1: Refine the top-level page copy**

Change the AnyRun checkbox label and related language so email investigations describe a single email-sample AnyRun analysis instead of per-URL/per-hash fan-out.

Example target copy:

```tsx
Run Any.Run email sample analysis
```

**Step 2: Move the template summary into the primary report position**

Adjust the page so the templated report text is the first main content block after the verdict banner, with supporting evidence sections below it.

**Step 3: Make clean URLs compact and risky URLs expanded**

In the URL section:

- keep all URLs visible
- only show the AI assessment panel for risky URLs
- keep clean URLs in a smaller deterministic presentation

Use the same backend-driven risk signals already shown in the URL cards.

**Step 4: Add AnyRun empty-state rendering**

Use the new normalized `email_analysis_state` and `email_analysis_message` fields to display:

- not run
- failed/unavailable
- completed without surfaced artifacts
- completed with artifacts

**Step 5: Update types for new AnyRun fields**

Extend `frontend/src/lib/types.ts` so the email AnyRun object includes the new normalized fields.

**Step 6: Run the frontend checks**

Run: `npm --prefix frontend run lint`

Expected: PASS, or only pre-existing unrelated warnings.

**Step 7: Commit**

```bash
git add frontend/src/app/email-investigations/page.tsx frontend/src/lib/types.ts
git commit -m "feat: restore template-first email investigation UI"
```

### Task 6: Verify the end-to-end behavior

**Files:**
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`
- Verify manually: `frontend/src/app/email-investigations/page.tsx`

**Step 1: Run the backend email helper tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -v`

Expected: PASS

**Step 2: Run the frontend lint check**

Run: `npm --prefix frontend run lint`

Expected: PASS, or only known pre-existing warnings that are unrelated to this feature.

**Step 3: Manually verify four UI scenarios**

Verify the email investigation page for:

- AnyRun disabled
- AnyRun completed with no surfaced indicators
- risky URL present and AI enabled
- only clean URLs present

Expected:

- template summary is the main report
- only risky URLs show AI assessment cards
- AnyRun empty result reads as a valid analyzed outcome
- clean URLs remain visible but compact

**Step 4: Commit final integration changes**

```bash
git add backend/tests/unit/test_services/test_email_investigations_helpers.py backend/app/services/email_investigation_processing_service.py frontend/src/app/email-investigations/page.tsx frontend/src/lib/types.ts
git commit -m "feat: improve email investigation reporting and selective AI analysis"
```
