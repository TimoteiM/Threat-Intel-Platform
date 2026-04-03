import asyncio
import threading

from app.services import email_indicator_checks_service as indicator_svc
from app.services import email_investigation_processing_service as processing_svc


def test_compact_checks_keeps_lexical_ml_section() -> None:
    checks = {
        "sender_domain": {},
        "sender_ip": {},
        "attachments": {"present": False, "items": [], "message": ""},
        "urls": [
            {
                "url": "https://example.com",
                "vt": {"verdict": "clean"},
                "lexical_ml": {"score": 0.12, "label": "low", "model_source": "built_in"},
                "screenshot": {"captured": False, "final_url": None, "error": "Not requested"},
            }
        ],
    }
    compact = processing_svc._compact_checks_for_ai(checks)
    assert len(compact["urls"]) == 1
    assert compact["urls"][0]["lexical_ml"]["label"] == "low"


def test_prepare_history_payload_keeps_lexical_ml_without_image_blob() -> None:
    payload = {
        "filename": "a.eml",
        "urls_count": 1,
        "attachments_count": 0,
        "indicator_checks": {
            "urls": [
                {
                    "url": "https://example.com",
                    "vt": {"verdict": "clean"},
                    "lexical_ml": {"score": 0.12, "label": "low"},
                    "screenshot": {"image_base64": "abc", "captured": False},
                }
            ]
        },
    }
    stored = processing_svc.prepare_history_payload(payload)
    url_item = stored["indicator_checks"]["urls"][0]
    assert "image_base64" not in url_item["screenshot"]
    assert url_item["lexical_ml"]["label"] == "low"


def test_render_email_template_resolution_enforces_expected_layout() -> None:
    extracted = {
        "email_subject": "Quarterly Update",
        "sender_email": "noreply@example.com",
        "sender_domain": "example.com",
        "sender_ip": "1.2.3.4",
        "urls": ["https://a.example.com"],
        "attachments": [],
    }
    checks = {
        "sender_domain": {"whois": {"registrar": "Namecheap"}},
        "sender_ip": {
            "abuseipdb": {"isp": "Example ISP", "usage_type": "Data Center"},
            "vt": {"verdict": "clean", "malicious_count": 0, "suspicious_count": 0, "total_vendors": 94},
        },
        "attachments": {"items": []},
        "urls": [{"url": "https://a.example.com"}],
    }
    resolution = {
        "sender_domain_analysis": {"primary_reasoning": "example.com is a known corporate domain."}
    }
    text = processing_svc._render_template_resolution(
        extracted=extracted,
        checks=checks,
        resolution=resolution,
        context="",
    )
    assert text.startswith('Email subject: "Quarterly Update"')
    assert "After our investigation, we found:" in text
    assert "Embedded URLs:" in text
    assert "Additional findings:" in text


def test_process_email_investigation_submits_email_to_anyrun_once(monkeypatch) -> None:
    extracted = {
        "email_subject": "Quarterly Update",
        "sender_email": "noreply@example.com",
        "sender_domain": "example.com",
        "sender_ip": "1.2.3.4",
        "authentication": {},
        "urls": ["https://example.com"],
        "url_domains": ["example.com"],
        "attachments": [],
    }
    observed: list[dict] = []

    monkeypatch.setattr(processing_svc, "extract_email_iocs", lambda payload, filename: extracted)
    monkeypatch.setattr(
        processing_svc,
        "run_email_indicator_checks",
        lambda *args, **kwargs: {
            "sender_domain": {},
            "sender_ip": {},
            "urls": [],
            "attachments": {"items": []},
            "hybrid_analysis": {"items": []},
            "final_risk": {"score": 10},
        },
    )
    monkeypatch.setattr(
        processing_svc,
        "lookup_anyrun",
        lambda **kwargs: observed.append(kwargs) or {
            "checked": True,
            "indicator_type": "file",
            "verdict": "malicious",
            "analysis_id": "task-1",
            "analysis_link": "https://app.any.run/tasks/task-1",
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
            "dynamic_io_summary": {"domains": [], "hosts": [], "mitre_attcks": []},
        },
    )

    payload = b"From: a@example.com\r\nSubject: Test\r\n\r\nBody"
    result = asyncio.run(
        processing_svc.process_email_investigation(
            payload=payload,
            filename="sample.eml",
            run_anyrun=True,
            run_ai=False,
        )
    )

    assert len(observed) == 1
    assert observed[0]["indicator_type"] == "file"
    assert observed[0]["file_bytes"] == payload
    assert observed[0]["file_name"] == "sample.eml"
    assert result["indicator_checks"]["email_anyrun"]["analysis_id"] == "task-1"


def test_process_email_investigation_starts_anyrun_and_indicator_checks_concurrently(monkeypatch) -> None:
    extracted = {
        "email_subject": "Quarterly Update",
        "sender_email": "noreply@example.com",
        "sender_domain": "example.com",
        "sender_ip": "1.2.3.4",
        "authentication": {},
        "urls": ["https://example.com"],
        "url_domains": ["example.com"],
        "attachments": [],
    }
    checks_started = threading.Event()
    anyrun_started = threading.Event()

    monkeypatch.setattr(processing_svc, "extract_email_iocs", lambda payload, filename: extracted)

    def fake_checks(*args, **kwargs):
        checks_started.set()
        assert anyrun_started.wait(0.5), "AnyRun should start before indicator checks finish"
        return {
            "sender_domain": {},
            "sender_ip": {},
            "urls": [],
            "attachments": {"items": []},
            "hybrid_analysis": {"items": []},
            "final_risk": {"score": 10},
        }

    def fake_anyrun(payload, filename, *, run_anyrun):
        anyrun_started.set()
        assert checks_started.wait(0.5), "Indicator checks should start before AnyRun finishes"
        return {
            "checked": True,
            "indicator_type": "file",
            "verdict": "clean",
            "analysis_id": "task-2",
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
            "dynamic_io_summary": {"domains": [], "hosts": [], "mitre_attcks": []},
            "file_name": filename,
        }

    monkeypatch.setattr(processing_svc, "run_email_indicator_checks", fake_checks)
    monkeypatch.setattr(processing_svc, "_lookup_email_anyrun", fake_anyrun)

    result = asyncio.run(
        processing_svc.process_email_investigation(
            payload=b"From: a@example.com\r\nSubject: Test\r\n\r\nBody",
            filename="sample.eml",
            run_anyrun=True,
            run_ai=False,
        )
    )

    assert result["indicator_checks"]["email_anyrun"]["analysis_id"] == "task-2"


def test_run_email_indicator_checks_skips_hybrid_fanout_when_anyrun_enabled(monkeypatch) -> None:
    extracted = {
        "sender_ip": None,
        "sender_domain": None,
        "urls": ["https://example.com"],
        "attachments": [{"sha256": "a" * 64, "filename": "sample.bin"}],
    }

    monkeypatch.setattr(indicator_svc, "_check_sender_domain", lambda domain: {"present": True, "domain": domain})
    monkeypatch.setattr(indicator_svc, "_check_ip", lambda ip: {"present": True, "ip": ip})
    monkeypatch.setattr(indicator_svc, "_vt_lookup", lambda *args, **kwargs: {"verdict": "clean"})
    monkeypatch.setattr(indicator_svc, "_resolve_final_url", lambda url: url)
    monkeypatch.setattr(indicator_svc, "assess_url_lexical_risk", lambda url: {"score": 0.1, "label": "low"})
    monkeypatch.setattr(indicator_svc, "score_url", lambda url: {"risk_level": "low"})
    monkeypatch.setattr(indicator_svc, "analyze_url_behavior", lambda *args, **kwargs: {"checked": True, "final_url": "https://example.com"})
    monkeypatch.setattr(indicator_svc, "_should_retry_vt_on_final", lambda *args, **kwargs: False)
    monkeypatch.setattr(indicator_svc, "_urlscan_lookup", lambda url: {"checked": False, "verdict": "unknown"})
    monkeypatch.setattr(indicator_svc, "classify_email_content_locally", lambda extracted: {"score": 0.2})
    monkeypatch.setattr(indicator_svc, "analyze_attachments_static", lambda attachments, vt_items_by_sha256=None: {"score": 0.0})
    monkeypatch.setattr(indicator_svc, "aggregate_risk", lambda payload: {"score": 15, "verdict": "low"})
    monkeypatch.setattr(
        indicator_svc,
        "_check_attachments",
        lambda attachments, max_hashes, run_anyrun: {
            "present": True,
            "items": [{"sha256": "a" * 64, "hybrid_analysis": {"checked": False, "verdict": "unknown"}}],
        },
    )

    checks = indicator_svc.run_email_indicator_checks(extracted, run_anyrun=True)

    assert checks["urls"][0]["hybrid_analysis"]["checked"] is False
    assert "single email-level AnyRun submission" in checks["urls"][0]["hybrid_analysis"]["error"]
    assert checks["attachments"]["items"][0]["hybrid_analysis"]["checked"] is False
