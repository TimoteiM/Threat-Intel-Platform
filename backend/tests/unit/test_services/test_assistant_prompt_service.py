import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.services import assistant_prompt_service as prompt_service


def test_alert_prompt_uses_sanitized_content_and_required_sections() -> None:
    sanitized_entries = [
        {"entry_label": "alert-1", "sanitized_text": "User [ACCOUNT_1] from 10.0.0.1"},
    ]
    raw_entries = ["User admin from 10.0.0.1"]

    system, user = prompt_service.build_alert_analysis_prompt(
        title="Suspicious login",
        sanitized_entries=sanitized_entries,
        raw_entries=raw_entries,
    )

    assert "event interpretation" in system.lower()
    assert "executive summary" not in system.lower()
    assert "notable entities" not in system.lower()
    assert "ignore low-value collection metadata" in system.lower()
    assert "error codes" in system.lower()
    assert "ip addresses are not redacted" in system.lower()
    assert "[ACCOUNT_1]" in user
    assert "10.0.0.1" in user
    assert "admin" not in user


def test_alert_prompt_requires_key_indicator_ips_and_tokens_to_be_preserved() -> None:
    system, _ = prompt_service.build_alert_analysis_prompt(
        title="Proxy connection",
        sanitized_entries=[
            {
                "entry_label": "alert-1",
                "sanitized_text": (
                    "srcip=10.0.0.1 dstip=10.0.0.2 user=[ACCOUNT_1] "
                    'policy="SIEMBIOT_REVERSE_PROXY" dstcountry="Romania"'
                ),
            }
        ],
        raw_entries=["srcip=10.0.0.1 dstip=10.0.0.2 user=vhorga"],
    )

    assert "include the exact ip addresses" in system.lower()
    assert "source, destination, translated, c2, or ioc addresses" in system.lower()


def test_incident_prompt_contains_timeline_iocs_root_cause_sections() -> None:
    system, user = prompt_service.build_incident_correlation_prompt(
        title="Multi-stage incident",
        sanitized_entries=[
            {"entry_label": "event-1", "sanitized_text": "Observed 10.0.0.1"},
            {"entry_label": "event-2", "sanitized_text": "Observed [EMAIL_1]"},
        ],
        raw_entries=["Observed 10.0.0.1", "Observed admin@example.com"],
    )

    assert "timeline" in system.lower()
    assert "attack chain" in system.lower()
    assert "root cause" in system.lower()
    assert "remediation" in system.lower()
    assert "10.0.0.1" in user
    assert "admin@example.com" not in user


def test_prompt_forbids_placeholder_tokens_when_no_tokens_present() -> None:
    _system, user = prompt_service.build_alert_analysis_prompt(
        title="Ransomware alert",
        sanitized_entries=[{"entry_label": "alert-1", "sanitized_text": "classification=Ransomware"}],
        token_map={},
    )

    assert "Tokens present in the evidence above: none" in user
    assert "Do not output placeholder tokens" in user
