import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.services.email_resolution_service import build_email_resolution  # noqa: E402


def test_missing_email_authentication_alone_does_not_classify_suspicious() -> None:
    result = build_email_resolution(
        {
            "email_subject": "Quarterly update",
            "sender_domain": "example.com",
            "sender_ip": "203.0.113.10",
            "authentication": {"spf": None, "dkim": None, "dmarc": None},
            "urls": [],
            "attachments": [],
        },
        outcomes=[],
    )

    assert result["sections"]["email_authentication_security"]["spoofing_risk_assessment"] == "medium"
    assert result["conclusion"]["classification"] != "suspicious"
    assert result["conclusion"]["classification"] != "malicious"


def test_missing_email_authentication_does_not_override_clean_indicators() -> None:
    result = build_email_resolution(
        {
            "email_subject": "Quarterly update",
            "sender_domain": "example.com",
            "sender_ip": "203.0.113.10",
            "authentication": {"spf": "none", "dkim": "none", "dmarc": "none"},
            "urls": [],
            "attachments": [],
        },
        outcomes=[
            {"indicator_type": "sender_domain", "report": {"classification": "benign"}, "evidence": {}},
            {"indicator_type": "sender_ip", "report": {"classification": "benign"}, "evidence": {}},
        ],
    )

    assert result["conclusion"]["classification"] not in {"suspicious", "malicious"}
