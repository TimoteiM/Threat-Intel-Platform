import importlib.util
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[3]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

APP_PACKAGE_DIR = BACKEND_ROOT / "app"
app_spec = importlib.util.spec_from_file_location(
    "app",
    APP_PACKAGE_DIR / "__init__.py",
    submodule_search_locations=[str(APP_PACKAGE_DIR)],
)
assert app_spec and app_spec.loader
app_module = importlib.util.module_from_spec(app_spec)
sys.modules["app"] = app_module
app_spec.loader.exec_module(app_module)

from app.api.email_investigations import _history_verdict_from_result


def test_history_verdict_prefers_overall_verdict():
    result_json = {
        "resolution": {
            "overall_verdict": "malicious",
            "classification": "unknown",
        }
    }

    assert _history_verdict_from_result(result_json) == "malicious"


def test_history_verdict_falls_back_to_legacy_classification():
    result_json = {"resolution": {"classification": "suspicious"}}

    assert _history_verdict_from_result(result_json) == "suspicious"


def test_history_verdict_defaults_to_unknown_when_missing():
    assert _history_verdict_from_result({}) == "unknown"
