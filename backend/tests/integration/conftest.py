"""Bind the `app` package explicitly, the way tests/unit/test_api already does.

The backend directory is itself a package (`backend/__init__.py`), and in the
api image it is mounted at /app. When pytest walks up a chain of __init__.py
files it inserts `/` into sys.path, so a plain `import app` binds
/app/__init__.py — the working directory — and `app.config` does not exist.

tests/unit/test_api/test_admin_api_health.py solves this by loading the
package from its known location and registering it before anything imports it.
The same trick is applied here for the whole integration directory, so the
smoke test runs identically on a developer machine and inside the container.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

_package_dir = BACKEND_ROOT / "app"
_already = sys.modules.get("app")
# Rebind only when `app` is absent or was bound to the wrong directory.
if _already is None or not str(getattr(_already, "__file__", "")).startswith(str(_package_dir)):
    _spec = importlib.util.spec_from_file_location(
        "app", _package_dir / "__init__.py", submodule_search_locations=[str(_package_dir)]
    )
    assert _spec and _spec.loader
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["app"] = _module
    _spec.loader.exec_module(_module)
