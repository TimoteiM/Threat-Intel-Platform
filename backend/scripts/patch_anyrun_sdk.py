"""
Patch anyrun-sdk after pip install to fix a file upload bug.

Bug: In run_file_analysis_async (windows.py / linux.py), the code passes
     json=params + files=files to _make_request_async, which forwards them
     to requests.request(). Python requests silently ignores json= when files=
     is also provided (multipart takes precedence), so ALL task parameters
     (env_version, opt_privacy_type, etc.) are dropped from the request.
     The API receives an incomplete form-data body and returns a null/empty
     response, causing AttributeError: 'NoneType' object has no attribute 'get'.

Fix: Add a form_data= parameter to _make_request_async that maps to data=
     in requests.request() (sends as multipart form fields alongside files).
     Use form_data=params instead of json=params in run_file_analysis_async.
"""
from __future__ import annotations

import os
import site
import sys


def main() -> None:
    candidates = site.getsitepackages() if hasattr(site, "getsitepackages") else []
    if hasattr(site, "getusersitepackages"):
        candidates.append(site.getusersitepackages())

    anyrun_dir: str | None = None
    for sp in candidates:
        d = os.path.join(str(sp), "anyrun")
        if os.path.isdir(d):
            anyrun_dir = d
            break

    if not anyrun_dir:
        print("anyrun SDK not installed — skipping patch", flush=True)
        return

    # ── Fix windows.py and linux.py ────────────────────────────────────────
    for os_name in ("windows", "linux"):
        path = os.path.join(
            anyrun_dir,
            "connectors",
            "sandbox",
            "operation_systems",
            f"{os_name}.py",
        )
        if not os.path.isfile(path):
            print(f"  skip (not found): {path}", flush=True)
            continue

        with open(path, encoding="utf-8") as fh:
            src = fh.read()

        # 1. Replace json=params with form_data=params in the file-upload call
        old = "await self._make_request_async('POST', url, json=params, files=files)"
        new = "await self._make_request_async('POST', url, form_data=params, files=files)"
        patched = src.replace(old, new)

        # 2. Protect against None response_data from the API
        patched = patched.replace(
            "return response_data.get('data').get('taskid')",
            "return (response_data or {}).get('data', {}).get('taskid')",
        )

        if patched == src:
            print(f"  already patched (no changes): {path}", flush=True)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            print(f"  patched: {path}", flush=True)

    # ── Fix base_connector.py ───────────────────────────────────────────────
    bc_path = os.path.join(anyrun_dir, "connectors", "base_connector.py")
    if not os.path.isfile(bc_path):
        print(f"  skip (not found): {bc_path}", flush=True)
        return

    with open(bc_path, encoding="utf-8") as fh:
        src = fh.read()

    patched = src

    # 1. Add form_data parameter to _make_request_async signature
    patched = patched.replace(
        "        files: Optional[dict[str, tuple[str, bytes]]] = None,\n"
        "        parse_response: bool = True,",
        "        files: Optional[dict[str, tuple[str, bytes]]] = None,\n"
        "        form_data: Optional[dict] = None,\n"
        "        parse_response: bool = True,",
    )

    # 2. Fix requests.request call to use form_data as multipart form fields
    patched = patched.replace(
        "                    json=json,\n"
        "                    params=data,\n"
        "                    files=files,",
        "                    json=json if not files else None,\n"
        "                    params=data,\n"
        "                    data=(\n"
        "                        {k: str(v) for k, v in form_data.items() if v is not None}\n"
        "                        if form_data and files else None\n"
        "                    ),\n"
        "                    files=files,",
    )

    # 3. Guard against None response body in _check_response_status
    patched = patched.replace(
        "        raise RunTimeException(\n"
        "            response_data.get('message') or response_data.get('description'),\n"
        "            status or HTTPStatus.BAD_REQUEST\n"
        "        )",
        "        if not isinstance(response_data, dict):\n"
        "            raise RunTimeException(\n"
        "                f'ANY.RUN API returned status {status} with empty/invalid response body.',\n"
        "                status or HTTPStatus.BAD_REQUEST,\n"
        "            )\n"
        "        raise RunTimeException(\n"
        "            response_data.get('message') or response_data.get('description') or f'HTTP {status}',\n"
        "            status or HTTPStatus.BAD_REQUEST,\n"
        "        )",
    )

    if patched == src:
        print(f"  already patched (no changes): {bc_path}", flush=True)
    else:
        with open(bc_path, "w", encoding="utf-8") as fh:
            fh.write(patched)
        print(f"  patched: {bc_path}", flush=True)

    print("anyrun-sdk patch complete", flush=True)


if __name__ == "__main__":
    main()
