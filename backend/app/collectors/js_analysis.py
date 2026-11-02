"""
JavaScript behavior analysis — Playwright-based sandbox that captures network
requests, detects credential harvesting, fingerprinting, and data exfiltration.

Called from analysis_task.py as a post-processing step (not a registered collector).
Reuses Playwright launch config from visual_comparison.py.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from typing import Callable, Optional
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from app.services.proxy_profiles import resolve_proxy_profile

logger = logging.getLogger(__name__)

# Paths that indicate credential form submission
CREDENTIAL_PATHS = re.compile(
    r"(login|signin|sign-in|auth|verify|password|submit|credential|account|session)",
    re.IGNORECASE,
)

_SENSITIVE_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("payment", re.compile(r"\b(card|credit|debit|cvv|cvc|iban|bank|expiry|expiration)\b", re.I)),
    ("credential", re.compile(r"\b(password|passcode|pin|username|user name|login|sign[ -]?in|credential)\b", re.I)),
    ("identity", re.compile(r"\b(ssn|social security|passport|national id|identity|tax id)\b", re.I)),
    ("vehicle_identifier", re.compile(
        r"\b(vehicle|registration|license plate|number plate|plate number|inmatriculare|numar de inmatriculare)\b",
        re.I,
    )),
    ("personal", re.compile(r"\b(first name|last name|full name|date of birth|birth date|address|postal|zip)\b", re.I)),
    ("contact", re.compile(r"\b(email|e-mail|phone|telephone|mobile)\b", re.I)),
)

_DATA_ENTRY_TYPES = {"text", "email", "password", "tel", "number", "date", "month", "url", "textarea", "select"}

# Known tracking pixel / analytics domains
KNOWN_TRACKERS = {
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "facebook.net", "connect.facebook.net", "pixel.facebook.com",
    "bat.bing.com", "analytics.twitter.com", "snap.licdn.com",
    "hotjar.com", "clarity.ms", "mc.yandex.ru", "plausible.io",
}

# Fingerprinting APIs to monitor
FINGERPRINT_INIT_SCRIPT = """
(function() {
    window.__fingerprintAPIs = [];
    window.__postEndpoints = [];

    // Canvas fingerprinting
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        window.__fingerprintAPIs.push('canvas.toDataURL');
        return origToDataURL.apply(this, arguments);
    };

    const origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type) {
        if (type === 'webgl' || type === 'webgl2') {
            window.__fingerprintAPIs.push('WebGL.getContext');
        }
        return origGetContext.apply(this, arguments);
    };

    // Battery API
    if (navigator.getBattery) {
        const origGetBattery = navigator.getBattery.bind(navigator);
        navigator.getBattery = function() {
            window.__fingerprintAPIs.push('navigator.getBattery');
            return origGetBattery();
        };
    }

    // AudioContext fingerprinting
    const origAudioContext = window.AudioContext || window.webkitAudioContext;
    if (origAudioContext) {
        window.AudioContext = function() {
            window.__fingerprintAPIs.push('AudioContext');
            return new origAudioContext(...arguments);
        };
    }

    // Hardware concurrency probe
    const origHardware = Object.getOwnPropertyDescriptor(
        Navigator.prototype, 'hardwareConcurrency'
    );
    if (origHardware && origHardware.get) {
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: function() {
                window.__fingerprintAPIs.push('navigator.hardwareConcurrency');
                return origHardware.get.call(navigator);
            }
        });
    }
})();
"""


def _fold_form_text(value: object) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    return " ".join("".join(ch for ch in text if not unicodedata.combining(ch)).lower().split())


def classify_rendered_form_controls(controls: list[dict]) -> dict:
    """Classify visible form controls without retaining their values."""
    classified: list[dict] = []
    categories: set[str] = set()
    form_indexes: set[int] = set()
    visible_data_controls = 0

    for raw in controls:
        if not isinstance(raw, dict) or not raw.get("visible"):
            continue
        field_type = _fold_form_text(raw.get("type") or raw.get("tag") or "text")
        if field_type not in _DATA_ENTRY_TYPES:
            continue
        visible_data_controls += 1
        combined = _fold_form_text(" ".join(
            str(raw.get(key) or "")
            for key in ("type", "autocomplete", "name", "id", "label", "placeholder", "nearby_text")
        ))
        category = ""
        if field_type == "password":
            category = "credential"
        elif field_type == "email":
            category = "contact"
        else:
            for candidate, pattern in _SENSITIVE_FIELD_PATTERNS:
                if pattern.search(combined):
                    category = candidate
                    break
        category = category or "generic_data_entry"
        categories.add(category)
        form_index = int(raw.get("form_index") or 0)
        form_indexes.add(form_index)
        classified.append({
            "form_index": form_index,
            "tag": str(raw.get("tag") or "input")[:20],
            "type": field_type[:30],
            "category": category,
            "label": str(raw.get("label") or "")[:160],
            "placeholder": str(raw.get("placeholder") or "")[:160],
            "autocomplete": str(raw.get("autocomplete") or "")[:80],
            "name": str(raw.get("name") or "")[:100],
            "required": bool(raw.get("required")),
            "has_submit_control": bool(raw.get("has_submit_control")),
            "bounds": raw.get("bounds") if isinstance(raw.get("bounds"), dict) else None,
        })

    sensitive_categories = categories - {"generic_data_entry"}
    detected = bool(classified)
    confidence = "high" if sensitive_categories else ("medium" if detected else "none")
    indicators = [f"Visible {category.replace('_', ' ')} field" for category in sorted(categories)]
    if detected and any(item["has_submit_control"] for item in classified):
        indicators.append("Rendered form includes a submit control")

    return {
        "detected": detected,
        "confidence": confidence,
        "interaction_required": detected,
        "form_count": len(form_indexes),
        "visible_control_count": visible_data_controls,
        "categories": sorted(categories),
        "indicators": indicators,
        "controls": classified[:30],
        "sources": ["rendered_dom"] if detected else [],
    }


_RENDERED_FORM_SCRIPT = """
() => {
  const candidates = Array.from(document.querySelectorAll(
    'input, textarea, select, [contenteditable="true"]'
  ));
  const formOrder = new Map();
  let nextFormIndex = 1;
  const clean = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
  const visible = (el) => {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity || 1) > 0 && rect.width >= 8 && rect.height >= 8 &&
      rect.bottom > 0 && rect.right > 0 &&
      rect.top < window.innerHeight && rect.left < window.innerWidth;
  };
  const labelFor = (el) => {
    if (el.labels && el.labels.length) return clean(Array.from(el.labels).map(x => x.innerText).join(' '));
    const parentLabel = el.closest('label');
    if (parentLabel) return clean(parentLabel.innerText);
    return clean(el.getAttribute('aria-label') || el.getAttribute('title'));
  };
  return candidates.map((el) => {
    const form = el.form || el.closest('form') || el.parentElement;
    if (!formOrder.has(form)) formOrder.set(form, nextFormIndex++);
    const rect = el.getBoundingClientRect();
    const submit = el.form
      ? el.form.querySelector('button[type="submit"], input[type="submit"], button:not([type])')
      : null;
    return {
      form_index: formOrder.get(form),
      tag: el.tagName.toLowerCase(),
      type: el.tagName === 'TEXTAREA' ? 'textarea' :
        el.tagName === 'SELECT' ? 'select' :
        clean(el.getAttribute('type') || 'text').toLowerCase(),
      autocomplete: clean(el.getAttribute('autocomplete')),
      name: clean(el.getAttribute('name')),
      id: clean(el.id),
      label: labelFor(el),
      placeholder: clean(el.getAttribute('placeholder')),
      nearby_text: clean((el.closest('fieldset, form, section, div') || el.parentElement)?.innerText).slice(0, 500),
      required: Boolean(el.required || el.getAttribute('aria-required') === 'true'),
      has_submit_control: Boolean(submit),
      visible: visible(el),
      bounds: {
        x: Math.round(rect.x), y: Math.round(rect.y),
        width: Math.round(rect.width), height: Math.round(rect.height)
      }
    };
  });
}
"""


def analyze_js_behavior(
    target: str,
    investigation_id: str,
    save_artifact_fn: Optional[Callable] = None,
    timeout: int = 60,
    proxy_country: str | None = None,
) -> dict:
    """
    Load a page in Playwright and analyze JavaScript behavior.

    Captures network requests, detects credential harvesting forms,
    fingerprinting API usage, and tracking pixels.

    Args:
        target: Domain or URL to analyze
        investigation_id: For artifact naming
        save_artifact_fn: Callback to persist HAR artifact
        timeout: Page load timeout in seconds

    Returns:
        Dict matching JSAnalysisEvidence schema
    """
    url = target if target.startswith("http") else f"https://{target}"
    target_domain = urlparse(url).hostname or target

    # Network request tracking
    captured_requests: list[dict] = []
    captured_responses: list[dict] = []
    websocket_urls: list[str] = []
    console_errors: list[str] = []
    rendered_form_controls: list[dict] = []
    rendered_form_screenshot_bytes: bytes | None = None
    proxy_profile = resolve_proxy_profile(proxy_country)

    with sync_playwright() as p:
        launch_kwargs = {}
        if proxy_profile:
            launch_kwargs["proxy"] = proxy_profile.playwright_proxy
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
                "--disable-features=VizDisplayCompositor",
                "--window-size=1280,720",
                "--allow-running-insecure-content",
            ],
            **launch_kwargs,
        )

        try:
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
                locale="en-US",
                timezone_id="America/New_York",
                java_script_enabled=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Upgrade-Insecure-Requests": "1",
                },
            )

            # Anti-bot masking
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                window.chrome = { runtime: {} };
            """)

            # Fingerprinting detection script
            context.add_init_script(FINGERPRINT_INIT_SCRIPT)

            page = context.new_page()

            # Request interception
            def on_request(request):
                try:
                    parsed = urlparse(request.url)
                    captured_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "domain": parsed.hostname or "",
                        "post_data": request.post_data[:500] if request.post_data else None,
                    })
                except Exception:
                    pass

            # Response tracking
            def on_response(response):
                try:
                    size = 0
                    try:
                        body = response.body()
                        size = len(body) if body else 0
                    except Exception:
                        pass
                    captured_responses.append({
                        "url": response.url,
                        "status": response.status,
                        "size": size,
                    })
                except Exception:
                    pass

            # WebSocket detection
            def on_websocket(ws):
                websocket_urls.append(ws.url)

            # Console errors
            def on_console(msg):
                if msg.type == "error" and len(console_errors) < 10:
                    console_errors.append(msg.text[:300])

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("websocket", on_websocket)
            page.on("console", on_console)

            try:
                page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            except Exception:
                try:
                    page.goto(url, timeout=timeout * 1000, wait_until="load")
                except Exception as e:
                    logger.warning(f"JS analysis page load failed: {e}")

            # Wait a bit for late-loading JS
            try:
                page.wait_for_timeout(3000)
            except Exception:
                pass

            # Extract fingerprinting APIs detected
            fingerprinting_apis: list[str] = []
            try:
                fp_raw = page.evaluate("() => window.__fingerprintAPIs || []")
                fingerprinting_apis = list(set(fp_raw)) if fp_raw else []
            except Exception:
                pass

            try:
                rendered_form_controls = page.evaluate(_RENDERED_FORM_SCRIPT) or []
            except Exception as exc:
                logger.debug("Rendered form extraction failed: %s", exc)
                rendered_form_controls = []

            form_detection = classify_rendered_form_controls(rendered_form_controls)
            if form_detection["detected"]:
                try:
                    rendered_form_screenshot_bytes = page.screenshot(full_page=False, type="png")
                except Exception as exc:
                    logger.debug("Rendered form screenshot capture failed: %s", exc)
        finally:
            browser.close()

    # Analyze captured data
    all_domains = set()
    external_domains = set()
    post_endpoints: list[dict] = []
    tracking_pixels: list[str] = []
    suspicious_scripts: list[dict] = []

    for req in captured_requests:
        domain = req.get("domain", "")
        if domain:
            all_domains.add(domain)
            if domain != target_domain and not domain.endswith(f".{target_domain}"):
                external_domains.add(domain)

        # POST endpoint analysis
        if req.get("method") == "POST":
            is_external = domain != target_domain and not domain.endswith(f".{target_domain}")
            is_credential = bool(CREDENTIAL_PATHS.search(req.get("url", "")))
            post_endpoints.append({
                "url": req["url"],
                "content_type": None,
                "is_external": is_external,
                "is_credential_form": is_credential and is_external,
            })

    # Tracking pixel detection (tiny image responses)
    for resp in captured_responses:
        resp_url = resp.get("url", "")
        resp_domain = urlparse(resp_url).hostname or ""
        resp_size = resp.get("size", 0)

        # Small image from known tracker or tiny response
        is_tracker_domain = any(
            resp_domain == t or resp_domain.endswith(f".{t}")
            for t in KNOWN_TRACKERS
        )
        if (resp_size <= 100 and resp_size > 0) or is_tracker_domain:
            # Check if it's an image-like request
            matching_req = next(
                (r for r in captured_requests if r["url"] == resp_url),
                None,
            )
            if matching_req and matching_req.get("resource_type") in ("image", "ping", "other"):
                tracking_pixels.append(resp_domain)
            elif is_tracker_domain:
                tracking_pixels.append(resp_domain)

    tracking_pixels = list(set(tracking_pixels))

    # Suspicious external scripts
    for req in captured_requests:
        if req.get("resource_type") == "script":
            domain = req.get("domain", "")
            if domain and domain != target_domain and not domain.endswith(f".{target_domain}"):
                reason = "External script from third-party domain"
                if any(domain == t or domain.endswith(f".{t}") for t in KNOWN_TRACKERS):
                    reason = "Script from known tracking domain"
                suspicious_scripts.append({
                    "url": req["url"],
                    "domain": domain,
                    "size_bytes": None,
                    "reason": reason,
                })

    # Limit suspicious scripts to most relevant
    suspicious_scripts = suspicious_scripts[:20]

    # Data exfiltration indicators
    data_exfil: list[str] = []
    credential_posts = [p for p in post_endpoints if p.get("is_credential_form")]
    if credential_posts:
        data_exfil.append(
            f"{len(credential_posts)} external POST(s) to credential-related endpoints"
        )
    if websocket_urls:
        ext_ws = [
            u for u in websocket_urls
            if urlparse(u).hostname not in (target_domain, f"www.{target_domain}")
        ]
        if ext_ws:
            data_exfil.append(f"{len(ext_ws)} WebSocket connection(s) to external domains")

    # Build simplified HAR artifact
    har_artifact_id = None
    rendered_form_screenshot_artifact_id = None
    if save_artifact_fn:
        try:
            har_data = {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": req["method"],
                                "url": req["url"],
                            },
                            "response": {
                                "status": next(
                                    (r["status"] for r in captured_responses if r["url"] == req["url"]),
                                    0,
                                ),
                            },
                        }
                        for req in captured_requests[:200]
                    ],
                }
            }
            har_bytes = json.dumps(har_data, indent=2).encode("utf-8")
            har_artifact_id = save_artifact_fn(
                investigation_id, "js_analysis",
                "network_capture.har",
                har_bytes, "application/json",
            )
        except Exception as e:
            logger.warning(f"Failed to save HAR artifact: {e}")
        if rendered_form_screenshot_bytes:
            try:
                rendered_form_screenshot_artifact_id = save_artifact_fn(
                    investigation_id,
                    "js_analysis",
                    "rendered_form_view.png",
                    rendered_form_screenshot_bytes,
                    "image/png",
                )
            except Exception as e:
                logger.warning("Failed to save rendered form screenshot: %s", e)

    form_detection = classify_rendered_form_controls(rendered_form_controls)
    if rendered_form_screenshot_artifact_id:
        form_detection["screenshot_artifact_id"] = rendered_form_screenshot_artifact_id
        form_detection["sources"].append("screenshot")

    # Build captured request list (capped at 200 for payload size)
    captured_req_list = []
    for req in captured_requests[:200]:
        domain = req.get("domain", "")
        is_ext = bool(domain and domain != target_domain and not domain.endswith(f".{target_domain}"))
        captured_req_list.append({
            "url": req["url"],
            "method": req.get("method", "GET"),
            "resource_type": req.get("resource_type", "other"),
            "domain": domain,
            "is_external": is_ext,
        })

    return {
        "total_requests": len(captured_requests),
        "external_requests": len([
            r for r in captured_requests
            if r.get("domain") and r["domain"] != target_domain
            and not r["domain"].endswith(f".{target_domain}")
        ]),
        "request_domains": sorted(all_domains),
        "captured_requests": captured_req_list,
        "post_endpoints": post_endpoints[:20],
        "tracking_pixels": tracking_pixels,
        "fingerprinting_apis": fingerprinting_apis,
        "suspicious_scripts": suspicious_scripts,
        "websocket_connections": websocket_urls,
        "data_exfil_indicators": data_exfil,
        "console_errors": console_errors,
        "har_artifact_id": har_artifact_id,
        "sensitive_form_detection": form_detection,
        "network_profile": proxy_profile.safe_summary if proxy_profile else None,
    }
