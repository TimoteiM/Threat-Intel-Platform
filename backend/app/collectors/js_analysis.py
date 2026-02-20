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
from typing import Callable, Optional
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

# Paths that indicate credential form submission
CREDENTIAL_PATHS = re.compile(
    r"(login|signin|sign-in|auth|verify|password|submit|credential|account|session)",
    re.IGNORECASE,
)

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


def analyze_js_behavior(
    target: str,
    investigation_id: str,
    save_artifact_fn: Optional[Callable] = None,
    timeout: int = 60,
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

    with sync_playwright() as p:
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
    }
