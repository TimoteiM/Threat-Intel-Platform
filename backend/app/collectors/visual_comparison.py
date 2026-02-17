"""
Visual Website Comparison — captures screenshots and computes image similarity.

Uses Playwright (sync API) for headless Chromium screenshots and
Pillow for image hashing / histogram comparison.

Only invoked when a client_domain is provided alongside the investigated domain.
"""

from __future__ import annotations

import io
import logging
import math
from typing import Optional

from PIL import Image

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════
# Image hashing & comparison (Pillow only, no numpy)
# ═════════════════════════════════════════════════

def _compute_average_hash(image: Image.Image, hash_size: int = 16) -> int:
    """
    Average hash (aHash): resize, grayscale, threshold at mean.
    Returns an integer whose bits represent the hash.
    """
    img = image.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
    pixels = list(img.getdata())
    mean_val = sum(pixels) / len(pixels)
    bits = 0
    for px in pixels:
        bits = (bits << 1) | (1 if px >= mean_val else 0)
    return bits


def _compute_difference_hash(image: Image.Image, hash_size: int = 16) -> int:
    """
    Difference hash (dHash): compare adjacent pixel intensities.
    More robust to gamma/brightness changes than aHash.
    """
    img = image.convert("L").resize((hash_size + 1, hash_size), Image.LANCZOS)
    pixels = list(img.getdata())
    width = hash_size + 1
    bits = 0
    for y in range(hash_size):
        for x in range(hash_size):
            left = pixels[y * width + x]
            right = pixels[y * width + x + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def _hamming_distance(hash1: int, hash2: int) -> int:
    """Count differing bits between two hashes."""
    xor = hash1 ^ hash2
    count = 0
    while xor:
        count += xor & 1
        xor >>= 1
    return count


def _histogram_similarity(img1: Image.Image, img2: Image.Image) -> float:
    """
    Compare RGB histograms using Pearson correlation coefficient.
    Returns 0.0–1.0 (1.0 = identical histograms).
    Pure Python — no numpy needed.
    """
    # Resize both to same dimensions for fair comparison
    size = (256, 256)
    img1 = img1.convert("RGB").resize(size, Image.LANCZOS)
    img2 = img2.convert("RGB").resize(size, Image.LANCZOS)

    hist1 = img1.histogram()  # 768 values (256 per channel)
    hist2 = img2.histogram()

    n = len(hist1)
    mean1 = sum(hist1) / n
    mean2 = sum(hist2) / n

    numerator = sum((a - mean1) * (b - mean2) for a, b in zip(hist1, hist2))
    denom1 = math.sqrt(sum((a - mean1) ** 2 for a in hist1))
    denom2 = math.sqrt(sum((b - mean2) ** 2 for b in hist2))

    if denom1 == 0 or denom2 == 0:
        return 0.0

    correlation = numerator / (denom1 * denom2)
    # Clamp to [0, 1] — correlation is [-1, 1] but negative means anti-correlated
    return max(0.0, min(1.0, correlation))


def _compute_phash_similarity(img1: Image.Image, img2: Image.Image) -> float:
    """
    Compute perceptual hash similarity using both aHash and dHash.
    Returns 0.0–1.0 (1.0 = identical).
    """
    hash_size = 16
    max_bits = hash_size * hash_size

    ahash1 = _compute_average_hash(img1, hash_size)
    ahash2 = _compute_average_hash(img2, hash_size)
    ahash_sim = 1.0 - (_hamming_distance(ahash1, ahash2) / max_bits)

    dhash1 = _compute_difference_hash(img1, hash_size)
    dhash2 = _compute_difference_hash(img2, hash_size)
    dhash_sim = 1.0 - (_hamming_distance(dhash1, dhash2) / max_bits)

    # Average of both hash methods
    return (ahash_sim + dhash_sim) / 2.0


def compare_images(img1_bytes: bytes, img2_bytes: bytes) -> dict:
    """
    Compare two images and return similarity metrics.

    Returns dict with phash_similarity, histogram_similarity,
    overall_visual_similarity (all 0.0–1.0).
    """
    img1 = Image.open(io.BytesIO(img1_bytes))
    img2 = Image.open(io.BytesIO(img2_bytes))

    phash_sim = _compute_phash_similarity(img1, img2)
    hist_sim = _histogram_similarity(img1, img2)

    # Weighted average: perceptual hash is better at structure,
    # histogram is better at color similarity
    overall = 0.6 * phash_sim + 0.4 * hist_sim

    return {
        "phash_similarity": round(phash_sim, 4),
        "histogram_similarity": round(hist_sim, 4),
        "overall_visual_similarity": round(overall, 4),
    }


# ═════════════════════════════════════════════════
# Screenshot capture (Playwright)
# ═════════════════════════════════════════════════

def _is_full_url(target: str) -> bool:
    """Check if a target is a full URL (starts with http:// or https://)."""
    return target.startswith("http://") or target.startswith("https://")


def capture_screenshot(target: str, timeout: int = 60) -> tuple[bytes, str]:
    """
    Capture a viewport screenshot using headless Chromium.

    Args:
        target: Either a domain name (e.g. 'example.com') or a full URL
                (e.g. 'https://example.com/login'). If a domain is provided,
                tries HTTPS first, then falls back to HTTP.
        timeout: Total timeout in seconds.

    Returns (raw PNG bytes, final URL after all redirects including JS).
    Raises on failure.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                # Anti-bot-detection flags
                "--disable-blink-features=AutomationControlled",
                "--disable-features=VizDisplayCompositor",
                "--window-size=1280,720",
                # Allow insecure HTTP content without interstitial
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
                # Disguise as real browser
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

            # Remove the 'webdriver' navigator property that exposes automation
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                // Overwrite the plugins array to look like a real browser
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
                // Overwrite the languages property
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
                // Pass Chrome runtime check
                window.chrome = { runtime: {} };
            """)

            page = context.new_page()

            loaded = False

            def _on_chrome_error(url: str) -> bool:
                """Check if browser ended up on an error page."""
                return url.startswith("chrome-error://") or url.startswith("chrome://")

            if _is_full_url(target):
                # User provided a full URL — use it directly
                try:
                    page.goto(target, wait_until="domcontentloaded", timeout=timeout * 1000)
                    if _on_chrome_error(page.url):
                        raise RuntimeError(f"Browser error page for {target}")
                    loaded = True
                except Exception as e:
                    raise RuntimeError(f"Failed to load {target}: {e}")
            else:
                # Domain only — try HTTPS first, then HTTP
                https_timeout_ms = int(timeout * 0.4 * 1000)
                http_timeout_ms = int(timeout * 0.6 * 1000)

                https_ok = False
                try:
                    page.goto(f"https://{target}", wait_until="domcontentloaded", timeout=https_timeout_ms)
                    if not _on_chrome_error(page.url):
                        https_ok = True
                        loaded = True
                except Exception as e:
                    logger.debug(f"HTTPS failed for {target}: {e}")

                if not https_ok:
                    # Close the broken page (stuck on chrome-error://) and open
                    # a fresh one so the HTTP navigation isn't interrupted.
                    try:
                        page.close()
                    except Exception:
                        pass
                    page = context.new_page()
                    try:
                        page.goto(f"http://{target}", wait_until="domcontentloaded", timeout=http_timeout_ms)
                        if _on_chrome_error(page.url):
                            raise RuntimeError(
                                f"HTTP loaded but browser shows error page for {target}"
                            )
                        loaded = True
                    except Exception as e2:
                        raise RuntimeError(
                            f"Both HTTPS ({https_timeout_ms}ms) and HTTP ({http_timeout_ms}ms) "
                            f"failed for {target}: {e2}"
                        )

            if loaded:
                # Wait for JS redirect chains to fully resolve.
                # Some sites chain multiple JS redirects (bouncer → tracker → final).
                # We poll page.url and wait until it stabilises.
                prev_url = page.url
                for _ in range(10):  # up to ~15s total (10 × 1.5s)
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                    page.wait_for_timeout(1500)
                    curr_url = page.url
                    if curr_url == prev_url:
                        break  # URL stopped changing — redirect chain is done
                    logger.debug(f"URL changed: {prev_url} -> {curr_url}")
                    prev_url = curr_url

            # Final check — JS redirect may have landed on error page
            final_url = page.url
            if _on_chrome_error(final_url):
                raise RuntimeError(
                    f"Page ended up on browser error page after navigation for {target}"
                )

            # Capture screenshot
            screenshot_bytes = page.screenshot(
                full_page=False,  # Viewport only (consistent size)
                type="png",
            )
            return screenshot_bytes, final_url
        finally:
            browser.close()


# ═════════════════════════════════════════════════
# Main comparison function
# ═════════════════════════════════════════════════

def compare_websites(
    investigated_domain: str,
    client_domain: str,
    client_reference_image: Optional[bytes] = None,
    timeout: int = 30,
) -> dict:
    """
    Compare visual appearance of two websites.

    Args:
        investigated_domain: Domain being investigated
        client_domain: Client's domain to compare against
        client_reference_image: Optional pre-uploaded reference screenshot (PNG bytes)
        timeout: Screenshot capture timeout in seconds

    Returns:
        Dict with comparison results, screenshot bytes, and evidence fields.
        Screenshot bytes are returned separately for artifact persistence.
    """
    result = {
        "investigated_domain": investigated_domain,
        "client_domain": client_domain,
        "reference_image_used": client_reference_image is not None,
        "investigated_final_url": None,
        "client_final_url": None,
        "phash_similarity": None,
        "histogram_similarity": None,
        "overall_visual_similarity": None,
        "is_visual_clone": False,
        "is_partial_clone": False,
        "summary": "",
        "investigated_capture_error": None,
        "client_capture_error": None,
        # These are NOT persisted in evidence JSON — used for artifact storage only
        "_investigated_screenshot_bytes": None,
        "_client_screenshot_bytes": None,
    }

    # ── Capture investigated domain ──
    investigated_bytes = None
    try:
        investigated_bytes, final_url = capture_screenshot(investigated_domain, timeout)
        result["_investigated_screenshot_bytes"] = investigated_bytes
        result["investigated_final_url"] = final_url
        logger.info(f"Captured screenshot of {investigated_domain} -> {final_url} ({len(investigated_bytes)} bytes)")
    except Exception as e:
        result["investigated_capture_error"] = str(e)
        logger.warning(f"Failed to capture screenshot of {investigated_domain}: {e}")

    # ── Get client domain image ──
    client_bytes = None
    if client_reference_image:
        client_bytes = client_reference_image
        result["_client_screenshot_bytes"] = client_bytes
        logger.info(f"Using uploaded reference image for {client_domain}")
    else:
        try:
            client_bytes, final_url = capture_screenshot(client_domain, timeout)
            result["_client_screenshot_bytes"] = client_bytes
            result["client_final_url"] = final_url
            logger.info(f"Captured screenshot of {client_domain} -> {final_url} ({len(client_bytes)} bytes)")
        except Exception as e:
            result["client_capture_error"] = str(e)
            logger.warning(f"Failed to capture screenshot of {client_domain}: {e}")

    # ── Compare if both screenshots available ──
    if investigated_bytes and client_bytes:
        try:
            metrics = compare_images(investigated_bytes, client_bytes)
            result["phash_similarity"] = metrics["phash_similarity"]
            result["histogram_similarity"] = metrics["histogram_similarity"]
            result["overall_visual_similarity"] = metrics["overall_visual_similarity"]

            overall = metrics["overall_visual_similarity"]
            result["is_visual_clone"] = overall >= 0.80
            result["is_partial_clone"] = 0.50 <= overall < 0.80

            if result["is_visual_clone"]:
                result["summary"] = (
                    f"HIGH visual similarity ({overall:.0%}) between "
                    f"{investigated_domain} and {client_domain} — "
                    f"page appears to be a visual clone"
                )
            elif result["is_partial_clone"]:
                result["summary"] = (
                    f"Moderate visual similarity ({overall:.0%}) between "
                    f"{investigated_domain} and {client_domain} — "
                    f"pages share visual elements"
                )
            else:
                result["summary"] = (
                    f"Low visual similarity ({overall:.0%}) between "
                    f"{investigated_domain} and {client_domain} — "
                    f"pages appear visually distinct"
                )
        except Exception as e:
            result["summary"] = f"Image comparison failed: {e}"
            logger.warning(f"Image comparison failed: {e}")
    else:
        errors = []
        if result["investigated_capture_error"]:
            errors.append(f"investigated: {result['investigated_capture_error']}")
        if result["client_capture_error"]:
            errors.append(f"client: {result['client_capture_error']}")
        result["summary"] = f"Comparison incomplete — screenshot capture failed ({'; '.join(errors)})"

    return result
