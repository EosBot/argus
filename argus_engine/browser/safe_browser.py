"""SafeBrowser — Playwright + Tor proxy with BrowserContext isolation."""

from __future__ import annotations

import logging
import hashlib
import time
from typing import Optional
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

# Graceful degradation: Playwright is optional
try:
    from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not available. SafeBrowser will return errors.")

# Stem for Tor circuit rotation (optional)
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    logger.debug("Stem not available. Tor circuit rotation disabled.")


class SafeBrowser:
    """Headless browser routed through Tor with fresh context per session.

    Features:
        - SOCKS5h proxy to Tor (DNS resolution through Tor)
        - Isolated BrowserContext per session (no shared state)
        - Circuit rotation via NEWNYM signal
        - Graceful degradation when Playwright is unavailable
    """

    def __init__(self, proxy: str = "socks5h://127.0.0.1:9050") -> None:
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is required for SafeBrowser. "
                "Install with: pip install playwright && playwright install"
            )

        # Preserve the operator-facing value for audit/debugging. Playwright's
        # proxy parser accepts ``socks5`` but not the requests-style
        # ``socks5h`` spelling, so conversion happens only at launch.
        self._proxy = proxy
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._current_url: str = ""

        self._launch_browser()

    def _launch_browser(self) -> None:
        """Launch headless Chromium with Tor proxy and isolated context."""
        self._playwright = sync_playwright().start()

        self._browser = self._playwright.chromium.launch(
            headless=True,
            proxy={"server": self._proxy.replace("socks5h://", "socks5://", 1)},
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--disable-gpu",
                "--window-size=1920,1080",
            ],
        )

        # Fresh context per session — no shared cookies, storage, or cache
        self._context = self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            java_script_enabled=False,
            bypass_csp=False,
            ignore_https_errors=True,
            accept_downloads=False,
            service_workers="block",
        )

        # Block unnecessary resources for speed and safety
        self._context.route("**/*", self._guard_route)

        self._page = self._context.new_page()
        logger.info("SafeBrowser launched with proxy %s", self._proxy)

    def navigate(self, url: str) -> dict:
        """Navigate to a URL (including .onion) via Playwright over Tor.

        Args:
            url: Target URL (http/https/.onion).

        Returns:
            dict with keys: url, status, title, content_length, elapsed_ms.
        """
        if not self._page:
            return {"error": "Browser not initialized", "url": url}
        host = (urlparse(url).hostname or "").lower()
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", host):
            return {"error": "Only valid Tor v3 .onion addresses are allowed", "url": url}

        start = time.monotonic()
        try:
            response = self._page.goto(url, wait_until="domcontentloaded", timeout=60000)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            self._current_url = self._page.url
            title = self._page.title()
            content = self._page.content()
            from argus_engine.browser.sanitizer import ContentSanitizer

            sanitizer = ContentSanitizer()
            safe_html = sanitizer.sanitize_html(content)
            safe_text = sanitizer.extract_text(safe_html)[:100_000]
            content_hash = hashlib.sha256(safe_text.encode("utf-8")).hexdigest()
            headers = response.headers if response else {}

            result = {
                "url": self._current_url,
                "status": response.status if response else None,
                "title": title,
                "content_length": len(content),
                "elapsed_ms": elapsed_ms,
                "content": safe_text,
                "content_hash": content_hash,
                "content_type": headers.get("content-type", ""),
                "captured_at": time.time(),
                "isolation": {
                    "javascript": "blocked",
                    "downloads": "blocked",
                    "service_workers": "blocked",
                    "proxy": "tor",
                },
            }

            logger.info("Navigated to %s [%s] in %dms", self._current_url, result["status"], elapsed_ms)
            return result

        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.error("Navigation failed for %s: %s", url, exc)
            return {
                "url": url,
                "status": None,
                "title": "",
                "content_length": 0,
                "elapsed_ms": elapsed_ms,
                "error": str(exc),
            }

    def _guard_route(self, route) -> None:
        """Block active/resource types and any request leaving the onion origin."""
        request = route.request
        parsed = urlparse(request.url)
        host = (parsed.hostname or "").lower()
        blocked_types = {"image", "media", "font", "websocket", "eventsource"}
        if request.resource_type in blocked_types:
            route.abort()
            return
        if parsed.scheme not in {"about", "data"} and not host.endswith(".onion"):
            route.abort()
            return
        route.continue_()

    def get_content(self) -> str:
        """Return the current page's HTML content.

        Returns:
            Raw HTML string of the current page.
        """
        if not self._page:
            return ""
        return self._page.content()

    def screenshot(self, path: str) -> bool:  # noqa: A002
        """Capture a screenshot of the current page.

        Args:
            path: File path to save the screenshot (PNG).

        Returns:
            True if screenshot was saved successfully.
        """
        if not self._page:
            logger.error("Cannot screenshot: browser not initialized")
            return False

        try:
            self._page.screenshot(path=path, full_page=False)
            logger.info("Screenshot saved to %s", path)
            return True
        except Exception as exc:
            logger.error("Screenshot failed: %s", exc)
            return False

    def rotate_circuit(self) -> bool:
        """Rotate Tor circuit by sending NEWNYM signal.

        Returns:
            True if circuit rotation was successful.
        """
        if not STEM_AVAILABLE:
            logger.warning("Stem library not available for circuit rotation")
            return False

        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit rotated (NEWNYM signal sent)")
                return True
        except Exception as exc:
            logger.error("Circuit rotation failed: %s", exc)
            return False

    def close(self) -> None:
        """Close browser, context, and stop Playwright."""
        try:
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
            logger.info("SafeBrowser closed")
        except Exception as exc:
            logger.error("Error closing browser: %s", exc)
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None

    def __enter__(self) -> "SafeBrowser":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
