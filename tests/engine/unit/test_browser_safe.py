"""Tests for SafeBrowser and browser sanitizer."""

import pytest
from unittest.mock import MagicMock, patch

from argus_engine.browser import safe_browser as sb_module

if not hasattr(sb_module, "sync_playwright"):
    sb_module.sync_playwright = MagicMock()


class TestSafeBrowser:
    """Test suite for SafeBrowser."""

    def test_playwright_not_available(self):
        """SafeBrowser should raise RuntimeError when Playwright is unavailable."""
        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="Playwright is required"):
                sb_module.SafeBrowser()

    def _make_mock_browser(self):
        """Create a set of mocks for browser testing."""
        mock_playwright = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()

        mock_playwright.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page

        return mock_playwright, mock_browser, mock_context, mock_page

    def test_init_with_playwright(self):
        """SafeBrowser should initialize with mocked Playwright."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        assert browser._page is not None
        assert browser._proxy == "socks5h://127.0.0.1:9050"

    def test_custom_proxy(self):
        """SafeBrowser should accept custom proxy."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser(proxy="socks5h://custom:9050")

        assert browser._proxy == "socks5h://custom:9050"

    def test_navigate(self):
        """navigate should return page info."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        mock_response = MagicMock()
        mock_response.status = 200
        mock_page.goto.return_value = mock_response
        onion_url = "http://" + ("a" * 56) + ".onion"
        mock_page.url = onion_url
        mock_page.title.return_value = "Example"
        mock_page.content.return_value = "<html>content</html>"

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        result = browser.navigate(onion_url)
        assert result["url"] == onion_url
        assert result["status"] == 200
        assert result["title"] == "Example"
        assert result["content_length"] > 0

    def test_navigate_failure(self):
        """navigate should handle navigation failures."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        mock_page.goto.side_effect = Exception("Navigation timeout")

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        onion_url = "http://" + ("a" * 56) + ".onion"
        result = browser.navigate(onion_url)
        assert "error" in result
        assert result["status"] is None

    def test_navigate_no_page(self):
        """navigate should handle missing page."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        browser._page = None
        result = browser.navigate("http://example.com")
        assert "error" in result

    def test_get_content(self):
        """get_content should return page HTML."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        mock_page.content.return_value = "<html>test</html>"

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        result = browser.get_content()
        assert result == "<html>test</html>"

    def test_get_content_no_page(self):
        """get_content should return empty string when no page."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        browser._page = None
        result = browser.get_content()
        assert result == ""

    def test_screenshot(self):
        """screenshot should save screenshot."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        result = browser.screenshot("/tmp/test.png")
        assert result is True

    def test_screenshot_failure(self):
        """screenshot should handle failures."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        mock_page.screenshot.side_effect = Exception("Screenshot failed")

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        result = browser.screenshot("/tmp/test.png")
        assert result is False

    def test_rotate_circuit_no_stem(self):
        """rotate_circuit should fail gracefully without stem."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "STEM_AVAILABLE", False), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()
            # Re-patch after browser creation since rotate_circuit checks at call time
            with patch.object(sb_module, "STEM_AVAILABLE", False):
                result = browser.rotate_circuit()
        assert result is False

    def test_close(self):
        """close should clean up resources."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            browser = sb_module.SafeBrowser()

        browser.close()
        assert browser._page is None
        assert browser._context is None
        assert browser._browser is None

    def test_context_manager(self):
        """SafeBrowser should work as context manager."""
        mock_playwright, mock_browser, mock_context, mock_page = self._make_mock_browser()
        mock_sync = MagicMock()
        mock_sync.return_value.start.return_value = mock_playwright

        with patch.object(sb_module, "PLAYWRIGHT_AVAILABLE", True), \
             patch.object(sb_module, "sync_playwright", mock_sync):
            with sb_module.SafeBrowser() as browser:
                assert browser is not None
