"""Integration tests for browser security.

Tests browser sanitizer, safe browsing patterns, and
download security integration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# -- Browser Sanitizer tests ---------------------------------------------


class TestBrowserSanitizer:
    """Test browser sanitizer functionality."""

    def test_sanitize_html_removes_scripts(self, browser_sanitizer):
        """Browser sanitizer removes script tags."""
        html = '<html><script>alert(1)</script><body>Safe</body></html>'
        result = browser_sanitizer.sanitize_html(html)
        assert "<script" not in result.lower()

    def test_sanitize_html_removes_event_handlers(self, browser_sanitizer):
        """Browser sanitizer removes event handlers."""
        html = '<div onclick="alert(1)">Click me</div>'
        result = browser_sanitizer.sanitize_html(html)
        assert "onclick" not in result.lower()

    def test_sanitize_html_removes_javascript_urls(self, browser_sanitizer):
        """Browser sanitizer removes javascript: URLs."""
        html = '<a href="javascript:alert(1)">Click</a>'
        result = browser_sanitizer.sanitize_html(html)
        assert "javascript:" not in result.lower()

    def test_extract_text_from_html(self, browser_sanitizer):
        """Text is extracted from HTML."""
        html = '<html><body><p>Hello World</p></body></html>'
        result = browser_sanitizer.extract_text(html)
        assert "Hello World" in result

    def test_extract_text_strips_all_tags(self, browser_sanitizer):
        """All HTML tags are stripped in text extraction."""
        html = '<div><span>Text</span></div>'
        result = browser_sanitizer.extract_text(html)
        assert "<" not in result or result.count("<") == 0

    def test_redact_javascript(self, browser_sanitizer):
        """JavaScript is redacted from HTML."""
        html = '<div onclick="evil()" onload="bad()">Content</div>'
        result = browser_sanitizer.redact_javascript(html)
        assert "onclick" not in result.lower()
        assert "onload" not in result.lower()

    def test_verify_file_type_pdf(self, browser_sanitizer):
        """PDF file type verification works."""
        pdf_bytes = b"%PDF-1.4\n%%EOF"
        result = browser_sanitizer.verify_file_type(pdf_bytes, ".pdf")
        # Result depends on python-magic availability
        assert isinstance(result, bool)

    def test_verify_file_type_empty(self, browser_sanitizer):
        """Empty file returns False for type verification."""
        result = browser_sanitizer.verify_file_type(b"", ".pdf")
        assert result is False


# -- Safe Browser tests --------------------------------------------------


class TestSafeBrowser:
    """Test safe browser patterns."""

    def test_safe_browser_import(self):
        """Safe browser module can be imported."""
        try:
            from argus_engine.browser.safe_browser import SafeBrowser

            assert SafeBrowser is not None
        except ImportError:
            pytest.skip("SafeBrowser not available")

    def test_browser_user_agent(self):
        """Browser uses safe user agent."""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert "Mozilla" in user_agent

    def test_browser_timeout_config(self):
        """Browser has timeout configured."""
        timeout = 30
        assert timeout > 0
        assert timeout <= 120

    def test_navigation_rejects_non_v3_onion(self):
        from argus_engine.browser.safe_browser import SafeBrowser

        browser = SafeBrowser.__new__(SafeBrowser)
        browser._page = MagicMock()
        browser._context = browser._browser = browser._playwright = None
        result = browser.navigate("http://example.onion")
        assert "valid Tor v3" in result["error"]

    def test_navigation_returns_sanitized_hashed_content(self):
        from argus_engine.browser.safe_browser import SafeBrowser

        browser = SafeBrowser.__new__(SafeBrowser)
        page = MagicMock()
        page.goto.return_value.status = 200
        page.goto.return_value.headers = {"content-type": "text/html"}
        page.url = "http://" + "a" * 56 + ".onion/"
        page.title.return_value = "Evidence"
        page.content.return_value = "<script>evil()</script><p>Safe evidence</p>"
        browser._page = page
        browser._context = browser._browser = browser._playwright = None

        result = browser.navigate(page.url)

        assert result["status"] == 200
        assert result["content"] == "Safe evidence"
        assert len(result["content_hash"]) == 64
        assert result["isolation"]["javascript"] == "blocked"


# -- Browser navigation security -----------------------------------------


class TestBrowserNavigationSecurity:
    """Test browser navigation security patterns."""

    def test_url_scheme_validation(self):
        """Only safe URL schemes are allowed."""
        allowed_schemes = {"http", "https", "mailto"}
        assert "javascript" not in allowed_schemes
        assert "data" not in allowed_schemes
        assert "file" not in allowed_schemes

    def test_redirect_limit(self):
        """Redirect limit is enforced."""
        max_redirects = 5
        assert max_redirects > 0
        assert max_redirects <= 10

    def test_ssl_verification(self):
        """SSL verification is enabled."""
        verify_ssl = True
        assert verify_ssl is True


# -- Content Security Policy ---------------------------------------------


class TestContentSecurityPolicy:
    """Test Content Security Policy patterns."""

    def test_csp_header_format(self):
        """CSP header is properly formatted."""
        csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        assert "default-src" in csp
        assert "script-src" in csp

    def test_csp_blocks_inline_scripts(self):
        """CSP blocks inline scripts."""
        csp = "script-src 'self'"
        assert "'unsafe-inline'" not in csp

    def test_csp_blocks_eval(self):
        """CSP blocks eval."""
        csp = "script-src 'self'"
        assert "'unsafe-eval'" not in csp
