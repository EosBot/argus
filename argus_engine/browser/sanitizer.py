"""ContentSanitizer — Readability + nh3 + python-magic for safe content extraction."""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Optional: Mozilla Readability for content extraction
try:
    from readability import Document
    READABILITY_AVAILABLE = True
except ImportError:
    READABILITY_AVAILABLE = False
    logger.debug("readability-lxml not available. Using fallback text extraction.")

# Optional: nh3 (Ammonia/Rust) for HTML sanitization
try:
    import nh3
    NH3_AVAILABLE = True
except ImportError:
    NH3_AVAILABLE = False
    logger.debug("nh3 not available. Using fallback HTML sanitization.")

# Optional: python-magic for file type detection
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.debug("python-magic not available. File type verification disabled.")


# Allowed tags and attributes for nh3 fallback sanitization
_ALLOWED_TAGS = {
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "strong", "em", "b", "i", "u",
    "a", "span", "div", "blockquote", "code", "pre",
    "table", "thead", "tbody", "tr", "th", "td",
    "img", "figure", "figcaption", "hr",
}

_ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"},
    "th": {"colspan", "rowspan"},
    "td": {"colspan", "rowspan"},
}


class ContentSanitizer:
    """Sanitize HTML content using Readability + nh3 + python-magic.

    Features:
        - Extract clean article content via Readability
        - Strip dangerous HTML via nh3 (or regex fallback)
        - Verify file types via python-magic
        - Remove JavaScript from HTML
    """

    def __init__(self) -> None:
        self._magic = None
        if MAGIC_AVAILABLE:
            try:
                self._magic = magic.Magic(mime=True)
            except Exception as exc:
                logger.warning("Failed to initialize python-magic: %s", exc)

    def sanitize_html(self, html: str) -> str:
        """Sanitize HTML by removing dangerous tags and attributes.

        Uses nh3 (Ammonia/Rust) if available, otherwise falls back to
        regex-based script removal and tag stripping.

        Args:
            html: Raw HTML string.

        Returns:
            Sanitized HTML string with only safe tags/attributes.
        """
        if not html:
            return ""

        if NH3_AVAILABLE:
            try:
                cleaned = nh3.clean(
                    html,
                    tags=_ALLOWED_TAGS,
                    attributes=_ALLOWED_ATTRIBUTES,
                    url_schemes={"http", "https", "mailto"},
                )
                return cleaned
            except Exception as exc:
                logger.warning("nh3 sanitization failed, using fallback: %s", exc)

        return self._fallback_sanitize(html)

    def extract_text(self, html: str) -> str:
        """Extract clean text content from HTML.

        Uses Mozilla Readability if available for article extraction,
        otherwise falls back to basic tag stripping.

        Args:
            html: Raw HTML string.

        Returns:
            Clean text content with scripts and styles removed.
        """
        if not html:
            return ""

        if READABILITY_AVAILABLE:
            try:
                doc = Document(html)
                summary = doc.summary()
                return self._strip_tags(summary).strip()
            except Exception as exc:
                logger.warning("Readability extraction failed, using fallback: %s", exc)

        return self._fallback_extract_text(html)

    def verify_file_type(self, file_bytes: bytes, claimed_ext: str) -> bool:
        """Verify that file content matches its claimed extension.

        Uses python-magic to detect the real MIME type and compares
        against the claimed extension.

        Args:
            file_bytes: Raw bytes of the file.
            claimed_ext: Claimed file extension (e.g., ".pdf", ".exe").

        Returns:
            True if the file type matches the claimed extension.
        """
        if not file_bytes:
            return False

        if not self._magic:
            logger.debug("python-magic not available, skipping file type verification")
            return True  # Cannot verify, assume OK

        try:
            detected_mime = self._magic.from_buffer(file_bytes)
            return self._mime_matches_extension(detected_mime, claimed_ext)
        except Exception as exc:
            logger.error("File type verification failed: %s", exc)
            return False

    def redact_javascript(self, html: str) -> str:
        """Remove all JavaScript from HTML.

        Strips <script> tags, event handlers (onclick, onerror, etc.),
        and javascript: URLs.

        Args:
            html: Raw HTML string.

        Returns:
            HTML with all JavaScript removed.
        """
        if not html:
            return ""

        # Remove <script> tags and their content
        html = re.sub(
            r"<script\b[^>]*>.*?</script>",
            "",
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Remove event handler attributes (onclick, onload, onerror, etc.)
        html = re.sub(
            r'\s+on\w+="[^"]*"',
            "",
            html,
            flags=re.IGNORECASE,
        )
        html = re.sub(
            r"\s+on\w+='[^']*'",
            "",
            html,
            flags=re.IGNORECASE,
        )

        # Remove javascript: URLs
        html = re.sub(
            r'href\s*=\s*["\']javascript:[^"\']*["\']',
            'href="#"',
            html,
            flags=re.IGNORECASE,
        )

        return html

    # --- Private helpers ---

    def _fallback_sanitize(self, html: str) -> str:
        """Regex-based HTML sanitization fallback."""
        # First remove all JavaScript
        html = self.redact_javascript(html)

        # Remove style tags
        html = re.sub(r"<style\b[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

        # Remove dangerous tags entirely (with content)
        dangerous_tags = {"iframe", "object", "embed", "form", "input", "textarea", "select"}
        for tag in dangerous_tags:
            html = re.sub(
                rf"<{tag}\b[^>]*>.*?</{tag}>",
                "",
                html,
                flags=re.DOTALL | re.IGNORECASE,
            )
            html = re.sub(rf"<{tag}\b[^>]*/?>", "", html, flags=re.IGNORECASE)

        # Remove all attributes except allowed ones
        def clean_tag(match: re.Match) -> str:
            tag = match.group(1).lower()
            attrs = match.group(2) or ""
            if tag not in _ALLOWED_TAGS:
                return ""
            allowed = _ALLOWED_ATTRIBUTES.get(tag, set())
            clean_attrs = []
            for attr_match in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', attrs):
                name, value = attr_match.groups()
                if name.lower() in allowed:
                    clean_attrs.append(f'{name}="{value}"')
            attr_str = " " + " ".join(clean_attrs) if clean_attrs else ""
            return f"<{tag}{attr_str}>"

        html = re.sub(r"<(\w+)([^>]*)>", clean_tag, html, flags=re.IGNORECASE)
        return html

    def _fallback_extract_text(self, html: str) -> str:
        """Basic text extraction fallback when Readability is unavailable."""
        # Remove scripts and styles
        html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<style\b[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

        # Replace block-level tags with newlines
        html = re.sub(r"</(p|div|h[1-6]|li|tr|br)\s*>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)

        # Strip remaining tags
        text = self._strip_tags(html)

        # Clean up whitespace
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def _strip_tags(html: str) -> str:
        """Remove all HTML tags, returning plain text."""
        return re.sub(r"<[^>]+>", "", html)

    @staticmethod
    def _mime_matches_extension(mime_type: str, claimed_ext: str) -> bool:
        """Check if a MIME type matches a claimed file extension."""
        ext = claimed_ext.lower().lstrip(".")

        MIME_MAP = {
            "pdf": ["application/pdf"],
            "exe": ["application/x-executable", "application/x-dosexec", "application/x-msdownload"],
            "dll": ["application/x-dosexec", "application/x-msdownload"],
            "doc": ["application/msword"],
            "docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
            "xls": ["application/vnd.ms-excel"],
            "xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
            "zip": ["application/zip", "application/x-zip-compressed"],
            "rar": ["application/x-rar-compressed", "application/vnd.rar"],
            "7z": ["application/x-7z-compressed"],
            "tar": ["application/x-tar"],
            "gz": ["application/gzip"],
            "png": ["image/png"],
            "jpg": ["image/jpeg"],
            "jpeg": ["image/jpeg"],
            "gif": ["image/gif"],
            "svg": ["image/svg+xml"],
            "mp3": ["audio/mpeg"],
            "mp4": ["video/mp4"],
            "txt": ["text/plain"],
            "html": ["text/html", "application/xhtml+xml"],
            "xml": ["application/xml", "text/xml"],
            "json": ["application/json"],
        }

        expected = MIME_MAP.get(ext, [])
        return mime_type in expected


# Backwards-compatible public name used by the browser integration and older
# plugins.  Keeping one implementation prevents the safe browser from silently
# falling back to unsanitized content because of an import-name mismatch.
Sanitizer = ContentSanitizer
