"""IOCParser — IOC parsing and categorization.

Wraps argus_engine/intel/ioc_extractor.py to provide a unified async interface
for IOC extraction and categorization.

Supported IOC types:
    - IPv4, IPv6 addresses
    - Domain names, URLs
    - MD5, SHA1, SHA256, SHA512 hashes
    - Email addresses
    - CVE identifiers
    - BTC/ETH wallet addresses
    - Onion v2/v3 addresses
    - PGP key fingerprints

Usage::

    from backend.tools.ioc_parser import IOCParser

    parser = IOCParser()
    result = await parser.parse("Check http://evil.com and 1.2.3.4")
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IOCResult:
    """Result of IOC parsing.

    Attributes:
        iocs: Dict mapping IOC type to list of unique values.
        total_count: Total number of IOCs found.
        categories: List of IOC categories found.
        primary_type: Most common IOC type.
        source_text_length: Length of source text analyzed.
    """

    iocs: dict[str, list[str]] = field(default_factory=dict)
    total_count: int = 0
    categories: list[str] = field(default_factory=list)
    primary_type: str = ""
    source_text_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "iocs": self.iocs,
            "total_count": self.total_count,
            "categories": self.categories,
            "primary_type": self.primary_type,
            "source_text_length": self.source_text_length,
        }

    def get_by_category(self, category: str) -> list[str]:
        """Get IOCs by category name."""
        return self.iocs.get(category, [])

    def has_iocs(self) -> bool:
        """Check if any IOCs were found."""
        return self.total_count > 0


class IOCParser:
    """Parse and categorize IOCs from text.

    Wraps argus_engine/intel/ioc_extractor.py with async interface and
    provides additional categorization and enrichment.
    """

    # Category mapping for normalized output
    CATEGORY_MAP: dict[str, str] = {
        "urls": "url",
        "ipv4": "ip_address",
        "ipv6": "ip_address",
        "domains": "domain",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "sha512": "hash",
        "emails": "email",
        "cves": "vulnerability",
        "onion_v2": "onion_address",
        "onion_v3": "onion_address",
        "btc": "cryptocurrency",
        "eth": "cryptocurrency",
        "pgp_keys": "pgp_key",
        "entities": "named_entity",
    }

    def __init__(self, use_ner: bool = True) -> None:
        """Initialize IOC parser.

        Args:
            use_ner: Whether to use spaCy NER for entity enrichment.
        """
        self._use_ner = use_ner
        self._extractor: Any = None

    def _get_extractor(self) -> Any:
        """Lazy-load the IOC extractor."""
        if self._extractor is None:
            try:
                from argus_engine.intel.ioc_extractor import IOCExtractor

                self._extractor = IOCExtractor(use_ner=self._use_ner)
            except ImportError:
                logger.warning("argus_engine.intel.ioc_extractor not available")
                self._extractor = _FallbackExtractor()
        return self._extractor

    async def parse(self, text: str) -> IOCResult:
        """Parse IOCs from text.

        Args:
            text: Raw text to analyze.

        Returns:
            IOCResult with categorized IOCs.
        """
        if not text:
            return IOCResult(source_text_length=0)

        loop = asyncio.get_event_loop()
        extractor = self._get_extractor()

        raw_iocs = await loop.run_in_executor(
            None, extractor.extract, text
        )

        return self._build_result(raw_iocs, len(text))

    async def parse_from_url(self, url: str) -> IOCResult:
        """Fetch a URL and parse IOCs from its content.

        Args:
            url: URL to fetch and analyze.

        Returns:
            IOCResult with categorized IOCs.
        """
        if not url:
            return IOCResult(source_text_length=0)

        loop = asyncio.get_event_loop()
        extractor = self._get_extractor()

        raw_iocs = await loop.run_in_executor(
            None, extractor.extract_from_url, url
        )

        return self._build_result(raw_iocs, len(url))

    async def categorize(self, ioc_value: str) -> str:
        """Categorize a single IOC value.

        Args:
            ioc_value: The IOC string to categorize.

        Returns:
            Category string (e.g., "ip_address", "domain", "hash").
        """
        if not ioc_value:
            return "unknown"

        # Quick regex-based categorization
        import re

        value = ioc_value.strip()

        if re.match(r"^(?:https?|ftp)://", value, re.IGNORECASE):
            if ".onion" in value:
                return "onion_address"
            return "url"
        if re.match(r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$", value):
            return "ip_address"
        if re.match(r"^(?:[0-9A-Fa-f]{1,4}:){2,7}", value):
            return "ip_address"
        if re.match(r"^[A-Fa-f0-9]{32}$", value):
            return "hash"
        if re.match(r"^[A-Fa-f0-9]{40}$", value):
            return "hash"
        if re.match(r"^[A-Fa-f0-9]{64}$", value):
            return "hash"
        if re.match(r"^[A-Fa-f0-9]{128}$", value):
            return "hash"
        if "@" in value and "." in value.split("@")[-1]:
            return "email"
        if re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE):
            return "vulnerability"
        if re.match(r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", value):
            return "cryptocurrency"
        if re.match(r"^0x[a-fA-F0-9]{40}$", value):
            return "cryptocurrency"
        if re.match(r"^[a-z2-7]{16}\.onion$", value):
            return "onion_address"
        if re.match(r"^[a-z2-7]{56}\.onion$", value):
            return "onion_address"
        if re.match(r"^(?:[A-Fa-f0-9]{4}\s){9}[A-Fa-f0-9]{4}$", value):
            return "pgp_key"
        if re.match(r"^[A-Fa-f0-9]{40}$", value):
            return "pgp_key"
        if "." in value and not value.startswith("http"):
            return "domain"

        return "unknown"

    async def bulk_categorize(self, ioc_values: list[str]) -> dict[str, list[str]]:
        """Categorize multiple IOC values.

        Args:
            ioc_values: List of IOC strings.

        Returns:
            Dict mapping category to list of values.
        """
        result: dict[str, list[str]] = {}
        for value in ioc_values:
            category = await self.categorize(value)
            if category not in result:
                result[category] = []
            result[category].append(value)
        return result

    def _build_result(
        self, raw_iocs: dict[str, Any], text_length: int
    ) -> IOCResult:
        """Build IOCResult from raw extraction output."""
        total = 0
        categories: list[str] = []
        primary_type = ""
        max_count = 0

        for key, values in raw_iocs.items():
            if key == "entities":
                # NER entities are structured differently
                if values:
                    total += len(values)
                    categories.append("named_entity")
                continue

            if values:
                count = len(values) if isinstance(values, list) else 0
                total += count
                category = self.CATEGORY_MAP.get(key, key)
                if category not in categories:
                    categories.append(category)
                if count > max_count:
                    max_count = count
                    primary_type = category

        return IOCResult(
            iocs=raw_iocs,
            total_count=total,
            categories=categories,
            primary_type=primary_type,
            source_text_length=text_length,
        )


class _FallbackExtractor:
    """Fallback IOC extractor using regex when argus_engine is not available."""

    import re

    _PATTERNS = {
        "urls": re.compile(r"https?://[^\s<>\"'\)\]\}]+", re.IGNORECASE),
        "ipv4": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        "ipv6": re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"),
        "domains": re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}\b"
        ),
        "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
        "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
        "sha512": re.compile(r"\b[A-Fa-f0-9]{128}\b"),
        "emails": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "cves": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
        "onion_v2": re.compile(r"\b[a-z2-7]{16}\.onion\b"),
        "onion_v3": re.compile(r"\b[a-z2-7]{56}\.onion\b"),
        "btc": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
        "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        "pgp_keys": re.compile(r"(?:[A-Fa-f0-9]{4}\s){9}[A-Fa-f0-9]{4}"),
        "entities": None,  # No NER in fallback
    }

    def extract(self, text: str) -> dict[str, Any]:
        """Extract IOCs using regex patterns."""
        if not text:
            return self._empty_result()

        result: dict[str, Any] = {}
        for key, pattern in self._PATTERNS.items():
            if pattern is None:
                result[key] = []
                continue
            matches = pattern.findall(text)
            # Deduplicate
            seen: set[str] = set()
            unique: list[str] = []
            for m in matches:
                k = m.lower()
                if k not in seen:
                    seen.add(k)
                    unique.append(m)
            result[key] = unique

        return result

    def extract_from_url(self, url: str) -> dict[str, Any]:
        """Fetch URL and extract IOCs (fallback: returns empty)."""
        return self._empty_result()

    @staticmethod
    def _empty_result() -> dict[str, list[Any]]:
        return {
            "urls": [],
            "ipv4": [],
            "ipv6": [],
            "domains": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "sha512": [],
            "emails": [],
            "cves": [],
            "onion_v2": [],
            "onion_v3": [],
            "btc": [],
            "eth": [],
            "pgp_keys": [],
            "entities": [],
        }
