"""Enhanced IOC extraction — wraps ARGUS's IOCExtractor with investigation attachment.

Provides async IOC extraction from text and URLs, with automatic
attachment to investigation records in PostgreSQL.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from argus_engine.intel.ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ioc_extract")


class EnhancedIOCExtractor:
    """Async wrapper around ARGUS's IOCExtractor with investigation linking.

    Extracts IOCs from raw text or URLs and optionally attaches them
    to an investigation record in the database.

    Usage::

        extractor = EnhancedIOCExtractor()
        iocs = await extractor.extract_from_text("Check http://evil.com")
        iocs = await extractor.extract_from_url("https://threatfeed.example.com")
        count = await extractor.attach_to_investigation(iocs, investigation_id, db)
    """

    def __init__(self, use_ner: bool = True) -> None:
        """Initialize the extractor.

        Args:
            use_ner: Whether to use spaCy NER for entity extraction.
        """
        self._use_ner = use_ner
        self._extractor: IOCExtractor | None = None

    async def extract_from_text(self, text: str) -> dict[str, list[str]]:
        """Extract IOCs from raw text asynchronously.

        Args:
            text: Raw text to analyze.

        Returns:
            Dictionary mapping IOC type to list of unique values.
        """
        loop = asyncio.get_running_loop()

        def _extract() -> dict[str, list[str]]:
            self._extractor = IOCExtractor(use_ner=self._use_ner)
            return self._extractor.extract(text)

        logger.info("Starting IOC extraction from text (length=%d)", len(text))
        result = await loop.run_in_executor(_executor, _extract)
        total = sum(len(v) for v in result.values() if isinstance(v, list))
        logger.info("IOC extraction complete: %d indicators found", total)
        return result

    async def extract_from_url(self, url: str) -> dict[str, list[str]]:
        """Fetch a URL and extract IOCs from its content.

        Args:
            url: URL to fetch and analyze.

        Returns:
            Dictionary mapping IOC type to list of unique values.
        """
        loop = asyncio.get_running_loop()

        def _extract() -> dict[str, list[str]]:
            self._extractor = IOCExtractor(use_ner=self._use_ner)
            return self._extractor.extract_from_url(url)

        logger.info("Starting IOC extraction from URL: %s", url)
        result = await loop.run_in_executor(_executor, _extract)
        total = sum(len(v) for v in result.values() if isinstance(v, list))
        logger.info("URL IOC extraction complete: %d indicators found", total)
        return result

    async def attach_to_investigation(
        self,
        iocs: dict[str, list[str]],
        investigation_id: str,
        db: Any,
    ) -> int:
        """Attach extracted IOCs to an investigation record.

        Creates IOC database entries for each extracted indicator,
        linked to the specified investigation.

        Args:
            iocs: IOC dictionary from extract_from_text/extract_from_url.
            investigation_id: Target investigation UUID.
            db: Async SQLAlchemy session.

        Returns:
            Total number of IOC records created.
        """
        from backend.db.models import IOC

        # Map IOC extractor keys to database type values
        type_mapping = {
            "urls": "url",
            "ipv4": "ip",
            "ipv6": "ip",
            "domains": "domain",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "sha512": "hash",
            "emails": "email",
            "cves": "cve",
            "onion_v2": "onion",
            "onion_v3": "onion",
            "btc": "bitcoin_address",
            "eth": "ethereum_address",
            "pgp_keys": "pgp_key",
        }

        created_count = 0
        seen_values: set[str] = set()

        for ioc_key, values in iocs.items():
            if ioc_key == "entities":
                # Skip NER entities — they don't map to atomic IOCs
                continue
            if not isinstance(values, list):
                continue

            ioc_type = type_mapping.get(ioc_key, ioc_key)
            for value in values:
                if not value or value in seen_values:
                    continue
                seen_values.add(value)

                ioc = IOC(
                    investigation_id=investigation_id,
                    type=ioc_type,
                    value=value,
                    threat_type=ioc_key,
                    severity=self._infer_severity(ioc_key, value),
                    source="enhanced_extraction",
                )
                db.add(ioc)
                created_count += 1

        if created_count > 0:
            await db.flush()
        logger.info(
            "Attached %d IOCs to investigation %s",
            created_count,
            investigation_id,
        )
        return created_count

    @staticmethod
    def _infer_severity(ioc_type: str, value: str) -> str:
        """Infer severity based on IOC type and value."""
        if ioc_type in ("cves",):
            return "high"
        if ioc_type in ("onion_v2", "onion_v3"):
            return "medium"
        if ioc_type in ("btc", "eth"):
            return "medium"
        if ioc_type in ("ipv4", "ipv6"):
            # Private IPs are lower severity
            if value.startswith(("10.", "192.168.", "172.16.", "127.")):
                return "low"
        return "medium"

    @staticmethod
    def get_summary(iocs: dict[str, list[str]]) -> dict[str, Any]:
        """Generate a summary of extracted IOCs.

        Args:
            iocs: IOC dictionary from extraction.

        Returns:
            Summary dict with counts per type and total.
        """
        summary: dict[str, Any] = {"total": 0, "by_type": {}}
        for key, values in iocs.items():
            if isinstance(values, list):
                count = len(values)
                summary["by_type"][key] = count
                summary["total"] += count
        return summary

    @staticmethod
    def shutdown() -> None:
        """Shutdown the thread pool executor."""
        _executor.shutdown(wait=False)
