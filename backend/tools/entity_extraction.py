"""EntityExtraction — regex + NER pipeline for entity extraction.

Extracts common entities from text using regex patterns and optional
spaCy NER enrichment with a bounded regex fallback.

Usage::

    from backend.tools.entity_extraction import EntityExtraction

    extractor = EntityExtraction()
    entities = await extractor.extract("Contact admin@evil.com at 1.2.3.4")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExtractedEntity:
    """A single extracted entity.

    Attributes:
        text: The extracted text value.
        label: Entity type label (e.g., "EMAIL", "IPv4", "PERSON").
        start: Start position in source text.
        end: End position in source text.
        confidence: Extraction confidence 0.0-1.0.
        source: Extraction source ("regex" or "ner").
    """

    text: str
    label: str
    start: int = 0
    end: int = 0
    confidence: float = 1.0
    source: str = "regex"

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "source": self.source,
        }


# Compiled regex patterns for common entities
_PATTERNS: dict[str, re.Pattern[str]] = {
    "IPv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "IPv6": re.compile(
        r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|"
        r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
        r"\b::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "URL": re.compile(
        r"https?://[^\s<>\"'\)\]\}]+"
    ),
    "DOMAIN": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}\b"
    ),
    "MD5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    "SHA1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    "SHA256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "SHA512": re.compile(r"\b[A-Fa-f0-9]{128}\b"),
    "CVE": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "BTC_WALLET": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "ETH_WALLET": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "ONION_V2": re.compile(r"\b[a-z2-7]{16}\.onion\b"),
    "ONION_V3": re.compile(r"\b[a-z2-7]{56}\.onion\b"),
    "PGP_FINGERPRINT": re.compile(r"(?:[A-Fa-f0-9]{4}\s){9}[A-Fa-f0-9]{4}"),
    "MAC_ADDRESS": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "PHONE_NUMBER": re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
    ),
    "DATE": re.compile(
        r"\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b"
    ),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[\s-]?(?:[A-Z0-9]{4}[\s-]?){3,7}[A-Z0-9]{1,4}\b"),
    "USER_HANDLE": re.compile(r"@[A-Za-z0-9_]{3,30}\b"),
    "HASHTAG": re.compile(r"#[A-Za-z][A-Za-z0-9_]{2,50}\b"),
}


class EntityExtraction:
    """Extract entities from text using regex patterns and optional NER.

    Provides a unified interface for entity extraction with:
    - Regex-based extraction for structured data (IPs, emails, hashes, etc.)
    - Optional spaCy NER for unstructured entity extraction
    - Deduplication and confidence scoring
    """

    def __init__(self, use_ner: bool = True) -> None:
        """Initialize entity extractor.

        Args:
            use_ner: Whether to use spaCy NER for entity extraction.
        """
        self._use_ner = use_ner
        self._nlp: Any = None

        if use_ner:
            self._load_spacy()

    def _load_spacy(self) -> None:
        """Load spaCy model for NER."""
        try:
            import spacy

            try:
                self._nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.debug("spaCy model 'en_core_web_sm' not found — NER disabled")
                self._use_ner = False
        except ImportError:
            logger.debug("spaCy not installed — NER disabled")
            self._use_ner = False

    async def extract(self, text: str) -> list[ExtractedEntity]:
        """Extract all entities from text.

        Args:
            text: Input text to analyze.

        Returns:
            List of extracted entities.
        """
        if not text:
            return []

        entities = self._extract_regex(text)

        if self._use_ner and self._nlp is not None:
            ner_entities = await self._extract_ner(text)
            entities.extend(ner_entities)

        # Deduplicate overlapping entities
        return self._deduplicate(entities)

    def extract_by_type(self, text: str, label: str) -> list[ExtractedEntity]:
        """Extract entities of a specific type.

        Args:
            text: Input text.
            label: Entity type label (e.g., "IPv4", "EMAIL").

        Returns:
            List of matching entities.
        """
        if not text or label not in _PATTERNS:
            return []

        pattern = _PATTERNS[label]
        return [
            ExtractedEntity(
                text=match.group(),
                label=label,
                start=match.start(),
                end=match.end(),
                confidence=0.95,
                source="regex",
            )
            for match in pattern.finditer(text)
        ]

    def extract_as_dict(self, text: str) -> dict[str, list[str]]:
        """Extract entities grouped by type.

        Args:
            text: Input text.

        Returns:
            Dict mapping entity type to list of unique values.
        """
        if not text:
            return {}

        result: dict[str, list[str]] = {}
        for label, pattern in _PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                # Deduplicate while preserving order
                seen: set[str] = set()
                unique: list[str] = []
                for m in matches:
                    key = m.lower()
                    if key not in seen:
                        seen.add(key)
                        unique.append(m)
                result[label] = unique

        return result

    def _extract_regex(self, text: str) -> list[ExtractedEntity]:
        """Extract entities using regex patterns."""
        entities: list[ExtractedEntity] = []

        for label, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                entities.append(ExtractedEntity(
                    text=match.group(),
                    label=label,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95,
                    source="regex",
                ))

        return entities

    async def _extract_ner(self, text: str) -> list[ExtractedEntity]:
        """Extract named entities using spaCy NER."""
        if not self._use_ner or self._nlp is None:
            import asyncio
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: [])

        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._extract_ner_sync, text)

    def _extract_ner_sync(self, text: str) -> list[ExtractedEntity]:
        """Synchronous NER extraction (runs in executor)."""
        if self._nlp is None:
            return []

        try:
            # Limit text length for performance
            doc = self._nlp(text[:100_000])
            entities: list[ExtractedEntity] = []
            seen: set[tuple[str, str]] = set()

            for ent in doc.ents:
                if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "NORP", "FAC", "PRODUCT"):
                    key = (ent.text.lower(), ent.label_)
                    if key not in seen:
                        seen.add(key)
                        entities.append(ExtractedEntity(
                            text=ent.text,
                            label=ent.label_,
                            start=ent.start_char,
                            end=ent.end_char,
                            confidence=0.8,
                            source="ner",
                        ))
            return entities
        except Exception as exc:
            logger.debug("NER extraction failed: %s", exc)
            return []

    @staticmethod
    def _deduplicate(entities: list[ExtractedEntity]) -> list[ExtractedEntity]:
        """Remove overlapping entities, preferring higher confidence."""
        if not entities:
            return []

        # Sort by start position, then by confidence descending
        sorted_entities = sorted(
            entities, key=lambda e: (e.start, -e.confidence)
        )

        result: list[ExtractedEntity] = []
        last_end = -1

        for entity in sorted_entities:
            if entity.start >= last_end:
                result.append(entity)
                last_end = entity.end
            # If overlapping, skip (the higher confidence one is already added)

        return result
