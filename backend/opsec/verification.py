"""Chain-of-Verification — anti-hallucination for LLM outputs.

Implements a verification pipeline to detect and flag potential
hallucinations in LLM-generated content:
    - Cross-reference claims against source material
    - Confidence scoring based on source alignment
    - Entity extraction and verification
    - Citation checking (does the source support the claim?)
    - Structured verification report

Based on the Chain-of-Verification (CoV) methodology:
    "Self-verification reduces hallucination by having the model
    check its own work against source material."
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# Confidence thresholds
_CONFIDENCE_HIGH: Final = 0.8
_CONFIDENCE_MEDIUM: Final = 0.5
_CONFIDENCE_LOW: Final = 0.3

# Patterns that suggest uncertain language
_UNCERTAINTY_PATTERNS: Final = [
    r"\b(?:maybe|perhaps|possibly|might|could|may)\b",
    r"\b(?:I think|I believe|it seems|apparently)\b",
    r"\b(?:not sure|uncertain|unclear|unknown)\b",
    r"\b(?:allegedly|reportedly|supposedly)\b",
]

# Patterns that suggest fabrication risk
_FABRICATION_PATTERNS: Final = [
    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",  # Dates
    r"\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b",  # Large numbers
    r"\b[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+\b",  # Triple names
    r"https?://[^\s]+",  # URLs
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP addresses
]


@dataclass
class VerificationResult:
    """Result of chain-of-verification check.

    Attributes:
        claim: The original claim being verified.
        is_verified: Whether the claim passed verification.
        confidence: Confidence score (0.0-1.0).
        source_alignment: How well the claim aligns with sources (0.0-1.0).
        issues: List of detected issues.
        suggestions: List of suggestions for improvement.
        entities_checked: Number of entities verified.
        entities_total: Total entities found in the claim.
    """

    claim: str = ""
    is_verified: bool = False
    confidence: float = 0.0
    source_alignment: float = 0.0
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    entities_checked: int = 0
    entities_total: int = 0

    def to_dict(self) -> dict:
        return {
            "claim": self.claim[:200],
            "is_verified": self.is_verified,
            "confidence": round(self.confidence, 3),
            "source_alignment": round(self.source_alignment, 3),
            "issues": self.issues,
            "suggestions": self.suggestions,
            "entities_checked": self.entities_checked,
            "entities_total": self.entities_total,
        }


class ChainOfVerification:
    """Anti-hallucination verification for LLM outputs.

    Verifies claims by cross-referencing with source material,
    checking entity consistency, and scoring confidence.

    Usage::

        cov = ChainOfVerification()
        result = await cov.verify(
            claim="The IP address is 192.168.1.1",
            sources=["Source text containing 192.168.1.1"],
        )
    """

    def __init__(
        self,
        min_confidence: float = _CONFIDENCE_MEDIUM,
        strict_mode: bool = False,
    ) -> None:
        """
        Args:
            min_confidence: Minimum confidence to consider verified.
            strict_mode: If True, applies stricter verification rules.
        """
        self._min_confidence = min_confidence
        self._strict_mode = strict_mode

    async def verify(
        self, claim: str, sources: list[str] | None = None
    ) -> VerificationResult:
        """Verify a claim against source material.

        Args:
            claim: The LLM-generated claim to verify.
            sources: List of source texts to cross-reference.

        Returns:
            VerificationResult with verification outcome.
        """
        result = VerificationResult(claim=claim)

        if not claim.strip():
            result.issues.append("Empty claim — nothing to verify")
            return result

        # Step 1: Extract entities from the claim
        entities = self._extract_entities(claim)
        result.entities_total = len(entities)

        # Step 2: Check uncertainty language
        uncertainty_score = self._check_uncertainty(claim)

        # Step 3: Cross-reference with sources
        if sources:
            alignment, matched = self._cross_reference(claim, entities, sources)
            result.source_alignment = alignment
            result.entities_checked = matched
        else:
            # No sources — can only do structural checks
            result.source_alignment = 0.0
            result.suggestions.append(
                "No source material provided for cross-reference"
            )

        # Step 4: Check for fabrication indicators
        fabrication_risk = self._check_fabrication_risk(claim)

        # Step 5: Compute overall confidence
        result.confidence = self._compute_confidence(
            source_alignment=result.source_alignment,
            uncertainty_score=uncertainty_score,
            fabrication_risk=fabrication_risk,
            entities_matched=result.entities_checked,
            entities_total=result.entities_total,
        )

        # Step 6: Determine verification status
        result.is_verified = result.confidence >= self._min_confidence

        # Step 7: Generate suggestions
        if not result.is_verified:
            if result.source_alignment < _CONFIDENCE_MEDIUM:
                result.suggestions.append(
                    "Low source alignment — verify claims against primary sources"
                )
            if fabrication_risk > _CONFIDENCE_MEDIUM:
                result.suggestions.append(
                    "High fabrication risk — fact-check specific claims (dates, numbers, URLs)"
                )
            if uncertainty_score > _CONFIDENCE_MEDIUM:
                result.suggestions.append(
                    "Claim contains uncertain language — consider as tentative"
                )

        return result

    async def verify_batch(
        self, claims: list[str], sources: list[str] | None = None
    ) -> list[VerificationResult]:
        """Verify multiple claims against source material.

        Args:
            claims: List of claims to verify.
            sources: Source texts to cross-reference.

        Returns:
            List of VerificationResult objects.
        """
        results: list[VerificationResult] = []
        for claim in claims:
            result = await self.verify(claim, sources)
            results.append(result)
        return results

    def _extract_entities(self, text: str) -> list[str]:
        """Extract verifiable entities from text.

        Entities include: IPs, URLs, dates, email addresses,
        monetary amounts, and proper nouns.

        Args:
            text: Text to extract entities from.

        Returns:
            List of entity strings.
        """
        entities: list[str] = []

        # IP addresses
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        entities.extend(re.findall(ip_pattern, text))

        # URLs
        url_pattern = r"https?://[^\s]+"
        entities.extend(re.findall(url_pattern, text))

        # Email addresses
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        entities.extend(re.findall(email_pattern, text))

        # Dates (various formats)
        date_pattern = r"\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b"
        entities.extend(re.findall(date_pattern, text))

        # Monetary amounts
        money_pattern = r"\$[\d,]+(?:\.\d{2})?"
        entities.extend(re.findall(money_pattern, text))

        # CVE identifiers
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        entities.extend(re.findall(cve_pattern, text))

        return entities

    def _check_uncertainty(self, text: str) -> float:
        """Check for uncertainty language in text.

        Args:
            text: Text to analyze.

        Returns:
            Uncertainty score (0.0 = certain, 1.0 = very uncertain).
        """
        text_lower = text.lower()
        matches = 0
        for pattern in _UNCERTAINTY_PATTERNS:
            matches += len(re.findall(pattern, text_lower))

        # Normalize: more matches = higher uncertainty
        word_count = max(len(text.split()), 1)
        score = min(1.0, matches / (word_count * 0.1 + 1))
        return score

    def _cross_reference(
        self,
        claim: str,
        entities: list[str],
        sources: list[str],
    ) -> tuple[float, int]:
        """Cross-reference claim entities with source material.

        Args:
            claim: The claim text.
            entities: Extracted entities from the claim.
            sources: Source texts to check against.

        Returns:
            Tuple of (alignment_score, matched_entity_count).
        """
        if not entities or not sources:
            return (0.0, 0)

        combined_sources = " ".join(sources).lower()
        matched = 0

        for entity in entities:
            if entity.lower() in combined_sources:
                matched += 1

        # Also check key phrases from the claim
        claim_words = set(claim.lower().split())
        source_words = set(combined_sources.split())

        if claim_words:
            word_overlap = len(claim_words & source_words) / len(claim_words)
        else:
            word_overlap = 0.0

        # Entity match ratio
        entity_ratio = matched / len(entities) if entities else 0.0

        # Combined alignment (weighted)
        alignment = (entity_ratio * 0.6) + (word_overlap * 0.4)

        return (min(1.0, alignment), matched)

    def _check_fabrication_risk(self, text: str) -> float:
        """Assess the risk of fabrication in the text.

        Higher risk when many specific claims (dates, numbers, URLs)
        are made without source backing.

        Args:
            text: Text to analyze.

        Returns:
            Fabrication risk score (0.0 = low, 1.0 = high).
        """
        risk_indicators = 0
        for pattern in _FABRICATION_PATTERNS:
            matches = re.findall(pattern, text)
            risk_indicators += len(matches)

        # More specific claims = higher risk if unverified
        word_count = max(len(text.split()), 1)
        risk = min(1.0, risk_indicators / (word_count * 0.05 + 1))
        return risk

    def _compute_confidence(
        self,
        source_alignment: float,
        uncertainty_score: float,
        fabrication_risk: float,
        entities_matched: int,
        entities_total: int,
    ) -> float:
        """Compute overall confidence score.

        Args:
            source_alignment: How well the claim aligns with sources.
            uncertainty_score: Level of uncertain language.
            fabrication_risk: Risk of fabrication.
            entities_matched: Number of entities matched in sources.
            entities_total: Total entities in the claim.

        Returns:
            Confidence score (0.0-1.0).
        """
        # Base confidence from source alignment
        confidence = source_alignment * 0.5

        # Entity match bonus
        if entities_total > 0:
            entity_bonus = (entities_matched / entities_total) * 0.3
            confidence += entity_bonus

        # Penalty for uncertainty
        confidence -= uncertainty_score * 0.2

        # Penalty for fabrication risk
        confidence -= fabrication_risk * 0.2

        # Strict mode: additional penalty
        if self._strict_mode:
            confidence -= 0.1

        return max(0.0, min(1.0, confidence))
