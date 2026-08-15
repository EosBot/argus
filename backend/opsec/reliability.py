"""Source reliability scoring — F6 NATO reporting standard.

Implements the NATO intelligence reporting standard for evaluating
source reliability and information credibility:

    Source Reliability (A-F):
        A - Completely reliable
        B - Usually reliable
        C - Fairly reliable
        D - Not usually reliable
        E - Unreliable
        F - Reliability cannot be judged

    Information Credibility (1-6):
        1 - Confirmed by other sources
        2 - Probably true
        3 - Possibly true
        4 - Doubtful
        5 - Improbable
        6 - Truth cannot be judged

The combined rating (e.g., "B2" = Probably true from a usually reliable
source) provides a standardized confidence assessment for intelligence
reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)


# Source reliability scale (A-F)
RELIABILITY_SCALE: Final = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged",
}

# Information credibility scale (1-6)
CREDIBILITY_SCALE: Final = {
    "1": "Confirmed by other sources",
    "2": "Probably true",
    "3": "Possibly true",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Truth cannot be judged",
}

# Combined rating confidence mapping (approximate)
RATING_CONFIDENCE: Final = {
    "A1": 0.95, "A2": 0.85, "A3": 0.70, "A4": 0.50, "A5": 0.30, "A6": 0.50,
    "B1": 0.90, "B2": 0.80, "B3": 0.65, "B4": 0.45, "B5": 0.25, "B6": 0.45,
    "C1": 0.80, "C2": 0.70, "C3": 0.55, "C4": 0.40, "C5": 0.20, "C6": 0.40,
    "D1": 0.65, "D2": 0.55, "D3": 0.45, "D4": 0.30, "D5": 0.15, "D6": 0.30,
    "E1": 0.50, "E2": 0.40, "E3": 0.30, "E4": 0.20, "E5": 0.10, "E6": 0.20,
    "F1": 0.50, "F2": 0.45, "F3": 0.40, "F4": 0.30, "F5": 0.20, "F6": 0.25,
}


@dataclass
class ReliabilityScore:
    """A NATO F6 reliability score for a source or piece of information.

    Attributes:
        reliability: Source reliability grade (A-F).
        credibility: Information credibility grade (1-6).
        combined_rating: Combined rating string (e.g., "B2").
        confidence: Numeric confidence score (0.0-1.0).
        source_name: Name or identifier of the source.
        assessment_reason: Reasoning for this assessment.
        caveats: Any caveats or conditions on this rating.
    """

    reliability: str = "F"
    credibility: str = "6"
    combined_rating: str = "F6"
    confidence: float = 0.25
    source_name: str = ""
    assessment_reason: str = ""
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "reliability": self.reliability,
            "credibility": self.credibility,
            "combined_rating": self.combined_rating,
            "confidence": self.confidence,
            "reliability_description": RELIABILITY_SCALE.get(self.reliability, "Unknown"),
            "credibility_description": CREDIBILITY_SCALE.get(self.credibility, "Unknown"),
            "source_name": self.source_name,
            "assessment_reason": self.assessment_reason,
            "caveats": self.caveats,
        }


class SourceReliability:
    """F6 NATO source reliability scoring system.

    Evaluates sources and information using the NATO standard
    A-F reliability and 1-6 credibility scales.

    Usage::

        scorer = SourceReliability()
        score = scorer.score_source(
            reliability="B",
            credibility="2",
            source_name="OSINT Feed Alpha",
        )
        print(score.combined_rating)  # "B2"
        print(score.confidence)      # 0.8
    """

    def __init__(self) -> None:
        """Initialize the source reliability scorer."""
        self._source_history: dict[str, list[ReliabilityScore]] = {}

    def score_source(
        self,
        reliability: str,
        credibility: str,
        source_name: str = "",
        assessment_reason: str = "",
        caveats: list[str] | None = None,
    ) -> ReliabilityScore:
        """Score a source using F6 NATO standard.

        Args:
            reliability: Source reliability grade (A-F).
            credibility: Information credibility grade (1-6).
            source_name: Name or identifier of the source.
            assessment_reason: Reasoning for this assessment.
            caveats: Any caveats on this rating.

        Returns:
            ReliabilityScore with combined rating and confidence.

        Raises:
            ValueError: If reliability or credibility grades are invalid.
        """
        # Normalize inputs
        rel = reliability.upper().strip()
        cred = credibility.strip()

        # Validate
        if rel not in RELIABILITY_SCALE:
            raise ValueError(
                f"Invalid reliability grade '{reliability}'. "
                f"Must be one of: {', '.join(RELIABILITY_SCALE.keys())}"
            )
        if cred not in CREDIBILITY_SCALE:
            raise ValueError(
                f"Invalid credibility grade '{credibility}'. "
                f"Must be one of: {', '.join(CREDIBILITY_SCALE.keys())}"
            )

        combined = f"{rel}{cred}"
        confidence = RATING_CONFIDENCE.get(combined, 0.25)

        score = ReliabilityScore(
            reliability=rel,
            credibility=cred,
            combined_rating=combined,
            confidence=confidence,
            source_name=source_name,
            assessment_reason=assessment_reason,
            caveats=caveats or [],
        )

        # Track history
        if source_name:
            if source_name not in self._source_history:
                self._source_history[source_name] = []
            self._source_history[source_name].append(score)

        return score

    def score_from_indicators(
        self,
        source_name: str = "",
        past_accuracy: float = 0.5,
        corroboration_count: int = 0,
        source_type: str = "unknown",
        direct_knowledge: bool = False,
        bias_risk: float = 0.5,
    ) -> ReliabilityScore:
        """Derive a reliability score from observable indicators.

        This method infers the F6 rating from measurable factors:
            - Past accuracy of the source
            - Number of corroborating sources
            - Whether the source has direct knowledge
            - Risk of bias or deception

        Args:
            source_name: Name of the source.
            past_accuracy: Historical accuracy (0.0-1.0).
            corroboration_count: Number of independent corroborating sources.
            source_type: Type of source (e.g., "human", "technical", "document").
            direct_knowledge: Whether the source has direct observation.
            bias_risk: Risk of bias/deception (0.0 = none, 1.0 = high).

        Returns:
            ReliabilityScore derived from indicators.
        """
        # Determine reliability grade (A-F) from past accuracy and source type
        reliability = self._infer_reliability(
            past_accuracy, source_type, direct_knowledge, bias_risk
        )

        # Determine credibility grade (1-6) from corroboration
        credibility = self._infer_credibility(
            corroboration_count, past_accuracy, bias_risk
        )

        # Build assessment reason
        reason_parts = [
            f"Past accuracy: {past_accuracy:.0%}",
            f"Corroborating sources: {corroboration_count}",
            f"Source type: {source_type}",
        ]
        if direct_knowledge:
            reason_parts.append("Direct knowledge: yes")
        if bias_risk > 0.5:
            reason_parts.append(f"High bias risk: {bias_risk:.0%}")

        caveats: list[str] = []
        if bias_risk > 0.7:
            caveats.append("High bias risk — treat with caution")
        if corroboration_count == 0:
            caveats.append("No independent corroboration")
        if not direct_knowledge and past_accuracy < 0.5:
            caveats.append("Indirect knowledge with low historical accuracy")

        return self.score_source(
            reliability=reliability,
            credibility=credibility,
            source_name=source_name,
            assessment_reason="; ".join(reason_parts),
            caveats=caveats,
        )

    def _infer_reliability(
        self,
        past_accuracy: float,
        source_type: str,
        direct_knowledge: bool,
        bias_risk: float,
    ) -> str:
        """Infer reliability grade from indicators.

        Args:
            past_accuracy: Historical accuracy (0.0-1.0).
            source_type: Type of source.
            direct_knowledge: Whether source has direct observation.
            bias_risk: Risk of bias (0.0-1.0).

        Returns:
            Reliability grade (A-F).
        """
        # Base score from accuracy
        score = past_accuracy

        # Adjustments
        if direct_knowledge:
            score += 0.1
        if source_type == "technical":
            score += 0.05  # Technical sources tend more reliable
        elif source_type == "human":
            score -= 0.05  # Human sources more fallible
        elif source_type == "social_media":
            score -= 0.15

        # Bias penalty
        score -= bias_risk * 0.2

        # Clamp
        score = max(0.0, min(1.0, score))

        # Map to A-F
        if score >= 0.9:
            return "A"
        elif score >= 0.75:
            return "B"
        elif score >= 0.6:
            return "C"
        elif score >= 0.4:
            return "D"
        elif score >= 0.2:
            return "E"
        else:
            return "F"

    def _infer_credibility(
        self,
        corroboration_count: int,
        past_accuracy: float,
        bias_risk: float,
    ) -> str:
        """Infer credibility grade from indicators.

        Args:
            corroboration_count: Number of corroborating sources.
            past_accuracy: Historical accuracy.
            bias_risk: Risk of bias.

        Returns:
            Credibility grade (1-6).
        """
        # More corroboration = higher credibility (lower number)
        if corroboration_count >= 3 and past_accuracy > 0.8:
            return "1"  # Confirmed
        elif corroboration_count >= 2 or past_accuracy > 0.7:
            return "2"  # Probably true
        elif corroboration_count >= 1 or past_accuracy > 0.5:
            return "3"  # Possibly true
        elif past_accuracy > 0.3:
            return "4"  # Doubtful
        elif past_accuracy > 0.1:
            return "5"  # Improbable
        else:
            return "6"  # Cannot be judged

    def get_source_history(
        self, source_name: str
    ) -> list[ReliabilityScore]:
        """Get the scoring history for a source.

        Args:
            source_name: Name of the source.

        Returns:
            List of past ReliabilityScore objects for this source.
        """
        return self._source_history.get(source_name, [])

    def get_average_confidence(self, source_name: str) -> float:
        """Get the average confidence for a source across all assessments.

        Args:
            source_name: Name of the source.

        Returns:
            Average confidence score (0.0-1.0), or 0.0 if no history.
        """
        history = self._source_history.get(source_name, [])
        if not history:
            return 0.0
        return sum(s.confidence for s in history) / len(history)

    @staticmethod
    def validate_rating(rating: str) -> bool:
        """Validate a combined rating string.

        Args:
            rating: Combined rating (e.g., "B2", "A1").

        Returns:
            True if the rating is valid.
        """
        if len(rating) != 2:
            return False
        rel, cred = rating[0].upper(), rating[1]
        return rel in RELIABILITY_SCALE and cred in CREDIBILITY_SCALE

    @staticmethod
    def describe_rating(rating: str) -> str:
        """Get a human-readable description of a combined rating.

        Args:
            rating: Combined rating (e.g., "B2").

        Returns:
            Human-readable description.
        """
        if len(rating) != 2:
            return "Invalid rating"
        rel, cred = rating[0].upper(), rating[1]
        rel_desc = RELIABILITY_SCALE.get(rel, "Unknown")
        cred_desc = CREDIBILITY_SCALE.get(cred, "Unknown")
        return f"{rel_desc} source, {cred_desc}"
