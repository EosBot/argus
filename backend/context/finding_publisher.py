"""Finding publisher — publishes findings and triggers correlation.

Bridges the gap between finding creation and downstream processing:
publishes findings to Redis pub/sub for real-time consumers and
triggers the correlation engine to cross-reference with existing data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.context.pubsub import RedisPubSub, PubSubChannel, redis_pubsub

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Finding:
    """A finding to be published.

    Attributes:
        id: Unique finding identifier (UUID hex).
        investigation_id: Associated investigation.
        title: Short title.
        description: Detailed description.
        severity: Severity level (info, low, medium, high, critical).
        confidence: Confidence level (low, medium, high).
        source: Source agent or tool name.
        data: Additional structured data.
        created_at: ISO 8601 creation timestamp.
    """

    id: str
    investigation_id: str
    title: str
    description: str = ""
    severity: str = "info"
    confidence: str = "medium"
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "data": self.data,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class PublishResult:
    """Result of publishing a finding.

    Attributes:
        finding_id: The finding that was published.
        published: Whether the Redis publish succeeded.
        correlation_triggered: Whether correlation was triggered.
        correlation_report: Correlation report dict (if triggered).
        errors: List of error messages encountered.
    """

    finding_id: str
    published: bool = False
    correlation_triggered: bool = False
    correlation_report: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)


class FindingPublisher:
    """Publishes findings to Redis and triggers correlation.

    Coordinates the flow: when a new finding is created, it is
    published to the ``findings.new`` channel and the correlation
    engine is invoked to cross-reference with existing findings.

    Usage::

        publisher = FindingPublisher()
        finding = Finding(id="...", investigation_id="...", title="...")
        result = await publisher.publish(finding)
    """

    def __init__(
        self,
        pubsub: RedisPubSub | None = None,
        trigger_correlation: bool = True,
    ) -> None:
        self._pubsub = pubsub or redis_pubsub
        self._trigger_correlation = trigger_correlation

    async def publish(
        self,
        finding: Finding,
        *,
        extra_data: dict[str, Any] | None = None,
    ) -> PublishResult:
        """Publish a finding and optionally trigger correlation.

        Args:
            finding: The finding to publish.
            extra_data: Additional data merged into the finding payload.

        Returns:
            PublishResult with status details.
        """
        errors: list[str] = []

        # Merge extra data
        data = {**finding.data, **(extra_data or {})}

        # Publish to Redis
        published = False
        try:
            published = await self._pubsub.publish_finding(
                finding_id=finding.id,
                investigation_id=finding.investigation_id,
                title=finding.title,
                severity=finding.severity,
                source=finding.source,
                data=data,
            )
        except Exception as exc:
            msg = f"Failed to publish finding {finding.id}: {exc}"
            logger.warning(msg)
            errors.append(msg)

        # Trigger correlation
        correlation_report = None
        correlation_triggered = False

        if self._trigger_correlation:
            try:
                correlation_report, corr_errors = await self._run_correlation(
                    finding, data
                )
                correlation_triggered = True
                errors.extend(corr_errors)
            except Exception as exc:
                msg = f"Correlation failed for finding {finding.id}: {exc}"
                logger.warning(msg)
                errors.append(msg)

        return PublishResult(
            finding_id=finding.id,
            published=published,
            correlation_triggered=correlation_triggered,
            correlation_report=correlation_report,
            errors=errors,
        )

    async def publish_batch(
        self,
        findings: list[Finding],
        *,
        extra_data: dict[str, Any] | None = None,
    ) -> list[PublishResult]:
        """Publish multiple findings sequentially.

        Args:
            findings: List of findings to publish.
            extra_data: Additional data merged into each finding.

        Returns:
            List of PublishResult, one per finding.
        """
        results: list[PublishResult] = []
        for finding in findings:
            result = await self.publish(finding, extra_data=extra_data)
            results.append(result)
        return results

    async def _run_correlation(
        self,
        finding: Finding,
        data: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        """Run correlation engine for a new finding.

        Builds a minimal agent_results dict from the finding and
        invokes the correlation engine.

        Returns:
            Tuple of (report_dict_or_None, errors).
        """
        errors: list[str] = []

        try:
            from backend.orchestrator.correlation import CorrelationEngine
        except ImportError as exc:
            return None, [f"Correlation engine import failed: {exc}"]

        try:
            engine = CorrelationEngine()

            # Build agent_results from the finding
            agent_results: dict[str, dict[str, Any]] = {
                finding.source or "unknown": {
                    "iocs": data.get("iocs", {}),
                    "entities": data.get("entities", []),
                    "geolocation": data.get("geolocation", []),
                    "attribution": data.get("attribution", {}),
                    "finding_id": finding.id,
                }
            }

            report = await engine.correlate_all(
                finding.investigation_id, agent_results
            )

            # Publish correlation alerts if any found
            if report.correlations:
                for corr in report.correlations:
                    try:
                        await self._pubsub.publish_correlation_alert(
                            investigation_id=finding.investigation_id,
                            correlation_type=corr.correlation_type,
                            description=corr.description,
                            confidence=corr.confidence,
                            entities=corr.entities,
                        )
                    except Exception as exc:
                        errors.append(f"Failed to publish alert: {exc}")

            return report.to_dict(), errors

        except Exception as exc:
            errors.append(f"Correlation engine error: {exc}")
            return None, errors


# Singleton instance
finding_publisher = FindingPublisher()
