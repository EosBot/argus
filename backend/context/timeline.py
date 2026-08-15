"""Timeline reconstruction from findings and evidence.

Reconstructs chronological event sequences from findings, evidence
entries, and correlation results. Supports filtering, grouping,
and export to various timeline formats.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """A single event on the investigation timeline.

    Attributes:
        id: Unique event identifier.
        timestamp: ISO 8601 event timestamp (UTC).
        event_type: Type of event (finding, evidence, correlation, ...).
        title: Short title.
        description: Detailed description.
        source: Source agent, tool, or module.
        severity: Severity level (info, low, medium, high, critical).
        investigation_id: Associated investigation.
        metadata: Additional structured data.
    """

    id: str
    timestamp: str
    event_type: str
    title: str
    description: str = ""
    source: str = ""
    severity: str = "info"
    investigation_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "severity": self.severity,
            "investigation_id": self.investigation_id,
            "metadata": self.metadata,
        }


class Timeline:
    """Reconstructs chronological event sequences.

    Collects events from findings, evidence, and correlation results,
    then orders them chronologically. Supports filtering by type,
    severity, source, and time range.

    Usage::

        timeline = Timeline()
        timeline.add_from_finding(finding_dict)
        timeline.add_from_evidence(evidence_dict)
        events = timeline.reconstruct()
    """

    # Severity ordering for sorting/filtering.
    SEVERITY_ORDER: dict[str, int] = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    @property
    def length(self) -> int:
        return len(self._events)

    # -- Event addition --------------------------------------------------------

    def add_event(
        self,
        event_id: str,
        timestamp: str,
        event_type: str,
        title: str,
        *,
        description: str = "",
        source: str = "",
        severity: str = "info",
        investigation_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TimelineEvent:
        """Add a single event to the timeline.

        Args:
            event_id: Unique event identifier.
            timestamp: ISO 8601 timestamp.
            event_type: Event type (finding, evidence, correlation, ...).
            title: Short title.
            description: Detailed description.
            source: Source agent or tool.
            severity: Severity level.
            investigation_id: Associated investigation.
            metadata: Additional data.

        Returns:
            The created TimelineEvent.
        """
        event = TimelineEvent(
            id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            title=title,
            description=description,
            source=source,
            severity=severity,
            investigation_id=investigation_id,
            metadata=metadata or {},
        )
        self._events.append(event)
        return event

    def add_from_finding(self, finding: dict[str, Any]) -> TimelineEvent:
        """Add an event from a finding dict.

        Expects keys: id, created_at, title, severity, source, etc.
        """
        return self.add_event(
            event_id=finding.get("id", ""),
            timestamp=finding.get("created_at", datetime.now(timezone.utc).isoformat()),
            event_type="finding",
            title=finding.get("title", "Untitled Finding"),
            description=finding.get("description", ""),
            source=finding.get("source", ""),
            severity=finding.get("severity", "info"),
            investigation_id=finding.get("investigation_id", ""),
            metadata={
                k: v
                for k, v in finding.items()
                if k
                not in (
                    "id",
                    "created_at",
                    "title",
                    "description",
                    "source",
                    "severity",
                    "investigation_id",
                )
            },
        )

    def add_from_evidence(self, evidence: dict[str, Any]) -> TimelineEvent:
        """Add an event from an evidence dict.

        Expects keys: id, created_at, type, source_url, etc.
        """
        return self.add_event(
            event_id=evidence.get("id", ""),
            timestamp=evidence.get("created_at", datetime.now(timezone.utc).isoformat()),
            event_type="evidence",
            title=f"Evidence: {evidence.get('type', 'unknown')}",
            description=evidence.get("source_url", ""),
            source="evidence_collector",
            severity="info",
            investigation_id=evidence.get("investigation_id", ""),
            metadata={
                k: v
                for k, v in evidence.items()
                if k
                not in (
                    "id",
                    "created_at",
                    "type",
                    "source_url",
                    "investigation_id",
                )
            },
        )

    def add_from_correlation(self, correlation: dict[str, Any]) -> TimelineEvent:
        """Add an event from a correlation finding dict.

        Expects keys: correlation_type, description, confidence, etc.
        """
        return self.add_event(
            event_id=correlation.get("id", ""),
            timestamp=correlation.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            ),
            event_type="correlation",
            title=f"Correlation: {correlation.get('correlation_type', 'unknown')}",
            description=correlation.get("description", ""),
            source=", ".join(correlation.get("source_agents", [])),
            severity="medium",
            investigation_id=correlation.get("investigation_id", ""),
            metadata={
                "confidence": correlation.get("confidence", 0.5),
                "entities": correlation.get("entities", []),
                "correlation_type": correlation.get("correlation_type", ""),
            },
        )

    def add_from_chain_entry(self, entry: dict[str, Any]) -> TimelineEvent:
        """Add an event from an evidence chain entry dict."""
        return self.add_event(
            event_id=entry.get("entry_id", ""),
            timestamp=entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event_type=f"chain:{entry.get('event_type', 'unknown')}",
            title=f"Chain: {entry.get('event_type', 'unknown')}",
            description="",
            source="evidence_chain",
            severity="info",
            investigation_id=entry.get("investigation_id", ""),
            metadata={
                "sequence": entry.get("sequence", 0),
                "data_hash": entry.get("data_hash", ""),
                "previous_hash": entry.get("previous_hash", ""),
                "entry_hash": entry.get("entry_hash", ""),
            },
        )

    def add_bulk_findings(self, findings: list[dict[str, Any]]) -> None:
        """Add multiple findings at once."""
        for finding in findings:
            self.add_from_finding(finding)

    def add_bulk_evidence(self, evidence_list: list[dict[str, Any]]) -> None:
        """Add multiple evidence entries at once."""
        for evidence in evidence_list:
            self.add_from_evidence(evidence)

    def add_bulk_correlations(self, correlations: list[dict[str, Any]]) -> None:
        """Add multiple correlations at once."""
        for correlation in correlations:
            self.add_from_correlation(correlation)

    # -- Reconstruction ---------------------------------------------------------

    def reconstruct(
        self,
        *,
        event_type: str | None = None,
        min_severity: str | None = None,
        source: str | None = None,
        investigation_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        reverse: bool = False,
    ) -> list[TimelineEvent]:
        """Reconstruct the chronological event sequence.

        Filters and sorts events by timestamp. Returns events in
        chronological order (oldest first) unless ``reverse`` is True.

        Args:
            event_type: Filter by event type (e.g. "finding").
            min_severity: Minimum severity level (inclusive).
            source: Filter by source agent/tool.
            investigation_id: Filter by investigation.
            start_time: ISO 8601 start of time range (inclusive).
            end_time: ISO 8601 end of time range (inclusive).
            reverse: If True, return newest first.

        Returns:
            Filtered, sorted list of TimelineEvent.
        """
        filtered = self._filter_events(
            event_type=event_type,
            min_severity=min_severity,
            source=source,
            investigation_id=investigation_id,
            start_time=start_time,
            end_time=end_time,
        )

        # Sort by timestamp
        sorted_events = sorted(filtered, key=lambda e: e.timestamp, reverse=reverse)

        return sorted_events

    def _filter_events(
        self,
        *,
        event_type: str | None = None,
        min_severity: str | None = None,
        source: str | None = None,
        investigation_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Apply filters to the event list."""
        min_sev_level = self.SEVERITY_ORDER.get(min_severity, 0) if min_severity else None

        filtered: list[TimelineEvent] = []
        for event in self._events:
            if event_type and event.event_type != event_type:
                continue
            if min_sev_level is not None:
                event_level = self.SEVERITY_ORDER.get(event.severity, 0)
                if event_level < min_sev_level:
                    continue
            if source and event.source != source:
                continue
            if investigation_id and event.investigation_id != investigation_id:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            filtered.append(event)

        return filtered

    # -- Analysis ---------------------------------------------------------------

    def get_time_range(self) -> tuple[str, str] | None:
        """Get the time range of all events.

        Returns:
            Tuple of (earliest_timestamp, latest_timestamp), or None if empty.
        """
        if not self._events:
            return None
        timestamps = [e.timestamp for e in self._events]
        return min(timestamps), max(timestamps)

    def get_event_counts_by_type(self) -> dict[str, int]:
        """Count events by type.

        Returns:
            Dict mapping event type to count.
        """
        counts: dict[str, int] = {}
        for event in self._events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        return counts

    def get_event_counts_by_severity(self) -> dict[str, int]:
        """Count events by severity.

        Returns:
            Dict mapping severity to count.
        """
        counts: dict[str, int] = {}
        for event in self._events:
            counts[event.severity] = counts.get(event.severity, 0) + 1
        return counts

    def get_sources(self) -> list[str]:
        """Get unique list of sources."""
        return sorted({e.source for e in self._events if e.source})

    def find_gaps(
        self,
        min_gap_seconds: float = 3600.0,
    ) -> list[tuple[TimelineEvent, TimelineEvent, float]]:
        """Find temporal gaps between consecutive events.

        Args:
            min_gap_seconds: Minimum gap size to report (default 1 hour).

        Returns:
            List of (earlier_event, later_event, gap_seconds) tuples.
        """
        if len(self._events) < 2:
            return []

        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        gaps: list[tuple[TimelineEvent, TimelineEvent, float]] = []

        for i in range(len(sorted_events) - 1):
            t1 = self._parse_timestamp(sorted_events[i].timestamp)
            t2 = self._parse_timestamp(sorted_events[i + 1].timestamp)
            if t1 is None or t2 is None:
                continue
            gap = (t2 - t1).total_seconds()
            if gap >= min_gap_seconds:
                gaps.append((sorted_events[i], sorted_events[i + 1], gap))

        return gaps

    def find_clusters(
        self,
        max_gap_seconds: float = 300.0,
    ) -> list[list[TimelineEvent]]:
        """Cluster events that are close together in time.

        Args:
            max_gap_seconds: Maximum gap within a cluster (default 5 minutes).

        Returns:
            List of event clusters (each cluster is a list of events).
        """
        if not self._events:
            return []

        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        clusters: list[list[TimelineEvent]] = []
        current_cluster: list[TimelineEvent] = [sorted_events[0]]

        for i in range(1, len(sorted_events)):
            t1 = self._parse_timestamp(sorted_events[i - 1].timestamp)
            t2 = self._parse_timestamp(sorted_events[i].timestamp)
            if t1 is None or t2 is None:
                current_cluster.append(sorted_events[i])
                continue

            gap = (t2 - t1).total_seconds()
            if gap <= max_gap_seconds:
                current_cluster.append(sorted_events[i])
            else:
                clusters.append(current_cluster)
                current_cluster = [sorted_events[i]]

        clusters.append(current_cluster)
        return clusters

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime | None:
        """Parse an ISO 8601 timestamp string."""
        try:
            # Handle both Z suffix and +00:00
            ts_clean = ts.replace("Z", "+00:00")
            return datetime.fromisoformat(ts_clean)
        except (ValueError, TypeError):
            return None

    # -- Export -----------------------------------------------------------------

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Export all events as a list of dicts."""
        return [e.to_dict() for e in self._events]

    def to_chronological_json(self) -> list[dict[str, Any]]:
        """Export events in chronological order as JSON-serializable dicts."""
        sorted_events = sorted(self._events, key=lambda e: e.timestamp)
        return [e.to_dict() for e in sorted_events]

    def to_vis_timeline_json(self) -> list[dict[str, Any]]:
        """Export in vis.js timeline format.

        Returns:
            List of items with ``id``, ``content``, ``start`` keys.
        """
        return [
            {
                "id": e.id,
                "content": f"[{e.severity.upper()}] {e.title}",
                "start": e.timestamp,
                "type": "point",
                "group": e.event_type,
            }
            for e in sorted(self._events, key=lambda e: e.timestamp)
        ]

    def clear(self) -> None:
        """Remove all events."""
        self._events.clear()
