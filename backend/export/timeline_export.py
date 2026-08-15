"""Timeline export — structured timeline generation and export.

Generates chronological event sequences from investigation data
and exports them in multiple formats (JSON, CSV, vis.js, STIX).

Usage::

    exporter = TimelineExporter()
    timeline = exporter.from_investigation(inv_id, findings, iocs, evidence)
    json_data = exporter.to_json(timeline)
    csv_data = exporter.to_csv(timeline)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return current UTC time in ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


class TimelineExporter:
    """Generates and exports investigation timelines.

    Creates chronological event sequences from findings, evidence,
    IOCs, and correlations. Supports multiple export formats.

    Usage::

        exporter = TimelineExporter()
        events = exporter.from_investigation(inv_id, findings, iocs)
        json_str = exporter.to_json(events)
    """

    # Severity ordering for sorting/filtering
    SEVERITY_ORDER: dict[str, int] = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def from_investigation(
        self,
        investigation_id: str,
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        correlations: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Build timeline from investigation data.

        Args:
            investigation_id: Investigation UUID.
            findings: List of finding dicts.
            iocs: List of IOC dicts.
            evidence: List of evidence dicts.
            correlations: List of correlation dicts.

        Returns:
            Chronologically sorted list of timeline events.
        """
        events: list[dict[str, Any]] = []

        # Add findings as events
        for finding in findings or []:
            events.append({
                "id": finding.get("id", str(uuid.uuid4())),
                "timestamp": finding.get("created_at", _now_iso()),
                "event_type": "finding",
                "title": finding.get("title", "Untitled Finding"),
                "description": finding.get("description", ""),
                "source": finding.get("source", ""),
                "severity": finding.get("severity", "info"),
                "investigation_id": investigation_id,
                "metadata": {
                    "confidence": finding.get("confidence", "medium"),
                    "finding_id": finding.get("id", ""),
                },
            })

        # Add IOCs as events
        for ioc in iocs or []:
            events.append({
                "id": ioc.get("id", str(uuid.uuid4())),
                "timestamp": ioc.get("created_at", _now_iso()),
                "event_type": "ioc_discovered",
                "title": f"IOC: {ioc.get('type', 'unknown')} — {ioc.get('value', '')[:64]}",
                "description": f"Discovered {ioc.get('type', 'unknown')} indicator",
                "source": ioc.get("source", ""),
                "severity": ioc.get("severity", "info"),
                "investigation_id": investigation_id,
                "metadata": {
                    "ioc_type": ioc.get("type", ""),
                    "ioc_value": ioc.get("value", ""),
                    "threat_type": ioc.get("threat_type", ""),
                },
            })

        # Add evidence as events
        for ev in evidence or []:
            events.append({
                "id": ev.get("id", str(uuid.uuid4())),
                "timestamp": ev.get("created_at", _now_iso()),
                "event_type": "evidence_collected",
                "title": f"Evidence: {ev.get('type', 'unknown')}",
                "description": ev.get("source_url", ""),
                "source": "evidence_collector",
                "severity": "info",
                "investigation_id": investigation_id,
                "metadata": {
                    "evidence_type": ev.get("type", ""),
                    "content_hash": ev.get("content_hash", ""),
                },
            })

        # Add correlations as events
        for corr in correlations or []:
            events.append({
                "id": corr.get("id", str(uuid.uuid4())),
                "timestamp": corr.get("timestamp", _now_iso()),
                "event_type": "correlation",
                "title": f"Correlation: {corr.get('correlation_type', 'unknown')}",
                "description": corr.get("description", ""),
                "source": ", ".join(corr.get("source_agents", [])),
                "severity": "medium",
                "investigation_id": investigation_id,
                "metadata": {
                    "confidence": corr.get("confidence", 0.5),
                    "entities": corr.get("entities", []),
                },
            })

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp", ""))

        logger.info(
            "Timeline generated: %d events for investigation '%s'",
            len(events), investigation_id,
        )
        return events

    def to_json(self, events: list[dict[str, Any]], pretty: bool = True) -> str:
        """Export timeline events to JSON string.

        Args:
            events: List of timeline event dicts.
            pretty: If True, format with indentation.

        Returns:
            JSON-formatted string.
        """
        return json.dumps(events, indent=2 if pretty else None, default=str)

    def to_csv(self, events: list[dict[str, Any]]) -> str:
        """Export timeline events to CSV string.

        Args:
            events: List of timeline event dicts.

        Returns:
            CSV-formatted string.
        """
        output = io.StringIO()
        columns = [
            "id", "timestamp", "event_type", "title", "description",
            "source", "severity", "investigation_id",
        ]
        writer = csv.DictWriter(
            output,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()

        for event in events:
            row = {col: event.get(col, "") for col in columns}
            writer.writerow(row)

        return output.getvalue()

    def to_vis_timeline(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Export timeline in vis.js format for visualization.

        Args:
            events: List of timeline event dicts.

        Returns:
            List of vis.js timeline items.
        """
        return [
            {
                "id": e.get("id", str(uuid.uuid4())),
                "content": f"[{e.get('severity', 'info').upper()}] {e.get('title', 'Event')}",
                "start": e.get("timestamp", ""),
                "type": "point",
                "group": e.get("event_type", "unknown"),
            }
            for e in events
        ]

    def to_stix_timeline(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert timeline events to STIX Observed Data objects.

        Args:
            events: List of timeline event dicts.

        Returns:
            List of STIX Observed Data dicts.
        """
        stix_objects: list[dict[str, Any]] = []

        for event in events:
            event_id = event.get("id", str(uuid.uuid4()))
            stix_objects.append({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{uuid.uuid5(uuid.NAMESPACE_DNS, event_id)}",
                "created": event.get("timestamp", _now_iso()),
                "modified": _now_iso(),
                "first_observed": event.get("timestamp", _now_iso()),
                "last_observed": event.get("timestamp", _now_iso()),
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "x-argus-timeline-event",
                        "id": event_id,
                        "event_type": event.get("event_type", "unknown"),
                        "title": event.get("title", ""),
                        "severity": event.get("severity", "info"),
                    },
                },
            })

        return stix_objects

    def get_summary(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate summary statistics for a timeline.

        Args:
            events: List of timeline event dicts.

        Returns:
            Summary dict with counts, time range, etc.
        """
        if not events:
            return {
                "total_events": 0,
                "time_range": None,
                "event_types": {},
                "severity_counts": {},
            }

        timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
        event_types: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for event in events:
            et = event.get("event_type", "unknown")
            event_types[et] = event_types.get(et, 0) + 1

            sev = event.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_events": len(events),
            "time_range": {
                "start": min(timestamps) if timestamps else None,
                "end": max(timestamps) if timestamps else None,
            },
            "event_types": event_types,
            "severity_counts": severity_counts,
        }

    def filter_events(
        self,
        events: list[dict[str, Any]],
        *,
        event_type: str | None = None,
        min_severity: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        """Filter timeline events.

        Args:
            events: List of timeline event dicts.
            event_type: Filter by event type.
            min_severity: Minimum severity level.
            start_time: Start of time range (ISO 8601).
            end_time: End of time range (ISO 8601).

        Returns:
            Filtered list of events.
        """
        min_sev_level = self.SEVERITY_ORDER.get(min_severity, 0) if min_severity else None

        filtered: list[dict[str, Any]] = []
        for event in events:
            if event_type and event.get("event_type") != event_type:
                continue

            if min_sev_level is not None:
                event_level = self.SEVERITY_ORDER.get(event.get("severity", "info"), 0)
                if event_level < min_sev_level:
                    continue

            if start_time and event.get("timestamp", "") < start_time:
                continue

            if end_time and event.get("timestamp", "") > end_time:
                continue

            filtered.append(event)

        return filtered
