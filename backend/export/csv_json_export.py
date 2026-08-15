"""CSV/JSON export — exports IOCs and findings in tabular formats.

Provides structured data export for IOCs and findings in CSV and JSON
formats suitable for SIEM ingestion, spreadsheet analysis, and data
exchange.

Usage::

    exporter = CSVJSONExporter()
    csv_data = exporter.iocs_to_csv(ioc_list)
    json_data = exporter.findings_to_json(finding_list)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class CSVJSONExporter:
    """Exports IOCs and findings to CSV and JSON formats.

    Supports:
        - IOC export to CSV with type, value, severity, source columns
        - Finding export to CSV with title, severity, confidence columns
        - Full investigation export to structured JSON
        - Bulk export combining multiple data types

    Usage::

        exporter = CSVJSONExporter()
        csv_bytes = exporter.iocs_to_csv(iocs)
        json_str = exporter.investigation_to_json(inv, findings, iocs)
    """

    # CSV column definitions for IOCs
    IOC_COLUMNS: list[str] = [
        "id", "type", "value", "severity", "threat_type",
        "source", "investigation_id", "created_at",
    ]

    # CSV column definitions for findings
    FINDING_COLUMNS: list[str] = [
        "id", "title", "description", "severity", "confidence",
        "source", "investigation_id", "created_at",
    ]

    def iocs_to_csv(self, iocs: list[dict[str, Any]]) -> str:
        """Export IOCs to CSV string.

        Args:
            iocs: List of IOC dicts.

        Returns:
            CSV-formatted string.
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=self.IOC_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()

        for ioc in iocs:
            row = {col: ioc.get(col, "") for col in self.IOC_COLUMNS}
            # Handle context dict - flatten description
            context = ioc.get("context", {})
            if isinstance(context, dict) and "description" in context:
                row["source"] = context["description"]
            writer.writerow(row)

        return output.getvalue()

    def iocs_to_csv_bytes(self, iocs: list[dict[str, Any]]) -> bytes:
        """Export IOCs to CSV bytes (UTF-8 encoded).

        Args:
            iocs: List of IOC dicts.

        Returns:
            CSV data as bytes.
        """
        return self.iocs_to_csv(iocs).encode("utf-8")

    def findings_to_csv(self, findings: list[dict[str, Any]]) -> str:
        """Export findings to CSV string.

        Args:
            findings: List of finding dicts.

        Returns:
            CSV-formatted string.
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=self.FINDING_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()

        for finding in findings:
            row = {col: finding.get(col, "") for col in self.FINDING_COLUMNS}
            # Truncate description for CSV readability
            desc = row.get("description", "")
            if desc and len(str(desc)) > 200:
                row["description"] = str(desc)[:200] + "..."
            writer.writerow(row)

        return output.getvalue()

    def findings_to_csv_bytes(self, findings: list[dict[str, Any]]) -> bytes:
        """Export findings to CSV bytes (UTF-8 encoded).

        Args:
            findings: List of finding dicts.

        Returns:
            CSV data as bytes.
        """
        return self.findings_to_csv(findings).encode("utf-8")

    def iocs_to_json(
        self,
        iocs: list[dict[str, Any]],
        pretty: bool = True,
    ) -> str:
        """Export IOCs to JSON string.

        Args:
            iocs: List of IOC dicts.
            pretty: If True, format with indentation.

        Returns:
            JSON-formatted string.
        """
        return json.dumps(iocs, indent=2 if pretty else None, default=str)

    def findings_to_json(
        self,
        findings: list[dict[str, Any]],
        pretty: bool = True,
    ) -> str:
        """Export findings to JSON string.

        Args:
            findings: List of finding dicts.
            pretty: If True, format with indentation.

        Returns:
            JSON-formatted string.
        """
        return json.dumps(findings, indent=2 if pretty else None, default=str)

    def investigation_to_json(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
        pretty: bool = True,
    ) -> str:
        """Export complete investigation to structured JSON.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.
            timeline: Optional timeline events.
            pretty: If True, format with indentation.

        Returns:
            JSON-formatted string with full investigation data.
        """
        data: dict[str, Any] = {
            "investigation": investigation,
            "findings": findings or [],
            "iocs": iocs or [],
            "metadata": {
                "export_format": "ARGUS Investigation Export",
                "version": "1.0",
                "finding_count": len(findings) if findings else 0,
                "ioc_count": len(iocs) if iocs else 0,
            },
        }

        if timeline:
            data["timeline"] = timeline
            data["metadata"]["timeline_event_count"] = len(timeline)

        return json.dumps(data, indent=2 if pretty else None, default=str)

    def bulk_export(
        self,
        data: dict[str, list[dict[str, Any]]],
        format: str = "json",
    ) -> str | bytes:
        """Bulk export multiple data types.

        Args:
            data: Dict with keys like "iocs", "findings", "timeline".
            format: Output format ("json" or "csv").

        Returns:
            Exported data as string (JSON) or string (CSV).
        """
        if format == "json":
            return json.dumps(data, indent=2, default=str)

        if format == "csv":
            # For CSV, combine all data types with a type column
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["record_type"] + self.IOC_COLUMNS)

            for record_type, records in data.items():
                for record in records:
                    row = [record_type]
                    for col in self.IOC_COLUMNS:
                        row.append(record.get(col, ""))
                    writer.writerow(row)

            return output.getvalue()

        raise ValueError(f"Unsupported format: {format}. Use 'json' or 'csv'.")
