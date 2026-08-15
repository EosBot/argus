"""TAXII 2.1 export module.

Provides TAXIIExporter for converting investigations into TAXII 2.1
envelope format and publishing to TAXII collections.

Usage::

    from backend.export.taxii import TAXIIExporter

    exporter = TAXIIExporter()
    envelope = exporter.from_investigation(investigation, findings, iocs)
    json_str = exporter.to_json(envelope)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# TAXII 2.1 content type
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

# Default API root path
DEFAULT_API_ROOT = "/taxii2/api1/"


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _uuid5(namespace: str, name: str) -> str:
    """Generate a deterministic UUID5 from namespace and name."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{namespace}:{name}"))


class TAXIIExporter:
    """Converts investigation data into TAXII 2.1 envelope format.

    Follows the same pattern as STIXExporter: ``from_investigation()``
    builds the data structure, ``to_json()`` serializes it.
    """

    def __init__(
        self,
        org_name: str = "ARGUS CTI",
        default_confidence: int = 75,
        tlp_level: str = "amber",
    ) -> None:
        """Initialize TAXII exporter.

        Args:
            org_name: Organization name for created_by_ref.
            default_confidence: Default confidence score (0-100).
            tlp_level: TLP marking (white, green, amber, red).
        """
        self.org_name = org_name
        self.default_confidence = default_confidence
        self.tlp_level = tlp_level

    def from_investigation(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build a TAXII 2.1 envelope from investigation data.

        Args:
            investigation: Investigation dict with id, title, description.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            TAXII 2.1 envelope dict with STIX objects.
        """
        # Import here to avoid circular imports
        from backend.export.stix_export import STIXExporter

        stix_exporter = STIXExporter(
            org_name=self.org_name,
            default_confidence=self.default_confidence,
            tlp_level=self.tlp_level,
        )
        bundle = stix_exporter.from_investigation(investigation, findings, iocs)

        envelope: dict[str, Any] = {
            "type": "envelope",
            "id": f"envelope--{_uuid5('envelope', investigation.get('id', str(uuid.uuid4())))}",
            "spec_version": "2.1",
            "objects": bundle.get("objects", []),
        }

        logger.info(
            "TAXII envelope created: %d objects for investigation '%s'",
            len(envelope["objects"]),
            investigation.get("title", "Untitled"),
        )
        return envelope

    def to_json(self, envelope: dict[str, Any], indent: int = 2) -> str:
        """Serialize a TAXII envelope to JSON string.

        Args:
            envelope: TAXII envelope dict.
            indent: JSON indentation level.

        Returns:
            JSON string representation.
        """
        return json.dumps(envelope, indent=indent, default=str)

    def discovery(self) -> dict[str, Any]:
        """Build TAXII 2.1 Discovery resource."""
        return {
            "title": "ARGUS TAXII Server",
            "description": "ARGUS CTI TAXII 2.1 Server for threat intelligence sharing",
            "contact": "cti@argus.local",
            "default": DEFAULT_API_ROOT,
            "api_roots": [DEFAULT_API_ROOT],
        }

    def api_root_info(self) -> dict[str, Any]:
        """Build TAXII 2.1 API Root info resource."""
        return {
            "title": "ARGUS API Root",
            "versions": ["taxii-2.1"],
            "max_content_length": 104857600,  # 100 MB
        }

    @staticmethod
    def error_response(
        title: str,
        detail: str,
        status: str = "error",
    ) -> dict[str, Any]:
        """Build a TAXII 2.1 Error resource.

        Args:
            title: Short error title.
            detail: Human-readable error description.
            status: Status string.

        Returns:
            TAXII error dict.
        """
        return {
            "title": title,
            "detail": detail,
            "status": status,
            "http_status": 400,
        }


__all__ = [
    "TAXIIExporter",
    "TAXII_CONTENT_TYPE",
    "DEFAULT_API_ROOT",
]
