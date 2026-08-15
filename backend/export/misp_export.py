"""MISP export/import — bidirectional MISP event conversion.

MISP (Malware Information Sharing Platform) is a leading open-source
threat intelligence sharing platform. This module converts between
internal investigation data and MISP event format.

MISP format spec: https://www.misp-project.org/misp-training/

Usage::

    exporter = MISPExporter()
    event = exporter.from_investigation(inv_data, findings, iocs)
    json_str = exporter.to_json(event)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# IOC type mapping: internal type → MISP attribute type
IOC_TO_MISP_TYPE: dict[str, str] = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "email": "email",
    "btc": "btc",
    "eth": "eth",
    "cve": "vulnerability",
    "onion_v2": "onion",
    "onion_v3": "onion",
    "pgp_keys": "pgp-key-id",
}

# MISP attribute type → internal IOC type (reverse mapping)
MISP_TO_IOC_TYPE: dict[str, str] = {v: k for k, v in IOC_TO_MISP_TYPE.items()}
# Fix collisions: prefer specific types
MISP_TO_IOC_TYPE.update({
    "ip-dst": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "email": "email",
    "btc": "btc",
    "eth": "eth",
    "vulnerability": "cve",
    "onion": "onion_v3",
})

# Severity to MISP threat level
SEVERITY_TO_THREAT_LEVEL: dict[str, int] = {
    "info": 4,
    "low": 3,
    "medium": 2,
    "high": 1,
    "critical": 1,
}


def _now_iso() -> str:
    """Return current UTC time in ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_date() -> str:
    """Return current date in MISP format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class MISPExporter:
    """Converts investigation data to/from MISP event format.

    Produces MISP-compatible JSON events with attributes, tags,
    and metadata. Supports bidirectional conversion for import
    and export of threat intelligence.

    Usage::

        exporter = MISPExporter(org_name="ACME", org_uuid="...")
        event = exporter.from_investigation(inv, findings, iocs)
    """

    def __init__(
        self,
        org_name: str = "ARGUS",
        org_uuid: str | None = None,
        default_distribution: int = 0,
        default_threat_level: int = 2,
        published: bool = False,
    ) -> None:
        """Initialize MISP exporter.

        Args:
            org_name: MISP organization name.
            org_uuid: MISP organization UUID.
            default_distribution: MISP distribution level
                (0=org only, 1=community, 2=connected, 3=all, 4=sharing group).
            default_threat_level: Default threat level (1=high, 2=medium, 3=low, 4=undefined).
            published: Whether to mark events as published.
        """
        self.org_name = org_name
        self.org_uuid = org_uuid or str(uuid.uuid4())
        self.default_distribution = default_distribution
        self.default_threat_level = default_threat_level
        self.published = published

    def from_investigation(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build a MISP event from investigation data.

        Args:
            investigation: Investigation dict with id, title, description, etc.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            MISP event dict.
        """
        inv_id = investigation.get("id", str(uuid.uuid4()))
        inv_title = investigation.get("title", "Untitled Investigation")

        # Determine threat level from findings
        threat_level = self.default_threat_level
        for finding in findings or []:
            sev = finding.get("severity", "medium")
            level = SEVERITY_TO_THREAT_LEVEL.get(sev, 2)
            if level < threat_level:
                threat_level = level

        event_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, inv_id))

        event: dict[str, Any] = {
            "Event": {
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"event-{inv_id}")),
                "orgc_id": "1",
                "org_id": "1",
                "date": _now_date(),
                "threat_level_id": str(threat_level),
                "info": inv_title,
                "published": self.published,
                "uuid": event_uuid,
                "attribute_count": 0,
                "analysis": "0",
                "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
                "distribution": str(self.default_distribution),
                "proposal_email_lock": False,
                "locked": False,
                "publish_timestamp": str(int(datetime.now(timezone.utc).timestamp())),
                "sharing_group_id": "0",
                "extends_uuid": "",
                "event_creator_email": "admin@argus.local",
                "Tag": [],
                "Attribute": [],
                "ShadowAttribute": [],
                "RelatedEvent": [],
                "Galaxy": [],
                "Object": [],
            }
        }

        attributes: list[dict[str, Any]] = []
        tags: list[dict[str, Any]] = []

        # Convert IOCs to MISP attributes
        for ioc in iocs or []:
            attr = self._ioc_to_attribute(ioc)
            if attr:
                attributes.append(attr)

                # Add tag for IOC source
                source = ioc.get("source", "")
                if source:
                    tags.append(self._make_tag(f"source:{source}"))

        # Convert findings to MISP attributes/hashes
        for finding in findings or []:
            attrs = self._finding_to_attributes(finding)
            attributes.extend(attrs)

            # Add severity tag
            severity = finding.get("severity", "info")
            tags.append(self._make_tag(f"severity:{severity}"))

        # Add investigation metadata tags
        tags.append(self._make_tag("ARGUS"))
        tags.append(self._make_tag("OSINT"))
        if investigation.get("tags"):
            for tag_name in investigation["tags"]:
                tags.append(self._make_tag(tag_name))

        event["Event"]["Attribute"] = attributes
        event["Event"]["Tag"] = tags
        event["Event"]["attribute_count"] = str(len(attributes))

        logger.info(
            "MISP event created: %d attributes, %d tags for '%s'",
            len(attributes), len(tags), inv_title,
        )
        return event

    def to_json(self, event: dict[str, Any], indent: int = 2) -> str:
        """Serialize a MISP event to JSON string.

        Args:
            event: MISP event dict.
            indent: JSON indentation level.

        Returns:
            JSON string representation.
        """
        return json.dumps(event, indent=indent, default=str)

    def parse_event(self, event_data: dict[str, Any]) -> dict[str, Any]:
        """Parse a MISP event into internal investigation format.

        Args:
            event_data: MISP event dict.

        Returns:
            Dict with investigation, findings, and iocs keys.
        """
        event = event_data.get("Event", event_data)

        investigation: dict[str, Any] = {
            "id": event.get("uuid", str(uuid.uuid4())),
            "title": event.get("info", "Imported MISP Event"),
            "description": event.get("info", ""),
            "tags": [],
            "source": "misp_import",
        }

        # Extract tags
        for tag in event.get("Tag", []):
            tag_name = tag.get("name", "")
            if tag_name and not tag_name.startswith("misp:"):
                investigation["tags"].append(tag_name)

        iocs: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        for attr in event.get("Attribute", []):
            ioc = self._attribute_to_ioc(attr)
            if ioc:
                iocs.append(ioc)

        return {
            "investigation": investigation,
            "findings": findings,
            "iocs": iocs,
        }

    def _ioc_to_attribute(self, ioc: dict[str, Any]) -> dict[str, Any] | None:
        """Convert a single IOC to a MISP attribute.

        Args:
            ioc: IOC dict with type, value, etc.

        Returns:
            MISP attribute dict or None.
        """
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if not value or ioc_type not in IOC_TO_MISP_TYPE:
            return None

        misp_type = IOC_TO_MISP_TYPE[ioc_type]
        severity_map = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 1}

        return {
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ioc_type}:{value}")),
            "type": misp_type,
            "category": self._misp_category(ioc_type),
            "to_ids": True,
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"attr-{ioc_type}-{value}")),
            "event_id": "0",
            "distribution": str(self.default_distribution),
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "comment": ioc.get("context", {}).get("description", "")
            if isinstance(ioc.get("context"), dict) else "",
            "sharing_group_id": "0",
            "deleted": False,
            "disable_correlation": False,
            "object_id": "0",
            "object_relation": None,
            "first_seen": None,
            "last_seen": None,
            "value": value,
            "Tag": [
                {"name": f"severity:{ioc.get('severity', 'medium')}"}
            ],
        }

    def _finding_to_attributes(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert a finding to MISP attributes (text/hash format).

        Args:
            finding: Finding dict.

        Returns:
            List of MISP attribute dicts.
        """
        title = finding.get("title", "Unknown Finding")
        description = finding.get("description", "")

        attrs: list[dict[str, Any]] = []

        # Add as text attribute
        if description:
            attrs.append({
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"finding-{finding.get('id', '')}")),
                "type": "text",
                "category": "Internal reference",
                "to_ids": False,
                "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"finding-text-{finding.get('id', '')}")),
                "event_id": "0",
                "distribution": str(self.default_distribution),
                "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
                "comment": title,
                "sharing_group_id": "0",
                "deleted": False,
                "disable_correlation": True,
                "object_id": "0",
                "object_relation": None,
                "first_seen": None,
                "last_seen": None,
                "value": description[:256],
                "Tag": [],
            })

        return attrs

    def _attribute_to_ioc(self, attr: dict[str, Any]) -> dict[str, Any] | None:
        """Convert a MISP attribute to an internal IOC dict.

        Args:
            attr: MISP attribute dict.

        Returns:
            IOC dict or None.
        """
        misp_type = attr.get("type", "")
        value = attr.get("value", "")

        if not value:
            return None

        ioc_type = MISP_TO_IOC_TYPE.get(misp_type, misp_type)

        return {
            "id": attr.get("id", str(uuid.uuid4())),
            "type": ioc_type,
            "value": value,
            "source": "misp_import",
            "severity": "medium",
            "context": {"description": attr.get("comment", "")},
        }

    def _make_tag(self, name: str) -> dict[str, Any]:
        """Create a MISP tag dict.

        Args:
            name: Tag name.

        Returns:
            MISP tag dict.
        """
        return {
            "name": name,
            "colour": "#3498db",
            "exportable": True,
            "hide_tag": False,
        }

    @staticmethod
    def _misp_category(ioc_type: str) -> str:
        """Map IOC type to MISP attribute category.

        Args:
            ioc_type: Internal IOC type.

        Returns:
            MISP category string.
        """
        category_map = {
            "ipv4": "Network activity",
            "ipv6": "Network activity",
            "domain": "Network activity",
            "url": "Network activity",
            "md5": "Payload delivery",
            "sha1": "Payload delivery",
            "sha256": "Payload delivery",
            "sha512": "Payload delivery",
            "email": "Payload delivery",
            "btc": "Financial fraud",
            "eth": "Financial fraud",
            "cve": "Vulnerability",
            "onion_v2": "Network activity",
            "onion_v3": "Network activity",
            "pgp_keys": "Person",
        }
        return category_map.get(ioc_type, "Other")
