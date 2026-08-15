"""STIX 2.1 export — converts investigations and findings to STIX bundles.

STIX (Structured Threat Information Expression) is an OASIS open standard
for cyber threat intelligence. This module converts internal investigation
data into STIX 2.1 bundles containing Indicators, Threat Actors, Reports,
and Observables.

Spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

Usage::

    exporter = STIXExporter()
    bundle = exporter.from_investigation(inv_data, findings, iocs)
    json_str = exporter.to_json(bundle)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# STIX pattern mapping from IOC types to STIX indicator patterns
IOC_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.SHA1 = '{value}']",
    "sha256": "[file:hashes.SHA256 = '{value}']",
    "sha512": "[file:hashes.SHA512 = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "btc": "[cryptocurrency-wallet:value = '{value}']",
    "eth": "[cryptocurrency-wallet:value = '{value}']",
    "cve": "[vulnerability:name = '{value}']",
    "onion_v2": "[domain-name:value = '{value}']",
    "onion_v3": "[domain-name:value = '{value}']",
}

# STIX type mapping for observables
IOC_TO_STIX_TYPE: dict[str, str] = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "sha512": "file",
    "email": "email-addr",
    "btc": "cryptocurrency-wallet",
    "eth": "cryptocurrency-wallet",
    "cve": "vulnerability",
    "onion_v2": "domain-name",
    "onion_v3": "domain-name",
}


def _uuid5(namespace: str, name: str) -> str:
    """Generate a deterministic UUID5 for STIX ID stability."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{namespace}:{name}"))


def _now_iso() -> str:
    """Return current UTC time in STIX-compatible ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class STIXExporter:
    """Converts investigation data to STIX 2.1 bundles.

    Produces valid STIX 2.1 JSON bundles with:
        - Indicator objects for each IOC
        - Observed Data objects for raw observables
        - Threat Actor objects from attribution data
        - Report objects for the investigation summary
        - Relationship objects linking indicators to threats

    Usage::

        exporter = STIXExporter(org_name="ACME CTI")
        bundle = exporter.from_investigation(inv, findings, iocs)
    """

    def __init__(
        self,
        org_name: str = "ARGUS CTI",
        org_id: str | None = None,
        default_confidence: int = 75,
        tlp_level: str = "amber",
    ) -> None:
        """Initialize STIX exporter.

        Args:
            org_name: Organization name for created_by_ref.
            org_id: Optional deterministic org UUID.
            default_confidence: Default confidence score (0-100).
            tlp_level: TLP marking (white, green, amber, red).
        """
        self.org_name = org_name
        self.org_id = org_id or _uuid5("org", org_name)
        self.default_confidence = default_confidence
        self.tlp_level = tlp_level

    def from_investigation(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build a STIX bundle from investigation data.

        Args:
            investigation: Investigation dict with id, title, description, etc.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            STIX 2.1 bundle dict with type "bundle".
        """
        objects: list[dict[str, Any]] = []
        inv_id = investigation.get("id", str(uuid.uuid4()))
        inv_title = investigation.get("title", "Untitled Investigation")

        # Create identity for the organization
        identity = self._make_identity()
        objects.append(identity)

        # Create TLP marking
        tlp_marking = self._make_tlp_marking()
        objects.append(tlp_marking)

        # Collect all indicator IDs for the report
        indicator_ids: list[str] = []

        # Convert IOCs to STIX indicators
        for ioc in iocs or []:
            indicator = self._ioc_to_indicator(ioc, tlp_marking["id"])
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator["id"])

                # Also create observed data for the observable
                observed = self._ioc_to_observed_data(ioc, tlp_marking["id"])
                if observed:
                    objects.append(observed)

        # Convert findings to STIX threat actors or notes
        for finding in findings or []:
            threat_ref = finding.get("data", {}).get("threat_ref") if finding.get("data") else None
            if threat_ref:
                ta = self._finding_to_threat_actor(finding, tlp_marking["id"])
                if ta:
                    objects.append(ta)
                    # Relate indicators to threat actor
                    for ind_id in indicator_ids[:10]:  # Limit relationships
                        rel = self._make_relationship(
                            ind_id, ta["id"], "indicates", tlp_marking["id"]
                        )
                        objects.append(rel)

        # Create report object
        report = self._make_report(
            inv_id, inv_title, investigation.get("description", ""),
            indicator_ids, tlp_marking["id"],
        )
        objects.append(report)

        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": f"bundle--{_uuid5('bundle', inv_id)}",
            "spec_version": "2.1",
            "objects": objects,
        }

        logger.info(
            "STIX bundle created: %d objects for investigation '%s'",
            len(objects), inv_title,
        )
        return bundle

    def from_iocs(
        self,
        iocs: list[dict[str, Any]],
        bundle_name: str = "IOC Export",
    ) -> dict[str, Any]:
        """Build a STIX bundle from IOCs only.

        Args:
            iocs: List of IOC dicts.
            bundle_name: Name for the bundle.

        Returns:
            STIX 2.1 bundle dict.
        """
        return self.from_investigation(
            {"id": str(uuid.uuid4()), "title": bundle_name, "description": ""},
            findings=[],
            iocs=iocs,
        )

    def to_json(self, bundle: dict[str, Any], indent: int = 2) -> str:
        """Serialize a STIX bundle to JSON string.

        Args:
            bundle: STIX bundle dict.
            indent: JSON indentation level.

        Returns:
            JSON string representation.
        """
        return json.dumps(bundle, indent=indent, default=str)

    def _make_identity(self) -> dict[str, Any]:
        """Create a STIX Identity object for the reporting organization."""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{self.org_id}",
            "created": _now_iso(),
            "modified": _now_iso(),
            "name": self.org_name,
            "identity_class": "organization",
            "object_marking_refs": [],
        }

    def _make_tlp_marking(self) -> dict[str, Any]:
        """Create TLP marking definition."""
        tlp_markers = {
            "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        }
        tlp_id = tlp_markers.get(self.tlp_level, tlp_markers["amber"])
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": tlp_id,
            "created": "2017-01-20T00:00:00Z",
            "definition_type": "tlp",
            "definition": {"tlp": self.tlp_level},
        }

    def _ioc_to_indicator(
        self,
        ioc: dict[str, Any],
        marking_id: str,
    ) -> dict[str, Any] | None:
        """Convert a single IOC to a STIX Indicator object.

        Args:
            ioc: IOC dict with type, value, severity, etc.
            marking_id: TLP marking definition ID.

        Returns:
            STIX Indicator dict or None if type is unsupported.
        """
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if not value or ioc_type not in IOC_TO_STIX_PATTERN:
            return None

        pattern = IOC_TO_STIX_PATTERN[ioc_type].format(value=value)
        ioc_id = _uuid5("indicator", f"{ioc_type}:{value}")

        severity_map = {"info": 20, "low": 40, "medium": 60, "high": 80, "critical": 95}
        confidence = severity_map.get(ioc.get("severity", "medium"), self.default_confidence)

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc_id}",
            "created": ioc.get("created_at", _now_iso()),
            "modified": _now_iso(),
            "name": f"{ioc_type}: {value[:64]}",
            "description": ioc.get("context", {}).get("description", "")
            if isinstance(ioc.get("context"), dict) else "",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("created_at", _now_iso()),
            "valid_until": None,
            "confidence": confidence,
            "object_marking_refs": [marking_id],
            "external_references": [
                {
                    "source_name": ioc.get("source", "ARGUS"),
                    "url": ioc.get("context", {}).get("url", "")
                    if isinstance(ioc.get("context"), dict) else "",
                }
            ] if ioc.get("source") else [],
        }

    def _ioc_to_observed_data(
        self,
        ioc: dict[str, Any],
        marking_id: str,
    ) -> dict[str, Any] | None:
        """Convert a single IOC to a STIX Observed Data object.

        Args:
            ioc: IOC dict with type and value.
            marking_id: TLP marking definition ID.

        Returns:
            STIX Observed Data dict or None.
        """
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if not value or ioc_type not in IOC_TO_STIX_TYPE:
            return None

        stix_type = IOC_TO_STIX_TYPE[ioc_type]
        observed_id = _uuid5("observed-data", f"{ioc_type}:{value}")

        # Build the observable object based on type
        if ioc_type in ("ipv4", "ipv6"):
            observable = {"type": stix_type, "value": value}
        elif ioc_type in ("domain", "onion_v2", "onion_v3"):
            observable = {"type": stix_type, "value": value}
        elif ioc_type == "url":
            observable = {"type": stix_type, "value": value}
        elif ioc_type in ("md5", "sha1", "sha256", "sha512"):
            hash_type = ioc_type.upper()
            observable = {"type": stix_type, "hashes": {hash_type: value}}
        elif ioc_type == "email":
            observable = {"type": stix_type, "value": value}
        elif ioc_type in ("btc", "eth"):
            observable = {"type": stix_type, "value": value}
        elif ioc_type == "cve":
            observable = {"type": stix_type, "name": value}
        else:
            return None

        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{observed_id}",
            "created": ioc.get("created_at", _now_iso()),
            "modified": _now_iso(),
            "first_observed": ioc.get("created_at", _now_iso()),
            "last_observed": _now_iso(),
            "number_observed": 1,
            "object_marking_refs": [marking_id],
            "objects": {"0": observable},
        }

    def _finding_to_threat_actor(
        self,
        finding: dict[str, Any],
        marking_id: str,
    ) -> dict[str, Any] | None:
        """Convert a finding to a STIX Threat Actor object.

        Args:
            finding: Finding dict with title, severity, data.
            marking_id: TLP marking definition ID.

        Returns:
            STIX Threat Actor dict or None.
        """
        title = finding.get("title", "Unknown Threat")
        finding_id = finding.get("id", str(uuid.uuid4()))

        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{_uuid5('ta', finding_id)}",
            "created": finding.get("created_at", _now_iso()),
            "modified": _now_iso(),
            "name": title,
            "description": finding.get("description", ""),
            "threat_actor_types": ["unknown"],
            "severity": finding.get("severity", "medium"),
            "object_marking_refs": [marking_id],
        }

    def _make_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        marking_id: str,
    ) -> dict[str, Any]:
        """Create a STIX Relationship object.

        Args:
            source_id: Source object ID.
            target_id: Target object ID.
            relationship_type: Type of relationship.
            marking_id: TLP marking definition ID.

        Returns:
            STIX Relationship dict.
        """
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{_uuid5('rel', f'{source_id}:{target_id}')}",
            "created": _now_iso(),
            "modified": _now_iso(),
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id,
            "object_marking_refs": [marking_id],
        }

    def _make_report(
        self,
        inv_id: str,
        title: str,
        description: str,
        object_refs: list[str],
        marking_id: str,
    ) -> dict[str, Any]:
        """Create a STIX Report object summarizing the investigation.

        Args:
            inv_id: Investigation ID.
            title: Report title.
            description: Report description.
            object_refs: List of STIX object IDs to include.
            marking_id: TLP marking definition ID.

        Returns:
            STIX Report dict.
        """
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{_uuid5('report', inv_id)}",
            "created": _now_iso(),
            "modified": _now_iso(),
            "name": title,
            "description": description,
            "report_types": ["threat-report"],
            "published": _now_iso(),
            "object_marking_refs": [marking_id],
            "object_refs": object_refs,
        }
