"""Sigma rules export — generates detection rules from IOCs.

Sigma is a generic and open signature format for SIEM (Security Information
and Event Management) systems. This module generates Sigma detection rules
from investigation IOCs.

Spec: https://github.com/SigmaHQ/sigma

Usage::

    exporter = SigmaExporter()
    rule = exporter.from_ioc(ioc_dict)
    yaml_str = exporter.to_yaml(rule)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# IOC type to Sigma log source category mapping
IOC_TO_SIGMA_LOGSOURCE: dict[str, dict[str, str]] = {
    "ipv4": {"category": "network_connection", "product": "windows"},
    "ipv6": {"category": "network_connection", "product": "windows"},
    "domain": {"category": "dns", "product": "windows"},
    "url": {"category": "proxy", "product": "windows"},
    "md5": {"category": "process_creation", "product": "windows"},
    "sha1": {"category": "process_creation", "product": "windows"},
    "sha256": {"category": "process_creation", "product": "windows"},
    "sha512": {"category": "process_creation", "product": "windows"},
    "email": {"category": "email", "product": "windows"},
    "btc": {"category": "network_connection", "product": "windows"},
    "eth": {"category": "network_connection", "product": "windows"},
    "cve": {"category": "vulnerability", "product": "windows"},
    "onion_v2": {"category": "network_connection", "product": "windows"},
    "onion_v3": {"category": "network_connection", "product": "windows"},
}

# IOC type to Sigma detection field mapping
IOC_TO_SIGMA_FIELD: dict[str, str] = {
    "ipv4": "DestinationIp",
    "ipv6": "DestinationIp",
    "domain": "QueryName",
    "url": "DestinationHostname",
    "md5": "Hashes.MD5",
    "sha1": "Hashes.SHA1",
    "sha256": "Hashes.SHA256",
    "sha512": "Hashes.SHA512",
    "email": "Sender",
    "btc": "DestinationIp",
    "eth": "DestinationIp",
    "cve": "CVE",
    "onion_v2": "DestinationIp",
    "onion_v3": "DestinationIp",
}


def _now_iso() -> str:
    """Return current UTC time in ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_today() -> str:
    """Return current date."""
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


class SigmaExporter:
    """Generates Sigma detection rules from IOCs.

    Produces valid Sigma YAML rules with proper log source, detection
    conditions, and metadata. Supports batch generation for multiple IOCs.

    Usage::

        exporter = SigmaExporter(author="ARGUS CTI")
        rules = exporter.from_iocs(ioc_list)
    """

    def __init__(
        self,
        author: str = "ARGUS CTI",
        level: str = "medium",
        status: str = "experimental",
        description_template: str = "Detection for {type} indicator: {value}",
    ) -> None:
        """Initialize Sigma exporter.

        Args:
            author: Rule author.
            level: Default severity level.
            status: Rule status (stable, experimental, testing, deprecated).
            description_template: Template for rule description.
        """
        self.author = author
        self.level = level
        self.status = status
        self.description_template = description_template

    def from_ioc(self, ioc: dict[str, Any]) -> dict[str, Any]:
        """Generate a Sigma rule from a single IOC.

        Args:
            ioc: IOC dict with type, value, severity, etc.

        Returns:
            Sigma rule dict (YAML-serializable).
        """
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if not value:
            return {}

        logsource = IOC_TO_SIGMA_LOGSOURCE.get(ioc_type, {
            "category": "network_connection",
            "product": "windows",
        })
        field = IOC_TO_SIGMA_FIELD.get(ioc_type, "DestinationIp")
        severity = ioc.get("severity", self.level)

        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ioc_type}:{value}"))

        rule: dict[str, Any] = {
            "title": f"ARGUS_{ioc_type}_{rule_id[:8]}",
            "id": rule_id,
            "status": self.status,
            "description": self.description_template.format(
                type=ioc_type, value=value[:64],
            ),
            "author": self.author,
            "date": _date_today(),
            "references": [
                f"https://argus.local/iocs/{ioc.get('id', '')}",
            ],
            "tags": [
                "attack.t1071",  # Application Layer Protocol
                "attack.t1041",  # Exfiltration Over C2 Channel
            ],
            "logsource": logsource,
            "detection": {
                "selection": {
                    field: value,
                },
                "condition": "selection",
            },
            "falsepositives": [
                "Unknown",
                "Legitimate use of this indicator",
            ],
            "level": severity,
        }

        # Add source reference if available
        if ioc.get("source"):
            rule["references"].append(ioc["source"])

        return rule

    def from_iocs(
        self,
        iocs: list[dict[str, Any]],
        group_by_type: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate Sigma rules from multiple IOCs.

        Args:
            iocs: List of IOC dicts.
            group_by_type: If True, group IOCs of same type into single rule.

        Returns:
            List of Sigma rule dicts.
        """
        if not group_by_type:
            return [rule for ioc in iocs if (rule := self.from_ioc(ioc))]

        # Group IOCs by type for combined rules
        grouped: dict[str, list[dict[str, Any]]] = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in grouped:
                grouped[ioc_type] = []
            grouped[ioc_type].append(ioc)

        rules: list[dict[str, Any]] = []
        for ioc_type, group in grouped.items():
            if len(group) == 1:
                rule = self.from_ioc(group[0])
                if rule:
                    rules.append(rule)
            else:
                rule = self._make_combined_rule(ioc_type, group)
                if rule:
                    rules.append(rule)

        return rules

    def from_investigation(
        self,
        investigation: dict[str, Any],
        iocs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate Sigma rules from an investigation.

        Args:
            investigation: Investigation dict.
            iocs: List of IOC dicts.

        Returns:
            List of Sigma rule dicts.
        """
        rules = self.from_iocs(iocs or [])

        # Add investigation reference to each rule
        inv_id = investigation.get("id", "")
        inv_title = investigation.get("title", "")
        for rule in rules:
            rule["description"] = f"[{inv_title}] {rule.get('description', '')}"
            if inv_id:
                rule["references"].insert(0, f"https://argus.local/investigations/{inv_id}")

        return rules

    def to_yaml(self, rule: dict[str, Any]) -> str:
        """Serialize a Sigma rule to YAML string.

        Args:
            rule: Sigma rule dict.

        Returns:
            YAML string representation.
        """
        try:
            import yaml
            return yaml.dump(rule, default_flow_style=False, sort_keys=False)
        except ImportError:
            return self._manual_yaml_dump(rule)

    def to_yaml_batch(self, rules: list[dict[str, Any]]) -> str:
        """Serialize multiple Sigma rules to YAML.

        Args:
            rules: List of Sigma rule dicts.

        Returns:
            YAML string with all rules separated by ---.
        """
        parts: list[str] = []
        for rule in rules:
            parts.append(self.to_yaml(rule))
        return "\n---\n".join(parts)

    def _make_combined_rule(
        self,
        ioc_type: str,
        iocs: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Create a combined Sigma rule for multiple IOCs of the same type.

        Args:
            ioc_type: Type of IOCs.
            iocs: List of IOC dicts of the same type.

        Returns:
            Combined Sigma rule dict or None.
        """
        if not iocs:
            return None

        logsource = IOC_TO_SIGMA_LOGSOURCE.get(ioc_type, {
            "category": "network_connection",
            "product": "windows",
        })
        field = IOC_TO_SIGMA_FIELD.get(ioc_type, "DestinationIp")
        values = [ioc.get("value", "") for ioc in iocs if ioc.get("value")]

        if not values:
            return None

        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"combined-{ioc_type}"))

        # Build selection with multiple values
        selection: dict[str, Any] = {field: values}

        return {
            "title": f"ARGUS_{ioc_type}_combined_{rule_id[:8]}",
            "id": rule_id,
            "status": self.status,
            "description": f"Combined detection for {len(values)} {ioc_type} indicators",
            "author": self.author,
            "date": _date_today(),
            "references": ["https://argus.local"],
            "tags": ["attack.t1071"],
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "falsepositives": ["Unknown"],
            "level": self.level,
        }

    @staticmethod
    def _manual_yaml_dump(data: dict[str, Any], indent: int = 0) -> str:
        """Simple YAML dumper fallback when PyYAML is not available.

        Args:
            data: Dict to serialize.
            indent: Current indentation level.

        Returns:
            YAML string.
        """
        lines: list[str] = []
        prefix = "  " * indent

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(SigmaExporter._manual_yaml_dump(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, str):
                        lines.append(f"{prefix}  - \"{item}\"")
                    else:
                        lines.append(f"{prefix}  - {item}")
            elif isinstance(value, str):
                # Quote strings that contain special characters
                if any(c in value for c in ":{}[]&*?|-><!%@`"):
                    lines.append(f'{prefix}{key}: "{value}"')
                else:
                    lines.append(f"{prefix}{key}: {value}")
            elif isinstance(value, bool):
                lines.append(f"{prefix}{key}: {str(value).lower()}")
            elif value is None:
                lines.append(f"{prefix}{key}: null")
            else:
                lines.append(f"{prefix}{key}: {value}")

        return "\n".join(lines)
