"""YARA rules export — generates YARA detection rules from IOCs.

YARA is a tool for identifying and classifying malware samples. This module
generates YARA rules from investigation IOCs (hashes, strings, patterns).

Spec: https://yara.readthedocs.io/

Usage::

    exporter = YARAExporter()
    rule = exporter.from_ioc(ioc_dict)
    rule_text = exporter.to_rule(rule)
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# IOC type to YARA string mapping
IOC_TO_YARA_STRINGS: dict[str, str] = {
    "md5": "hash",
    "sha1": "hash",
    "sha512": "hash",
    "sha256": "hash",
    "domain": "domain",
    "url": "url",
    "ipv4": "ip",
    "ipv6": "ip",
    "email": "email",
    "btc": "btc",
    "eth": "eth",
    "cve": "cve",
    "onion_v2": "onion",
    "onion_v3": "onion",
}

# Severity to YARA metadata score
SEVERITY_TO_SCORE: dict[str, int] = {
    "info": 20,
    "low": 40,
    "medium": 60,
    "high": 80,
    "critical": 95,
}


def _date_today() -> str:
    """Return current date."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _sanitize_name(name: str) -> str:
    """Sanitize a string for use as a YARA rule name.

    Args:
        name: Input string.

    Returns:
        Sanitized string safe for YARA identifiers.
    """
    # Replace non-alphanumeric chars with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # Remove leading digits
    sanitized = re.sub(r"^[0-9]+", "", sanitized)
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    # Strip trailing underscores
    sanitized = sanitized.strip("_")
    return sanitized or "ARGUS_Rule"


class YARAExporter:
    """Generates YARA detection rules from IOCs.

    Produces valid YARA rules with strings, conditions, and metadata.
    Supports hash-based rules, string-based rules, and combined rules.

    Usage::

        exporter = YARAExporter(author="ARGUS CTI")
        rules = exporter.from_iocs(ioc_list)
    """

    def __init__(
        self,
        author: str = "ARGUS CTI",
        prefix: str = "ARGUS",
        default_severity: str = "medium",
    ) -> None:
        """Initialize YARA exporter.

        Args:
            author: Rule author metadata.
            prefix: Rule name prefix.
            default_severity: Default severity level.
        """
        self.author = author
        self.prefix = prefix
        self.default_severity = default_severity

    def from_ioc(self, ioc: dict[str, Any]) -> dict[str, Any]:
        """Generate a YARA rule from a single IOC.

        Args:
            ioc: IOC dict with type, value, severity, etc.

        Returns:
            YARA rule dict (serializable to YARA text).
        """
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        if not value:
            return {}

        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ioc_type}:{value}"))
        rule_name = _sanitize_name(f"{self.prefix}_{ioc_type}_{rule_id[:8]}")
        severity = ioc.get("severity", self.default_severity)
        score = SEVERITY_TO_SCORE.get(severity, 60)

        rule: dict[str, Any] = {
            "name": rule_name,
            "meta": {
                "author": self.author,
                "date": _date_today(),
                "description": f"Detection for {ioc_type} indicator",
                "severity": severity,
                "score": score,
                "reference": f"https://argus.local/iocs/{ioc.get('id', '')}",
                "ioc_type": ioc_type,
                "ioc_value": value[:128],
            },
            "strings": [],
            "condition": "",
        }

        # Generate strings based on IOC type
        if ioc_type in ("md5", "sha1", "sha256", "sha512"):
            rule["strings"].append({
                "name": "$hash",
                "type": "hash",
                "value": value,
                "modifiers": [],
            })
            rule["condition"] = "uint16(0) == 0x5A4D and $hash"
        elif ioc_type in ("domain", "onion_v2", "onion_v3"):
            rule["strings"].append({
                "name": "$domain",
                "type": "text",
                "value": value,
                "modifiers": ["ascii", "wide", "nocase"],
            })
            rule["condition"] = "$domain"
        elif ioc_type == "url":
            rule["strings"].append({
                "name": "$url",
                "type": "text",
                "value": value,
                "modifiers": ["ascii", "nocase"],
            })
            rule["condition"] = "$url"
        elif ioc_type in ("ipv4", "ipv6"):
            rule["strings"].append({
                "name": "$ip",
                "type": "text",
                "value": value,
                "modifiers": ["ascii"],
            })
            rule["condition"] = "$ip"
        elif ioc_type == "email":
            rule["strings"].append({
                "name": "$email",
                "type": "text",
                "value": value,
                "modifiers": ["ascii", "nocase"],
            })
            rule["condition"] = "$email"
        elif ioc_type in ("btc", "eth"):
            rule["strings"].append({
                "name": "$wallet",
                "type": "text",
                "value": value,
                "modifiers": ["ascii"],
            })
            rule["condition"] = "$wallet"
        elif ioc_type == "cve":
            rule["strings"].append({
                "name": "$cve",
                "type": "text",
                "value": value,
                "modifiers": ["ascii", "nocase"],
            })
            rule["condition"] = "$cve"
        else:
            rule["strings"].append({
                "name": "$indicator",
                "type": "text",
                "value": value,
                "modifiers": ["ascii", "nocase"],
            })
            rule["condition"] = "$indicator"

        return rule

    def from_iocs(
        self,
        iocs: list[dict[str, Any]],
        group_by_type: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate YARA rules from multiple IOCs.

        Args:
            iocs: List of IOC dicts.
            group_by_type: If True, group IOCs of same type into single rule.

        Returns:
            List of YARA rule dicts.
        """
        if not group_by_type:
            return [rule for ioc in iocs if (rule := self.from_ioc(ioc))]

        # Group IOCs by type
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
        """Generate YARA rules from an investigation.

        Args:
            investigation: Investigation dict.
            iocs: List of IOC dicts.

        Returns:
            List of YARA rule dicts.
        """
        rules = self.from_iocs(iocs or [])

        inv_title = investigation.get("title", "")
        inv_id = investigation.get("id", "")
        for rule in rules:
            rule["meta"]["description"] = f"[{inv_title}] {rule['meta']['description']}"
            if inv_id:
                rule["meta"]["investigation_id"] = inv_id

        return rules

    def to_rule(self, rule: dict[str, Any]) -> str:
        """Serialize a YARA rule dict to YARA text format.

        Args:
            rule: YARA rule dict.

        Returns:
            YARA rule as text string.
        """
        lines: list[str] = []

        # Rule name
        lines.append(f"rule {rule['name']} {{")
        lines.append("    meta:")

        # Meta section
        for key, value in rule.get("meta", {}).items():
            if isinstance(value, str):
                lines.append(f'        {key} = "{value}"')
            elif isinstance(value, int):
                lines.append(f"        {key} = {value}")
            elif isinstance(value, bool):
                lines.append(f"        {key} = {str(value).lower()}")

        # Strings section
        if rule.get("strings"):
            lines.append("")
            lines.append("    strings:")
            for s in rule["strings"]:
                modifiers = " " + " ".join(s.get("modifiers", [])) if s.get("modifiers") else ""
                if s["type"] == "hash":
                    lines.append(f'        ${s["name"]} = "{s["value"]}"{modifiers}')
                else:
                    lines.append(f'        ${s["name"]} = "{s["value"]}"{modifiers}')

        # Condition section
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {rule['condition']}")

        lines.append("}")
        return "\n".join(lines)

    def to_rules_batch(self, rules: list[dict[str, Any]]) -> str:
        """Serialize multiple YARA rules to text.

        Args:
            rules: List of YARA rule dicts.

        Returns:
            YARA text with all rules.
        """
        return "\n\n".join(self.to_rule(r) for r in rules)

    def _make_combined_rule(
        self,
        ioc_type: str,
        iocs: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Create a combined YARA rule for multiple IOCs of the same type.

        Args:
            ioc_type: Type of IOCs.
            iocs: List of IOC dicts of the same type.

        Returns:
            Combined YARA rule dict or None.
        """
        if not iocs:
            return None

        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"combined-{ioc_type}"))
        rule_name = _sanitize_name(f"{self.prefix}_{ioc_type}_combined_{rule_id[:8]}")
        values = [ioc.get("value", "") for ioc in iocs if ioc.get("value")]

        if not values:
            return None

        rule: dict[str, Any] = {
            "name": rule_name,
            "meta": {
                "author": self.author,
                "date": _date_today(),
                "description": f"Combined detection for {len(values)} {ioc_type} indicators",
                "severity": self.default_severity,
                "score": SEVERITY_TO_SCORE.get(self.default_severity, 60),
                "ioc_type": ioc_type,
                "ioc_count": len(values),
            },
            "strings": [],
            "condition": "",
        }

        # Generate strings for each value
        conditions: list[str] = []
        for i, value in enumerate(values[:50]):  # Limit to 50 strings per rule
            string_name = f"$s{i}"
            if ioc_type in ("md5", "sha1", "sha256", "sha512"):
                rule["strings"].append({
                    "name": string_name,
                    "type": "hash",
                    "value": value,
                    "modifiers": [],
                })
            else:
                rule["strings"].append({
                    "name": string_name,
                    "type": "text",
                    "value": value,
                    "modifiers": ["ascii", "nocase"],
                })
            conditions.append(string_name)

        # Build condition
        if ioc_type in ("md5", "sha1", "sha256", "sha512"):
            rule["condition"] = f"uint16(0) == 0x5A4D and ({' or '.join(conditions)})"
        else:
            rule["condition"] = " or ".join(conditions)

        return rule
