"""IOC package export — bundled IOC packages in multiple formats.

Creates comprehensive IOC packages combining STIX, MISP, YARA, and
Sigma formats into a single export bundle for threat intelligence
sharing.

Usage::

    exporter = IOCPackageExporter()
    package = exporter.create_package(investigation, findings, iocs)
    zip_bytes = exporter.to_zip(package)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.export.stix_export import STIXExporter
from backend.export.misp_export import MISPExporter
from backend.export.sigma_export import SigmaExporter
from backend.export.yara_export import YARAExporter
from backend.export.csv_json_export import CSVJSONExporter

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return current UTC time in ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


class IOCPackageExporter:
    """Creates comprehensive IOC packages in multiple formats.

    Bundles IOCs into a unified package containing:
        - STIX 2.1 bundle (stix.json)
        - MISP event (misp.json)
        - Sigma rules (sigma_rules.yaml)
        - YARA rules (yara_rules.yar)
        - CSV export (iocs.csv)
        - JSON export (iocs.json)
        - Package manifest (manifest.json)

    Usage::

        exporter = IOCPackageExporter()
        package = exporter.create_package(inv, findings, iocs)
        zip_data = exporter.to_zip(package)
    """

    def __init__(
        self,
        org_name: str = "ARGUS CTI",
        tlp_level: str = "amber",
    ) -> None:
        """Initialize IOC package exporter.

        Args:
            org_name: Organization name for metadata.
            tlp_level: TLP marking level.
        """
        self.org_name = org_name
        self.tlp_level = tlp_level
        self._stix = STIXExporter(org_name=org_name, tlp_level=tlp_level)
        self._misp = MISPExporter(org_name=org_name)
        self._sigma = SigmaExporter(author=org_name)
        self._yara = YARAExporter(author=org_name)
        self._csv_json = CSVJSONExporter()

    def create_package(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Create a complete IOC package.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            Package dict with format keys mapping to content.
        """
        findings = findings or []
        iocs = iocs or []

        package: dict[str, Any] = {
            "manifest": self._create_manifest(investigation, findings, iocs),
            "stix.json": "",
            "misp.json": "",
            "sigma_rules.yaml": "",
            "yara_rules.yar": "",
            "iocs.csv": "",
            "iocs.json": "",
            "findings.json": "",
        }

        # Generate STIX bundle
        try:
            stix_bundle = self._stix.from_investigation(investigation, findings, iocs)
            package["stix.json"] = self._stix.to_json(stix_bundle)
        except Exception as exc:
            logger.warning("STIX generation failed: %s", exc)
            package["stix.json"] = json.dumps({"error": str(exc)})

        # Generate MISP event
        try:
            misp_event = self._misp.from_investigation(investigation, findings, iocs)
            package["misp.json"] = self._misp.to_json(misp_event)
        except Exception as exc:
            logger.warning("MISP generation failed: %s", exc)
            package["misp.json"] = json.dumps({"error": str(exc)})

        # Generate Sigma rules
        try:
            sigma_rules = self._sigma.from_investigation(investigation, iocs)
            package["sigma_rules.yaml"] = self._sigma.to_yaml_batch(sigma_rules)
        except Exception as exc:
            logger.warning("Sigma generation failed: %s", exc)
            package["sigma_rules.yaml"] = f"# Error: {exc}"

        # Generate YARA rules
        try:
            yara_rules = self._yara.from_investigation(investigation, iocs)
            package["yara_rules.yar"] = self._yara.to_rules_batch(yara_rules)
        except Exception as exc:
            logger.warning("YARA generation failed: %s", exc)
            package["yara_rules.yar"] = f"// Error: {exc}"

        # Generate CSV/JSON exports
        try:
            package["iocs.csv"] = self._csv_json.iocs_to_csv(iocs)
            package["iocs.json"] = self._csv_json.iocs_to_json(iocs)
            package["findings.json"] = self._csv_json.findings_to_json(findings)
        except Exception as exc:
            logger.warning("CSV/JSON generation failed: %s", exc)

        logger.info(
            "IOC package created: %d IOCs, %d findings, %d formats",
            len(iocs), len(findings),
            sum(1 for v in package.values() if v and v != ""),
        )
        return package

    def to_zip(self, package: dict[str, Any]) -> bytes:
        """Convert package to ZIP archive bytes.

        Args:
            package: Package dict with format keys.

        Returns:
            ZIP archive as bytes.
        """
        import zipfile
        from io import BytesIO

        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for filename, content in package.items():
                if isinstance(content, str) and content:
                    zf.writestr(filename, content.encode("utf-8"))
                elif isinstance(content, dict):
                    zf.writestr(
                        filename,
                        json.dumps(content, indent=2, default=str).encode("utf-8"),
                    )

        return buffer.getvalue()

    def to_dict(self, package: dict[str, Any]) -> dict[str, Any]:
        """Return package as a dict (for JSON serialization).

        Args:
            package: Package dict.

        Returns:
            Package dict with all string values.
        """
        result: dict[str, Any] = {}
        for key, value in package.items():
            if isinstance(value, str):
                result[key] = value
            elif isinstance(value, dict):
                result[key] = value
            else:
                result[key] = str(value)
        return result

    def _create_manifest(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Create package manifest.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            Manifest dict.
        """
        # Count IOCs by type
        ioc_types: dict[str, int] = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1

        return {
            "package_id": str(uuid.uuid4()),
            "package_type": "ARGUS IOC Package",
            "version": "1.0",
            "created_at": _now_iso(),
            "organization": self.org_name,
            "classification": f"TLP:{self.tlp_level.upper()}",
            "investigation": {
                "id": investigation.get("id", ""),
                "title": investigation.get("title", ""),
                "description": investigation.get("description", ""),
            },
            "contents": {
                "ioc_count": len(iocs),
                "finding_count": len(findings),
                "ioc_types": ioc_types,
                "formats": [
                    "stix.json",
                    "misp.json",
                    "sigma_rules.yaml",
                    "yara_rules.yar",
                    "iocs.csv",
                    "iocs.json",
                    "findings.json",
                ],
            },
        }
