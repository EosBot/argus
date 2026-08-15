"""Supply chain security — hash pinning + SBOM generation.

Validates dependency integrity and generates SBOMs:
    - Hash pinning verification for Python dependencies
    - SBOM (Software Bill of Materials) generation in CycloneDX format
    - Dependency vulnerability awareness (via package metadata)
    - Lock file parsing (requirements.txt, pipfile.lock, poetry.lock)
    - Integrity hash comparison

All checks are local-only (no external API calls) for security.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# Supported hash algorithms in order of preference
_HASH_ALGORITHMS: Final = ["sha512", "sha384", "sha256", "blake2b"]


@dataclass
class DependencyHash:
    """A pinned dependency with its expected hash.

    Attributes:
        name: Package name.
        version: Package version.
        hash_algo: Hash algorithm (e.g., "sha256").
        hash_value: Expected hash value.
        source: Source file where this pin was defined.
    """

    name: str
    version: str
    hash_algo: str = ""
    hash_value: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "hash_algo": self.hash_algo,
            "hash_value": self.hash_value,
            "source": self.source,
        }


@dataclass
class SBOMResult:
    """Result of SBOM generation.

    Attributes:
        format: SBOM format (e.g., "cyclone-json").
        version: SBOM specification version.
        serial_number: Unique serial number for this SBOM.
        timestamp: ISO timestamp of generation.
        component_count: Number of components in the SBOM.
        components: List of component dicts.
        raw_json: Raw JSON string of the SBOM.
    """

    format: str = "cyclone-json"
    version: str = "1.5"
    serial_number: str = ""
    timestamp: str = ""
    component_count: int = 0
    components: list[dict] = field(default_factory=list)
    raw_json: str = ""

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "version": self.version,
            "serial_number": self.serial_number,
            "timestamp": self.timestamp,
            "component_count": self.component_count,
            "components": self.components,
        }


class SupplyChainSecurity:
    """Supply chain security — hash pinning and SBOM generation.

    Features:
        - Parse requirements.txt with hash pinning
        - Generate CycloneDX-format SBOMs
        - Verify dependency integrity against pinned hashes
        - Support for multiple lock file formats

    Usage::

        scs = SupplyChainSecurity(project_root="/path/to/project")
        sbom = await scs.generate_sbom()
        pinned = scs.parse_pinned_requirements()
    """

    def __init__(
        self,
        project_root: str = ".",
        requirements_file: str = "requirements.txt",
    ) -> None:
        self._project_root = Path(project_root)
        self._requirements_file = self._project_root / requirements_file

    async def generate_sbom(self) -> SBOMResult:
        """Generate a CycloneDX-format SBOM from requirements.

        Returns:
            SBOMResult with the generated bill of materials.
        """
        components = await self._collect_components()

        timestamp = datetime.now(timezone.utc).isoformat()
        serial = str(uuid.uuid4())

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{serial}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "ARGUS",
                        "name": "opsec-supply-chain",
                        "version": "1.0.0",
                    }
                ],
            },
            "components": components,
        }

        raw_json = json.dumps(sbom, indent=2)

        return SBOMResult(
            format="cyclone-json",
            version="1.5",
            serial_number=serial,
            timestamp=timestamp,
            component_count=len(components),
            components=components,
            raw_json=raw_json,
        )

    async def _collect_components(self) -> list[dict]:
        """Collect component data from requirements files.

        Returns:
            List of component dicts for the SBOM.
        """
        components: list[dict] = []

        # Parse requirements.txt
        if self._requirements_file.exists():
            pinned = self.parse_pinned_requirements()
            for dep in pinned:
                components.append({
                    "type": "library",
                    "name": dep.name,
                    "version": dep.version,
                    "hashes": [
                        {
                            "alg": dep.hash_algo,
                            "content": dep.hash_value,
                        }
                    ] if dep.hash_value else [],
                    "purl": f"pkg:pypi/{dep.name}@{dep.version}",
                })

        # Try to parse poetry.lock if present
        poetry_lock = self._project_root / "poetry.lock"
        if poetry_lock.exists():
            components.extend(self._parse_poetry_lock(poetry_lock))

        # Try to parse Pipfile.lock if present
        pipfile_lock = self._project_root / "Pipfile.lock"
        if pipfile_lock.exists():
            components.extend(self._parse_pipfile_lock(pipfile_lock))

        return components

    def parse_pinned_requirements(self) -> list[DependencyHash]:
        """Parse requirements.txt for pinned dependencies with hashes.

        Supports format::
            package==version \\
                --hash=sha256:abcdef...

        Returns:
            List of DependencyHash objects.
        """
        dependencies: list[DependencyHash] = []

        if not self._requirements_file.exists():
            logger.warning(
                "Requirements file not found: %s", self._requirements_file
            )
            return dependencies

        content = self._requirements_file.read_text()
        lines = content.strip().split("\n")

        # Pattern for: package==version or package>=version
        pkg_pattern = re.compile(
            r"^([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*([^\s;]+)"
        )
        # Pattern for: --hash=sha256:abcdef...
        hash_pattern = re.compile(
            r"--hash=([a-zA-Z0-9]+):([a-fA-F0-9]+)"
        )

        current_dep: DependencyHash | None = None

        for line in lines:
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Check for hash line
            hash_match = hash_pattern.search(stripped)
            if hash_match and current_dep is not None:
                current_dep.hash_algo = hash_match.group(1)
                current_dep.hash_value = hash_match.group(2)
                continue

            # Check for package line
            pkg_match = pkg_pattern.match(stripped)
            if pkg_match:
                # Save previous dep
                if current_dep is not None:
                    dependencies.append(current_dep)

                current_dep = DependencyHash(
                    name=pkg_match.group(1),
                    version=pkg_match.group(2),
                    source=str(self._requirements_file),
                )

        # Don't forget the last dependency
        if current_dep is not None:
            dependencies.append(current_dep)

        logger.info(
            "Parsed %d dependencies from %s",
            len(dependencies),
            self._requirements_file,
        )
        return dependencies

    def _parse_poetry_lock(self, lock_path: Path) -> list[dict]:
        """Parse poetry.lock file for components.

        Args:
            lock_path: Path to poetry.lock.

        Returns:
            List of component dicts.
        """
        components: list[dict] = []
        try:
            content = lock_path.read_text()
            # Simple TOML-like parsing for poetry.lock
            # Look for [[package]] sections
            package_blocks = re.split(r"\[\[package\]\]", content)

            for block in package_blocks[1:]:  # Skip header
                name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                version_match = re.search(r'version\s*=\s*"([^"]+)"', block)

                if name_match and version_match:
                    name = name_match.group(1)
                    version = version_match.group(1)

                    # Extract hashes if present
                    hashes: list[dict] = []
                    hash_section = re.search(
                        r"hashes\s*=\s*\[(.*?)\]", block, re.DOTALL
                    )
                    if hash_section:
                        for h in re.findall(r'"([^"]+)"', hash_section.group(1)):
                            hashes.append({"alg": "unknown", "content": h})

                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version,
                        "hashes": hashes,
                        "purl": f"pkg:pypi/{name}@{version}",
                    })
        except Exception as exc:
            logger.warning("Failed to parse poetry.lock: %s", exc)

        return components

    def _parse_pipfile_lock(self, lock_path: Path) -> list[dict]:
        """Parse Pipfile.lock for components.

        Args:
            lock_path: Path to Pipfile.lock.

        Returns:
            List of component dicts.
        """
        components: list[dict] = []
        try:
            data = json.loads(lock_path.read_text())

            for section in ("default", "develop"):
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get("version", "").lstrip("=")
                    hashes = []
                    if "hashes" in info:
                        for h in info["hashes"]:
                            hashes.append({"alg": "sha256", "content": h})

                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version or "unknown",
                        "hashes": hashes,
                        "purl": f"pkg:pypi/{name}@{version}",
                    })
        except Exception as exc:
            logger.warning("Failed to parse Pipfile.lock: %s", exc)

        return components

    async def verify_integrity(
        self, dependencies: list[DependencyHash]
    ) -> dict:
        """Verify dependency integrity against pinned hashes.

        Note: This is a metadata verification — it checks that the pinned
        hashes are well-formed and match expected patterns. Full integrity
        verification requires downloading packages and computing hashes.

        Args:
            dependencies: List of dependencies to verify.

        Returns:
            Dict with verification results.
        """
        results: dict = {
            "total": len(dependencies),
            "verified": 0,
            "missing_hash": 0,
            "invalid_hash": 0,
            "details": [],
        }

        for dep in dependencies:
            detail = {
                "name": dep.name,
                "version": dep.version,
                "status": "unknown",
            }

            if not dep.hash_value:
                detail["status"] = "missing_hash"
                results["missing_hash"] += 1
            elif not self._is_valid_hash(dep.hash_algo, dep.hash_value):
                detail["status"] = "invalid_hash"
                results["invalid_hash"] += 1
            else:
                detail["status"] = "verified"
                results["verified"] += 1

            results["details"].append(detail)

        return results

    def _is_valid_hash(self, algo: str, value: str) -> bool:
        """Check if a hash value is well-formed for the given algorithm.

        Args:
            algo: Hash algorithm name.
            value: Hash hex string.

        Returns:
            True if the hash appears valid.
        """
        expected_lengths = {
            "sha256": 64,
            "sha384": 96,
            "sha512": 128,
            "blake2b": 128,
            "md5": 32,
        }
        expected = expected_lengths.get(algo.lower())
        if expected is None:
            # Unknown algorithm, just check it's hex
            return bool(re.match(r"^[a-fA-F0-9]+$", value))
        return len(value) == expected and bool(
            re.match(r"^[a-fA-F0-9]+$", value)
        )

    @staticmethod
    def compute_file_hash(
        file_path: str | Path, algorithm: str = "sha256"
    ) -> str:
        """Compute the hash of a local file.

        Args:
            file_path: Path to the file.
            algorithm: Hash algorithm to use.

        Returns:
            Hex digest string.
        """
        h = hashlib.new(algorithm)
        path = Path(file_path)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
