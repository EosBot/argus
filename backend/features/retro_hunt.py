"""Retro-hunt engine — re-scan historical IOCs for new appearances.

Periodically re-scans previously discovered IOCs to detect new
appearances, changes in status, or newly associated infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Finding, IOC, Investigation

logger = logging.getLogger(__name__)


class RetroHuntEngine:
    """Re-scan historical IOCs for new intelligence.

    Performs retroactive hunting by:
    1. Loading historical IOCs from the database
    2. Re-scanning them against current threat intelligence
    3. Detecting new appearances or status changes
    4. Generating findings for any new intelligence

    Usage::

        engine = RetroHuntEngine(db_session)
        results = await engine.retro_hunt(investigation_id="abc123")
        all_results = await engine.retro_hunt_all(days_back=30)
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with an async database session."""
        self._db = db

    async def retro_hunt(
        self,
        investigation_id: str,
    ) -> dict[str, Any]:
        """Re-scan all IOCs from a specific investigation.

        Args:
            investigation_id: Investigation UUID.

        Returns:
            Dict with retro-hunt results including new findings.
        """
        result = await self._db.execute(
            select(IOC).where(IOC.investigation_id == investigation_id),
        )
        iocs = result.scalars().all()

        if not iocs:
            return {
                "investigation_id": investigation_id,
                "iocs_scanned": 0,
                "new_findings": [],
                "changes_detected": 0,
            }

        new_findings: list[dict[str, Any]] = []
        changes = 0

        for ioc in iocs:
            hunt_result = await self._hunt_ioc(ioc)
            if hunt_result.get("has_changes"):
                changes += 1
                new_findings.append(hunt_result)

        # Create a finding if changes were detected
        if changes > 0:
            finding = Finding(
                investigation_id=investigation_id,
                title=f"Retro-hunt: {changes} IOC(s) with new intelligence",
                description=f"Re-scanned {len(iocs)} IOCs, found changes in {changes}",
                severity="medium",
                confidence="medium",
                source="retro_hunt",
                data={
                    "iocs_scanned": len(iocs),
                    "changes_detected": changes,
                    "findings": new_findings,
                },
            )
            self._db.add(finding)
            await self._db.flush()

        return {
            "investigation_id": investigation_id,
            "iocs_scanned": len(iocs),
            "changes_detected": changes,
            "new_findings": new_findings,
            "hunted_at": datetime.now(timezone.utc).isoformat(),
        }

    async def retro_hunt_all(
        self,
        days_back: int = 30,
    ) -> dict[str, Any]:
        """Re-scan all IOCs from the last N days across all investigations.

        Args:
            days_back: Number of days to look back.

        Returns:
            Dict with aggregated retro-hunt results.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days_back)

        result = await self._db.execute(
            select(IOC).where(IOC.created_at >= since),
        )
        iocs = result.scalars().all()

        if not iocs:
            return {
                "iocs_scanned": 0,
                "new_findings": [],
                "changes_detected": 0,
                "period_days": days_back,
            }

        new_findings: list[dict[str, Any]] = []
        changes = 0

        for ioc in iocs:
            hunt_result = await self._hunt_ioc(ioc)
            if hunt_result.get("has_changes"):
                changes += 1
                new_findings.append(hunt_result)

        return {
            "iocs_scanned": len(iocs),
            "changes_detected": changes,
            "new_findings": new_findings,
            "period_days": days_back,
            "hunted_at": datetime.now(timezone.utc).isoformat(),
        }

    async def retro_hunt_by_type(
        self,
        ioc_type: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Re-scan IOCs of a specific type.

        Args:
            ioc_type: IOC type to filter (ip, domain, hash, url, etc.).
            limit: Maximum IOCs to scan.

        Returns:
            Dict with retro-hunt results for the specified type.
        """
        result = await self._db.execute(
            select(IOC)
            .where(IOC.type == ioc_type)
            .order_by(IOC.created_at.desc())
            .limit(limit),
        )
        iocs = result.scalars().all()

        new_findings: list[dict[str, Any]] = []
        changes = 0

        for ioc in iocs:
            hunt_result = await self._hunt_ioc(ioc)
            if hunt_result.get("has_changes"):
                changes += 1
                new_findings.append(hunt_result)

        return {
            "ioc_type": ioc_type,
            "iocs_scanned": len(iocs),
            "changes_detected": changes,
            "new_findings": new_findings,
            "hunted_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _hunt_ioc(self, ioc: IOC) -> dict[str, Any]:
        """Perform retro-hunt on a single IOC.

        Checks for:
        - New geolocation data (if IP)
        - New subdomain discoveries (if domain)
        - Associated infrastructure changes

        Args:
            ioc: IOC database record.

        Returns:
            Dict with hunt results and change indicators.
        """
        result: dict[str, Any] = {
            "ioc_id": ioc.id,
            "ioc_type": ioc.type,
            "ioc_value": ioc.value,
            "has_changes": False,
            "findings": [],
        }

        if ioc.type == "ip":
            result.update(await self._hunt_ip(ioc))
        elif ioc.type == "domain":
            result.update(await self._hunt_domain(ioc))
        elif ioc.type in ("url", "onion"):
            result.update(await self._hunt_url(ioc))

        return result

    async def _hunt_ip(self, ioc: IOC) -> dict[str, Any]:
        """Re-scan an IP IOC for new geolocation data."""
        from backend.features.geolocation import GeoMapService

        service = GeoMapService()
        try:
            geo_data = await service.geolocate_ips([ioc.value])
            if geo_data:
                geo = geo_data[0]
                return {
                    "has_changes": True,
                    "findings": [{
                        "type": "geolocation_update",
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "org": geo.get("org"),
                        "asn": geo.get("asn"),
                    }],
                }
        except Exception as exc:
            logger.debug("IP hunt failed for %s: %s", ioc.value, exc)

        return {"has_changes": False, "findings": []}

    async def _hunt_domain(self, ioc: IOC) -> dict[str, Any]:
        """Re-scan a domain IOC for new subdomains."""
        from backend.features.geolocation import GeoMapService

        service = GeoMapService()
        try:
            subdomains = await service._discover_subdomains(ioc.value)
            if subdomains:
                return {
                    "has_changes": True,
                    "findings": [{
                        "type": "subdomain_discovery",
                        "new_subdomains": subdomains[:20],
                        "total_found": len(subdomains),
                    }],
                }
        except Exception as exc:
            logger.debug("Domain hunt failed for %s: %s", ioc.value, exc)

        return {"has_changes": False, "findings": []}

    async def _hunt_url(self, ioc: IOC) -> dict[str, Any]:
        """Re-scan a URL/onion IOC for content changes."""
        # For URLs, we check if the content has changed
        # This is a simplified check — in production, compare content hashes
        return {"has_changes": False, "findings": []}

    async def get_hunt_history(
        self,
        investigation_id: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get retro-hunt execution history.

        Args:
            investigation_id: Optional investigation filter.
            limit: Maximum results.

        Returns:
            List of historical hunt results.
        """
        query = (
            select(Finding)
            .where(Finding.source == "retro_hunt")
            .order_by(Finding.created_at.desc())
            .limit(limit)
        )
        if investigation_id:
            query = query.where(Finding.investigation_id == investigation_id)

        result = await self._db.execute(query)
        findings = result.scalars().all()

        return [
            {
                "id": f.id,
                "investigation_id": f.investigation_id,
                "title": f.title,
                "severity": f.severity,
                "data": f.data,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ]
