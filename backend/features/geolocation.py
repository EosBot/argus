"""Geolocation map + heatmap — map coordinates from IPs found in investigations.

Wraps ARGUS's GeoLocator to provide map visualization data including
scatter geo plots and heatmap data for IP locations.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import select

from argus_engine.intel.geolocate import GeoLocator

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="geo")


class GeoMapService:
    """Generate map and heatmap data from investigation IPs.

    Uses ARGUS's GeoLocator to resolve IPs to coordinates and
    produces plotly-compatible map data structures.

    Usage::

        service = GeoMapService()
        map_data = await service.get_map_data(["8.8.8.8", "1.1.1.1"])
        heatmap = await service.get_heatmap_data(investigation_id, db_session)
    """

    def __init__(
        self,
        ipinfo_token: str | None = None,
        shodan_api_key: str | None = None,
    ) -> None:
        """Initialize the geolocation service.

        Args:
            ipinfo_token: Optional IPinfo.io API token.
            shodan_api_key: Optional Shodan API key.
        """
        self._ipinfo_token = ipinfo_token
        self._shodan_api_key = shodan_api_key
        self._locator: GeoLocator | None = None

    async def geolocate_ips(self, ips: list[str]) -> list[dict[str, Any]]:
        """Geolocate a list of IP addresses.

        Args:
            ips: List of IP address strings.

        Returns:
            List of geolocation result dicts with coordinates.
        """
        loop = asyncio.get_running_loop()

        def _geolocate() -> list[dict[str, Any]]:
            self._locator = GeoLocator(
                ipinfo_token=self._ipinfo_token,
                shodan_api_key=self._shodan_api_key,
            )
            results = []
            for ip in ips:
                info = self._locator.geolocate_ip(ip)
                if info and info.get("loc"):
                    results.append(info)
            return results

        logger.info("Geolocating %d IPs", len(ips))
        results = await loop.run_in_executor(_executor, _geolocate)
        logger.info("Geolocation complete: %d/%d resolved", len(results), len(ips))
        return results

    async def get_map_data(self, ips: list[str]) -> dict[str, Any]:
        """Generate plotly scattergeo data for a list of IPs.

        Args:
            ips: List of IP address strings.

        Returns:
            Plotly-compatible scattergeo data structure.
        """
        loop = asyncio.get_running_loop()

        def _build_map() -> dict[str, Any]:
            self._locator = GeoLocator(
                ipinfo_token=self._ipinfo_token,
                shodan_api_key=self._shodan_api_key,
            )
            locations = []
            for ip in ips:
                info = self._locator.geolocate_ip(ip)
                if info and info.get("latitude") and info.get("longitude"):
                    locations.append({
                        "lat": info["latitude"],
                        "lon": info["longitude"],
                        "label": ip,
                        "text": f"{ip}<br>{info.get('city', 'N/A')}, {info.get('country', 'N/A')}<br>{info.get('org', 'N/A')}",
                        "color": self._country_color(info.get("country", "")),
                        "size": 12,
                    })
            return self._locator.to_map_data(locations)

        return await loop.run_in_executor(_executor, _build_map)

    async def get_heatmap_data(
        self,
        investigation_id: str,
        db: Any,
    ) -> dict[str, Any]:
        """Generate heatmap data for all IPs in an investigation.

        Queries the database for IP-type IOCs belonging to the
        investigation and produces heatmap coordinates.

        Args:
            investigation_id: Investigation UUID.
            db: Async SQLAlchemy session.

        Returns:
            Heatmap data structure with coordinates and intensity.
        """
        from backend.db.models import IOC

        result = await db.execute(
            select(IOC).where(
                IOC.investigation_id == investigation_id,
                IOC.type == "ip",
            ),
        )
        iocs = result.scalars().all()
        ips = [ioc.value for ioc in iocs]

        if not ips:
            return {"lat": [], "lon": [], "intensity": [], "type": "heatmap"}

        geo_data = await self.geolocate_ips(ips)

        lats: list[float] = []
        lons: list[float] = []
        intensities: list[float] = []

        for geo in geo_data:
            lat = geo.get("latitude")
            lon = geo.get("longitude")
            if lat is not None and lon is not None:
                lats.append(lat)
                lons.append(lon)
                # Intensity based on severity of the IOC
                severity = geo.get("severity", "medium")
                intensity_map = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
                intensities.append(intensity_map.get(severity, 0.5))

        return {
            "lat": lats,
            "lon": lons,
            "intensity": intensities,
            "type": "heatmap",
            "total_ips": len(ips),
            "resolved_ips": len(lats),
        }

    async def get_infrastructure_map(
        self,
        investigation_id: str,
        db: Any,
    ) -> dict[str, Any]:
        """Get full infrastructure map with IPs, domains, and subdomains.

        Args:
            investigation_id: Investigation UUID.
            db: Async SQLAlchemy session.

        Returns:
            Map data with all infrastructure markers.
        """
        from backend.db.models import IOC

        result = await db.execute(
            select(IOC).where(IOC.investigation_id == investigation_id),
        )
        iocs = result.scalars().all()

        ips = [ioc.value for ioc in iocs if ioc.type == "ip"]
        domains = [ioc.value for ioc in iocs if ioc.type == "domain"]

        # Geolocate IPs
        ip_map_data = await self.get_map_data(ips) if ips else {"lat": [], "lon": [], "text": []}

        # Discover subdomains for domains (limited to first 5 for performance)
        subdomain_results: list[dict[str, Any]] = []
        for domain in domains[:5]:
            subs = await self._discover_subdomains(domain)
            if subs:
                subdomain_results.append({
                    "domain": domain,
                    "subdomains": subs[:50],  # Limit for response
                    "count": len(subs),
                })

        return {
            "ip_map": ip_map_data,
            "domains": subdomain_results,
            "total_ips": len(ips),
            "total_domains": len(domains),
        }

    async def _discover_subdomains(self, domain: str) -> list[str]:
        """Discover subdomains for a domain via crt.sh.

        Args:
            domain: Root domain.

        Returns:
            List of subdomain strings.
        """
        loop = asyncio.get_running_loop()

        def _discover() -> list[str]:
            self._locator = GeoLocator(
                ipinfo_token=self._ipinfo_token,
                shodan_api_key=self._shodan_api_key,
            )
            return self._locator.discover_subdomains(domain)

        return await loop.run_in_executor(_executor, _discover)

    @staticmethod
    def _country_color(country_code: str) -> str:
        """Assign a consistent color per country for map visualization."""
        # Hash the country code to a consistent color
        import hashlib
        if not country_code:
            return "#95A5A6"
        hash_val = int(hashlib.md5(country_code.encode()).hexdigest()[:6], 16)
        r = (hash_val >> 16) & 0xFF
        g = (hash_val >> 8) & 0xFF
        b = hash_val & 0xFF
        # Ensure reasonable brightness
        r = max(80, min(r, 200))
        g = max(80, min(g, 200))
        b = max(80, min(b, 200))
        return f"#{r:02x}{g:02x}{b:02x}"

    @staticmethod
    def shutdown() -> None:
        """Shutdown the thread pool executor."""
        _executor.shutdown(wait=False)
