"""ForensicAnalyst agent — IOC extraction + geolocation.

Wraps argus_engine/intel/ioc_extractor.py (IOC extraction) and
argus_engine/intel/geolocate.py (IP geolocation, subdomain discovery).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent
from backend.agents.context import evidence_text
from backend.core.config import settings

logger = logging.getLogger(__name__)


class ForensicAnalyst(BaseAgent):
    """Digital forensics agent — IOC extraction and geolocation.

    Extracts indicators of compromise from text (URLs, IPs, domains,
    hashes, emails, CVEs, wallets, PGP keys) and geolocates IPs.
    """

    name = "forensic_analyst"
    description = "Digital forensics — extracts IOCs from text, geolocates IPs, discovers subdomains"
    capabilities = [
        "ioc_extraction",
        "ip_geolocation",
        "subdomain_discovery",
        "threat_analysis",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute forensic analysis.

        Task dict keys:
            - text (str): Text to analyze for IOCs (required)
            - url (str): URL to fetch and analyze (alternative to text)
            - geolocate (bool): Whether to geolocate extracted IPs (default: true)
            - discover_subdomains (bool): Whether to find subdomains (default: false)

        Returns:
            dict with keys: iocs (dict), geolocation (list), subdomains (dict)
        """
        start = time.monotonic()
        text = evidence_text(task)
        url = task.get("url", "")
        geolocate = task.get("geolocate", True)
        discover_subdomains = task.get("discover_subdomains", False)

        if not text and not url:
            return self._error_result("Missing required 'text' or 'url' parameter")

        result: dict[str, Any] = {
            "agent_name": self.name,
            "iocs": {},
            "geolocation": [],
            "subdomains": {},
        }

        loop = asyncio.get_event_loop()

        # Step 1: Extract IOCs
        ioc_data = await loop.run_in_executor(
            None, self._extract_iocs, text, url
        )
        result["iocs"] = ioc_data.get("iocs", {})
        result["ioc_status"] = ioc_data.get("status", "unknown")

        # Step 2: Geolocate IPs
        if geolocate:
            ipv4_list = result["iocs"].get("ipv4", [])
            ipv6_list = result["iocs"].get("ipv6", [])
            if ipv4_list or ipv6_list:
                geo_data = await loop.run_in_executor(
                    None, self._geolocate_ips, ipv4_list, ipv6_list
                )
                result["geolocation"] = geo_data

        # Step 3: Discover subdomains
        if discover_subdomains:
            domains = result["iocs"].get("domains", [])
            if domains:
                sub_data = await loop.run_in_executor(
                    None, self._discover_subdomains, domains
                )
                result["subdomains"] = sub_data

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _extract_iocs(self, text: str, url: str) -> dict[str, Any]:
        """Extract IOCs via argus_engine/intel/ioc_extractor.py."""
        try:
            from argus_engine.intel.ioc_extractor import IOCExtractor

            extractor = IOCExtractor()
            if url:
                iocs = extractor.extract_from_url(url)
            else:
                iocs = extractor.extract(text)
            return {"status": "completed", "iocs": iocs}
        except ImportError:
            logger.warning("argus_engine.intel.ioc_extractor not available")
            return {"status": "degraded", "iocs": {}, "error": "IOCExtractor not available"}
        except Exception as exc:
            logger.exception("IOC extraction failed")
            return {"status": "failed", "iocs": {}, "error": str(exc)}

    def _geolocate_ips(self, ipv4_list: list[str], ipv6_list: list[str]) -> list[dict]:
        """Geolocate IPs via argus_engine/intel/geolocate.py."""
        try:
            from argus_engine.intel.geolocate import GeoLocator

            locator = GeoLocator(proxy_url=settings.tor_proxy)
            results = []
            for ip in ipv4_list + ipv6_list:
                info = locator.geolocate_ip(ip)
                if info:
                    results.append(info)
            return results
        except ImportError:
            logger.warning("argus_engine.intel.geolocate not available")
            return []
        except Exception as exc:
            logger.exception("Geolocation failed")
            return []

    def _discover_subdomains(self, domains: list[str]) -> dict[str, list[str]]:
        """Discover subdomains via argus_engine/intel/geolocate.py."""
        try:
            from argus_engine.intel.geolocate import GeoLocator

            locator = GeoLocator(proxy_url=settings.tor_proxy)
            results = {}
            for domain in domains[:5]:  # Limit to 5 domains
                subs = locator.discover_subdomains(domain)
                if subs:
                    results[domain] = subs
            return results
        except ImportError:
            logger.warning("argus_engine.intel.geolocate not available")
            return {}
        except Exception as exc:
            logger.exception("Subdomain discovery failed")
            return {}

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "iocs": {},
            "geolocation": [],
            "subdomains": {},
        }
