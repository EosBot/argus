"""InfrastructureMapper agent — network infrastructure scanning.

Wraps argus_engine/pentest/scanner.py (nmap, nuclei, subfinder, sslyze, wafw00f,
whatweb, dnsrecon, gitleaks, trivy).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent

logger = logging.getLogger(__name__)


class InfrastructureMapper(BaseAgent):
    """Infrastructure mapping and vulnerability scanning agent.

    Runs nmap, nuclei, subfinder, and other pentest tools against
    targets for infrastructure reconnaissance.
    """

    name = "infrastructure_mapper"
    description = "Infrastructure mapping — port scanning (nmap), vulnerability scanning (nuclei), subdomain enumeration (subfinder)"
    capabilities = [
        "port_scanning",
        "vulnerability_scanning",
        "subdomain_enumeration",
        "ssl_analysis",
        "waf_detection",
        "technology_fingerprinting",
        "dns_reconnaissance",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute infrastructure mapping.

        Task dict keys:
            - target (str): Target host/domain to scan (required)
            - tools (list): Tool names to run (default: ["nmap", "subfinder"])
            - options (dict): Tool-specific options
            - authorized (bool): Authorization confirmation (default: false)

        Returns:
            dict with keys: target, results (list), total_tools, successful
        """
        start = time.monotonic()
        target = task.get("target", "")
        if not target:
            return self._error_result("Missing required 'target' parameter")

        tools = task.get("tools", ["nmap", "subfinder"])
        options = task.get("options", {})
        authorized = task.get("authorized", False)

        result: dict[str, Any] = {
            "agent_name": self.name,
            "target": target,
            "results": [],
        }

        loop = asyncio.get_event_loop()

        # Run scans via argus_engine/pentest/scanner.py
        scan_data = await loop.run_in_executor(
            None, self._run_scans, target, tools, options, authorized
        )
        result["results"] = scan_data.get("results", [])
        result["total_tools"] = scan_data.get("total_tools", 0)
        result["successful"] = scan_data.get("successful", 0)
        result["scan_status"] = scan_data.get("status", "unknown")

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _run_scans(
        self,
        target: str,
        tools: list[str],
        options: dict[str, Any],
        authorized: bool,
    ) -> dict[str, Any]:
        """Run pentest scans via argus_engine/pentest/scanner.py."""
        try:
            from argus_engine.pentest.scanner import PentestScanner

            scanner = PentestScanner()
            opts = {**options, "authorized": authorized}

            results = []
            for tool_name in tools:
                scan_result = scanner.run_scan(tool_name, target, opts)
                scan_result["tool_name"] = tool_name
                results.append(scan_result)

            successful = sum(1 for r in results if r.get("success", False))

            return {
                "status": "completed",
                "results": results,
                "total_tools": len(results),
                "successful": successful,
            }
        except ImportError:
            logger.warning("argus_engine.pentest.scanner not available")
            return {
                "status": "degraded",
                "results": [],
                "total_tools": 0,
                "successful": 0,
                "error": "PentestScanner not available",
            }
        except Exception as exc:
            logger.exception("Infrastructure scan failed")
            return {
                "status": "failed",
                "results": [],
                "total_tools": 0,
                "successful": 0,
                "error": str(exc),
            }

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "results": [],
        }
