"""Attack surface visualization — aggregate pentest results.

Aggregates penetration test results (ports, services, vulnerabilities)
to produce attack surface metrics and visualization data.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Finding, Investigation

logger = logging.getLogger(__name__)


class AttackSurfaceAggregator:
    """Aggregate and analyze attack surface data from pentest results.

    Processes findings from penetration tests to produce:
    - Open port statistics
    - Service inventory
    - Vulnerability summary
    - Risk heatmap data

    Usage::

        aggregator = AttackSurfaceAggregator(db_session)
        surface = await aggregator.get_attack_surface(investigation_id)
        summary = await aggregator.get_network_summary()
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with an async database session."""
        self._db = db

    async def get_attack_surface(
        self,
        investigation_id: str,
    ) -> dict[str, Any]:
        """Get attack surface data for a specific investigation.

        Args:
            investigation_id: Investigation UUID.

        Returns:
            Dict with ports, services, and vulnerabilities found.
        """
        result = await self._db.execute(
            select(Finding).where(
                Finding.investigation_id == investigation_id,
                Finding.source.in_(["pentest", "robin_pipeline", "nmap_scan"]),
            ),
        )
        findings = result.scalars().all()

        ports: list[dict[str, Any]] = []
        services: dict[str, int] = {}
        vulnerabilities: list[dict[str, Any]] = []

        for finding in findings:
            data = finding.data or {}
            # Extract port data
            if "ports" in data:
                for port_info in data["ports"]:
                    if isinstance(port_info, dict):
                        ports.append(port_info)
                        svc = port_info.get("service", "unknown")
                        services[svc] = services.get(svc, 0) + 1

            # Extract service data
            if "service" in data:
                svc = data["service"]
                services[svc] = services.get(svc, 0) + 1

            # Extract vulnerability data
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    if isinstance(vuln, dict):
                        vulnerabilities.append(vuln)
            elif finding.title and "vuln" in finding.title.lower():
                vulnerabilities.append({
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                })

        return {
            "investigation_id": investigation_id,
            "total_ports": len(ports),
            "open_ports": ports[:100],  # Limit for response size
            "services": [{"name": k, "count": v} for k, v in sorted(services.items())],
            "vulnerabilities": vulnerabilities,
            "vuln_count": len(vulnerabilities),
            "critical_vulns": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
            "high_vulns": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
        }

    async def get_network_summary(self) -> dict[str, Any]:
        """Get network-wide attack surface summary across all investigations.

        Returns:
            Dict with aggregated network exposure metrics.
        """
        # Get all pentest-related findings
        result = await self._db.execute(
            select(Finding).where(
                Finding.source.in_(["pentest", "robin_pipeline", "nmap_scan"]),
            ),
        )
        findings = result.scalars().all()

        all_ports: set[int] = set()
        all_services: dict[str, int] = {}
        all_vulns: list[dict[str, Any]] = []

        for finding in findings:
            data = finding.data or {}
            if "ports" in data:
                for port_info in data["ports"]:
                    if isinstance(port_info, dict):
                        port_num = port_info.get("port")
                        if port_num:
                            try:
                                all_ports.add(int(port_num))
                            except (ValueError, TypeError):
                                pass
                        svc = port_info.get("service", "unknown")
                        all_services[svc] = all_services.get(svc, 0) + 1

            if "vulnerabilities" in data:
                all_vulns.extend(
                    v for v in data["vulnerabilities"]
                    if isinstance(v, dict)
                )

        # Calculate exposure score
        exposure_score = min(len(all_ports) * 2 + len(all_vulns) * 5, 100)

        return {
            "total_open_ports": len(all_ports),
            "unique_services": len(all_services),
            "top_services": sorted(
                [{"name": k, "count": v} for k, v in all_services.items()],
                key=lambda s: s["count"],
                reverse=True,
            )[:20],
            "total_vulnerabilities": len(all_vulns),
            "critical_count": sum(1 for v in all_vulns if v.get("severity") == "critical"),
            "high_count": sum(1 for v in all_vulns if v.get("severity") == "high"),
            "medium_count": sum(1 for v in all_vulns if v.get("severity") == "medium"),
            "low_count": sum(1 for v in all_vulns if v.get("severity") == "low"),
            "exposure_score": exposure_score,
            "risk_level": self._exposure_level(exposure_score),
        }

    async def get_port_distribution(self) -> list[dict[str, Any]]:
        """Get port distribution across all pentest findings.

        Returns:
            List of port usage counts sorted by frequency.
        """
        result = await self._db.execute(
            select(Finding).where(
                Finding.source.in_(["pentest", "robin_pipeline", "nmap_scan"]),
            ),
        )
        findings = result.scalars().all()

        port_counts: dict[int, int] = {}
        for finding in findings:
            data = finding.data or {}
            if "ports" in data:
                for port_info in data["ports"]:
                    if isinstance(port_info, dict):
                        port_num = port_info.get("port")
                        if port_num:
                            try:
                                pn = int(port_num)
                                port_counts[pn] = port_counts.get(pn, 0) + 1
                            except (ValueError, TypeError):
                                pass

        return [
            {"port": port, "count": count}
            for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        ]

    async def get_vulnerability_trends(self, days: int = 30) -> list[dict[str, Any]]:
        """Get vulnerability discovery trends over time.

        Args:
            days: Number of days to analyze.

        Returns:
            List of daily vulnerability counts.
        """
        from datetime import datetime, timedelta, timezone

        since = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self._db.execute(
            select(
                func.date(Finding.created_at).label("date"),
                func.count(Finding.id).label("count"),
            )
            .where(
                Finding.created_at >= since,
                Finding.severity.in_(["high", "critical"]),
            )
            .group_by(func.date(Finding.created_at))
            .order_by("date"),
        )
        rows = result.all()

        return [
            {"date": str(row.date), "count": row.count}
            for row in rows
        ]

    @staticmethod
    def _exposure_level(score: int) -> str:
        """Convert exposure score to risk level."""
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"
