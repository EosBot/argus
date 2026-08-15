"""Threat intel dashboard — risk scores and severity aggregation.

Provides threat intelligence dashboard data with risk scoring,
severity distribution, and trend analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Finding, IOC, Investigation

logger = logging.getLogger(__name__)


class ThreatDashboard:
    """Generate threat intelligence dashboard data.

    Aggregates threat data from investigations, findings, and IOCs
    to produce risk scores and severity distributions for the dashboard.

    Usage::

        dashboard = ThreatDashboard(db_session)
        overview = await dashboard.get_overview()
        risk_scores = await dashboard.get_risk_scores()
        severity_dist = await dashboard.get_severity_distribution()
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with an async database session."""
        self._db = db

    async def get_overview(self) -> dict[str, Any]:
        """Get high-level threat overview statistics.

        Returns:
            Dict with total counts, active threats, and risk summary.
        """
        # Count investigations by status
        inv_result = await self._db.execute(
            select(Investigation.status, func.count(Investigation.id)).group_by(Investigation.status),
        )
        status_counts = dict(inv_result.all())

        # Count IOCs by severity
        ioc_result = await self._db.execute(
            select(IOC.severity, func.count(IOC.id)).group_by(IOC.severity),
        )
        ioc_severity = dict(ioc_result.all())

        # Count findings by severity
        finding_result = await self._db.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity),
        )
        finding_severity = dict(finding_result.all())

        # Calculate overall risk score (0-100)
        risk_score = self._calculate_risk_score(ioc_severity, finding_severity)

        return {
            "investigations": {
                "total": sum(status_counts.values()),
                "open": status_counts.get("open", 0),
                "in_progress": status_counts.get("in_progress", 0),
                "closed": status_counts.get("closed", 0),
            },
            "iocs": {
                "total": sum(ioc_severity.values()),
                "by_severity": ioc_severity,
            },
            "findings": {
                "total": sum(finding_severity.values()),
                "by_severity": finding_severity,
            },
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_risk_scores(self) -> list[dict[str, Any]]:
        """Calculate risk scores per investigation.

        Risk score is based on:
        - Number and severity of IOCs
        - Number and severity of findings
        - Investigation priority

        Returns:
            List of dicts with investigation ID, title, and risk score.
        """
        result = await self._db.execute(
            select(Investigation).where(Investigation.status.in_(["open", "in_progress"])),
        )
        investigations = result.scalars().all()

        scores: list[dict[str, Any]] = []
        for inv in investigations:
            # Count IOCs for this investigation
            ioc_result = await self._db.execute(
                select(func.count(IOC.id)).where(IOC.investigation_id == inv.id),
            )
            ioc_count = ioc_result.scalar_one()

            # Count high/critical IOCs
            critical_ioc_result = await self._db.execute(
                select(func.count(IOC.id)).where(
                    IOC.investigation_id == inv.id,
                    IOC.severity.in_(["high", "critical"]),
                ),
            )
            critical_iocs = critical_ioc_result.scalar_one()

            # Count findings
            finding_result = await self._db.execute(
                select(func.count(Finding.id)).where(Finding.investigation_id == inv.id),
            )
            finding_count = finding_result.scalar_one()

            # Calculate score
            score = self._investigation_risk_score(
                ioc_count, critical_iocs, finding_count, inv.priority,
            )

            scores.append({
                "investigation_id": inv.id,
                "title": inv.title,
                "priority": inv.priority,
                "risk_score": score,
                "risk_level": self._risk_level(score),
                "ioc_count": ioc_count,
                "critical_ioc_count": critical_iocs,
                "finding_count": finding_count,
            })

        # Sort by risk score descending
        scores.sort(key=lambda s: s["risk_score"], reverse=True)
        return scores

    async def get_severity_distribution(self) -> dict[str, Any]:
        """Get severity distribution across all threat data.

        Returns:
            Dict with severity counts for IOCs and findings,
            plus a combined distribution.
        """
        # IOC severity distribution
        ioc_result = await self._db.execute(
            select(IOC.severity, func.count(IOC.id)).group_by(IOC.severity),
        )
        ioc_dist = dict(ioc_result.all())

        # Finding severity distribution
        finding_result = await self._db.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity),
        )
        finding_dist = dict(finding_result.all())

        # IOC type distribution
        type_result = await self._db.execute(
            select(IOC.type, func.count(IOC.id)).group_by(IOC.type),
        )
        type_dist = dict(type_result.all())

        # Combined severity
        combined: dict[str, int] = {}
        for severity in ["low", "medium", "high", "critical"]:
            combined[severity] = ioc_dist.get(severity, 0) + finding_dist.get(severity, 0)

        return {
            "iocs_by_severity": ioc_dist,
            "findings_by_severity": finding_dist,
            "combined_severity": combined,
            "iocs_by_type": type_dist,
        }

    async def get_recent_threats(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent high-severity threats.

        Args:
            limit: Maximum number of threats to return.

        Returns:
            List of recent threat dicts sorted by severity and date.
        """
        # Get recent critical/high IOCs
        result = await self._db.execute(
            select(IOC)
            .where(IOC.severity.in_(["high", "critical"]))
            .order_by(IOC.created_at.desc())
            .limit(limit),
        )
        iocs = result.scalars().all()

        return [
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "severity": ioc.severity,
                "threat_type": ioc.threat_type,
                "source": ioc.source,
                "investigation_id": ioc.investigation_id,
                "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
            }
            for ioc in iocs
        ]

    async def get_threat_timeline(self, days: int = 30) -> list[dict[str, Any]]:
        """Get threat activity timeline for the last N days.

        Args:
            days: Number of days to look back.

        Returns:
            List of daily threat counts.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self._db.execute(
            select(
                func.date(IOC.created_at).label("date"),
                func.count(IOC.id).label("count"),
            )
            .where(IOC.created_at >= since)
            .group_by(func.date(IOC.created_at))
            .order_by("date"),
        )
        rows = result.all()

        return [
            {"date": str(row.date), "count": row.count}
            for row in rows
        ]

    @staticmethod
    def _calculate_risk_score(
        ioc_severity: dict[str, int],
        finding_severity: dict[str, int],
    ) -> int:
        """Calculate overall risk score (0-100) from severity distributions."""
        weights = {"low": 1, "medium": 3, "high": 6, "critical": 10}
        max_possible = 100

        score = 0
        for severity, count in ioc_severity.items():
            score += weights.get(severity, 1) * count
        for severity, count in finding_severity.items():
            score += weights.get(severity, 1) * count * 0.5

        # Normalize to 0-100 range (log scale for large numbers)
        import math
        if score > 0:
            normalized = min(int(10 * math.log2(1 + score)), max_possible)
        else:
            normalized = 0

        return normalized

    @staticmethod
    def _investigation_risk_score(
        ioc_count: int,
        critical_iocs: int,
        finding_count: int,
        priority: str,
    ) -> int:
        """Calculate risk score for a single investigation."""
        priority_weights = {"low": 1, "medium": 2, "high": 4, "critical": 8}
        priority_mult = priority_weights.get(priority, 2)

        raw_score = (ioc_count * 2 + critical_iocs * 10 + finding_count * 3) * priority_mult

        import math
        return min(int(10 * math.log2(1 + raw_score)), 100) if raw_score > 0 else 0

    @staticmethod
    def _risk_level(score: int) -> str:
        """Convert numeric risk score to level label."""
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"
