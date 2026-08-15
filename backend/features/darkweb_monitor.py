"""Dark web monitoring — onion status, scheduled scans, alerts.

Provides dark web monitoring dashboard data including onion link status,
scan scheduling, and alert management.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OnionStatus:
    """Status of a monitored onion service."""
    url: str
    is_online: bool
    last_checked: str | None = None
    response_time_ms: int | None = None
    status_code: int | None = None
    category: str = "UNKNOWN"
    alert_triggered: bool = False


@dataclass(frozen=True, slots=True)
class DarkWebAlert:
    """Alert generated from dark web monitoring."""
    id: str
    onion_url: str
    alert_type: str  # offline, content_change, new_content, keyword_match
    severity: str  # low, medium, high, critical
    message: str
    created_at: str
    acknowledged: bool = False


class DarkWebMonitor:
    """Monitor dark web onion services and generate alerts.

    Tracks onion link status, schedules periodic scans, and generates
    alerts when status changes or keywords are detected.

    Usage::

        monitor = DarkWebMonitor()
        status = await monitor.check_onion("http://example.onion")
        alerts = await monitor.get_active_alerts()
    """

    def __init__(self) -> None:
        """Initialize the dark web monitor."""
        self._onions: dict[str, OnionStatus] = {}
        self._alerts: dict[str, DarkWebAlert] = {}
        self._scan_schedule: dict[str, dict[str, Any]] = {}

    async def check_onion(self, url: str) -> OnionStatus:
        """Check the status of an onion service.

        Attempts to connect to the onion via Tor and records
        response time and availability.

        Args:
            url: Onion URL to check.

        Returns:
            OnionStatus with availability and timing data.
        """
        import asyncio

        is_online = False
        response_time_ms = None
        status_code = None

        try:
            import httpx
            import asyncio

            from backend.core.config import settings

            # Use Tor proxy from settings (env TOR_PROXY)
            proxy = settings.tor_proxy
            async with httpx.AsyncClient(
                proxy=proxy,
                timeout=30.0,
                verify=False,
            ) as client:
                start = datetime.now(timezone.utc)
                resp = await client.get(url)
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                response_time_ms = int(elapsed * 1000)
                status_code = resp.status_code
                is_online = resp.status_code < 500
        except Exception as exc:
            logger.debug("Onion check failed for %s: %s", url, exc)
            is_online = False

        status = OnionStatus(
            url=url,
            is_online=is_online,
            last_checked=datetime.now(timezone.utc).isoformat(),
            response_time_ms=response_time_ms,
            status_code=status_code,
        )

        # Check for status change and generate alert
        previous = self._onions.get(url)
        if previous and previous.is_online != is_online:
            await self._generate_alert(
                onion_url=url,
                alert_type="offline" if not is_online else "online",
                severity="high" if not is_online else "low",
                message=f"Onion {url} is now {'OFFLINE' if not is_online else 'ONLINE'}",
            )

        self._onions[url] = status
        return status

    async def check_all_onions(self) -> list[OnionStatus]:
        """Check all monitored onion services.

        Returns:
            List of OnionStatus for all monitored onions.
        """
        import asyncio

        tasks = [self.check_onion(url) for url in self._onions]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, OnionStatus)]
        return []

    async def add_onion(self, url: str, category: str = "UNKNOWN") -> None:
        """Add an onion URL to monitoring.

        Args:
            url: Onion URL to monitor.
            category: Category label (FORUM, MARKET, LEAK, etc.).
        """
        status = OnionStatus(
            url=url,
            is_online=False,
            category=category,
        )
        self._onions[url] = status
        logger.info("Added onion to monitoring: %s (category=%s)", url, category)

    async def remove_onion(self, url: str) -> bool:
        """Remove an onion from monitoring.

        Args:
            url: Onion URL to remove.

        Returns:
            True if removed, False if not found.
        """
        if url in self._onions:
            del self._onions[url]
            logger.info("Removed onion from monitoring: %s", url)
            return True
        return False

    async def get_onion_statuses(self) -> list[dict[str, Any]]:
        """Get status of all monitored onions.

        Returns:
            List of onion status dicts.
        """
        return [
            {
                "url": s.url,
                "is_online": s.is_online,
                "last_checked": s.last_checked,
                "response_time_ms": s.response_time_ms,
                "status_code": s.status_code,
                "category": s.category,
                "alert_triggered": s.alert_triggered,
            }
            for s in self._onions.values()
        ]

    async def get_dashboard(self) -> dict[str, Any]:
        """Get dark web monitoring dashboard data.

        Returns:
            Dict with onion statistics, alerts, and scan status.
        """
        total = len(self._onions)
        online = sum(1 for s in self._onions.values() if s.is_online)
        offline = total - online

        # Category distribution
        categories: dict[str, int] = {}
        for s in self._onions.values():
            categories[s.category] = categories.get(s.category, 0) + 1

        # Active alerts
        active_alerts = [a for a in self._alerts.values() if not a.acknowledged]

        return {
            "onions": {
                "total": total,
                "online": online,
                "offline": offline,
                "availability_pct": round((online / total * 100), 1) if total > 0 else 0,
                "by_category": categories,
            },
            "alerts": {
                "total": len(self._alerts),
                "active": len(active_alerts),
                "critical": sum(1 for a in active_alerts if a.severity == "critical"),
            },
            "scans": {
                "scheduled": len(self._scan_schedule),
                "last_scan": self._get_last_scan_time(),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_active_alerts(self) -> list[dict[str, Any]]:
        """Get all active (unacknowledged) alerts.

        Returns:
            List of alert dicts sorted by severity.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts = sorted(
            (a for a in self._alerts.values() if not a.acknowledged),
            key=lambda a: severity_order.get(a.severity, 99),
        )
        return [
            {
                "id": a.id,
                "onion_url": a.onion_url,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "created_at": a.created_at,
                "acknowledged": a.acknowledged,
            }
            for a in alerts
        ]

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert.

        Args:
            alert_id: Alert UUID.

        Returns:
            True if acknowledged, False if not found.
        """
        alert = self._alerts.get(alert_id)
        if alert is None:
            return False

        # Create new acknowledged instance (frozen dataclass)
        acknowledged = DarkWebAlert(
            id=alert.id,
            onion_url=alert.onion_url,
            alert_type=alert.alert_type,
            severity=alert.severity,
            message=alert.message,
            created_at=alert.created_at,
            acknowledged=True,
        )
        self._alerts[alert_id] = acknowledged
        return True

    async def schedule_scan(
        self,
        onion_url: str,
        interval_minutes: int = 60,
        keywords: list[str] | None = None,
    ) -> str:
        """Schedule a recurring scan for an onion.

        Args:
            onion_url: Onion URL to scan.
            interval_minutes: Scan interval in minutes.
            keywords: Optional keywords to watch for.

        Returns:
            Schedule ID.
        """
        schedule_id = str(uuid.uuid4())
        self._scan_schedule[schedule_id] = {
            "id": schedule_id,
            "onion_url": onion_url,
            "interval_minutes": interval_minutes,
            "keywords": keywords or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_run": None,
            "enabled": True,
        }
        logger.info(
            "Scheduled scan for %s every %d minutes (id=%s)",
            onion_url,
            interval_minutes,
            schedule_id,
        )
        return schedule_id

    async def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a scheduled scan.

        Args:
            schedule_id: Schedule UUID.

        Returns:
            True if removed, False if not found.
        """
        if schedule_id in self._scan_schedule:
            del self._scan_schedule[schedule_id]
            return True
        return False

    async def get_schedules(self) -> list[dict[str, Any]]:
        """Get all scheduled scans.

        Returns:
            List of schedule dicts.
        """
        return list(self._scan_schedule.values())

    async def _generate_alert(
        self,
        onion_url: str,
        alert_type: str,
        severity: str,
        message: str,
    ) -> DarkWebAlert:
        """Generate a new alert."""
        alert = DarkWebAlert(
            id=str(uuid.uuid4()),
            onion_url=onion_url,
            alert_type=alert_type,
            severity=severity,
            message=message,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._alerts[alert.id] = alert
        logger.warning("Dark web alert: %s - %s", severity, message)
        return alert

    def _get_last_scan_time(self) -> str | None:
        """Get the most recent scan time across all schedules."""
        times = [
            s["last_run"]
            for s in self._scan_schedule.values()
            if s.get("last_run")
        ]
        return max(times) if times else None
