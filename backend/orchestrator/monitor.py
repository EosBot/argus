"""Monitor loop — 5s heartbeat checking agent status via Redis pub/sub.

Continuously monitors running investigations, checking agent health,
progress, and completion status. Publishes updates to WebSocket subscribers.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)


@dataclass
class AgentHeartbeat:
    """Status snapshot for a single agent task.

    Attributes:
        task_id: Unique task identifier.
        agent_name: Name of the agent.
        status: Current status (queued, running, completed, failed, timeout).
        progress: Progress percentage (0-100).
        started_at: When the task started.
        last_heartbeat: Last status update timestamp.
        error: Error message if failed.
    """

    task_id: str
    agent_name: str
    status: str = "queued"
    progress: float = 0.0
    started_at: str | None = None
    last_heartbeat: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "status": self.status,
            "progress": self.progress,
            "started_at": self.started_at,
            "last_heartbeat": self.last_heartbeat,
            "error": self.error,
        }


@dataclass
class InvestigationProgress:
    """Aggregated progress for an entire investigation.

    Attributes:
        investigation_id: Investigation identifier.
        state: Current state machine state.
        total_steps: Total number of plan steps.
        completed_steps: Number of completed steps.
        failed_steps: Number of failed steps.
        running_steps: Number of currently running steps.
        agent_heartbeats: Per-agent heartbeat data.
        started_at: Investigation start timestamp.
        estimated_completion: Estimated completion timestamp (if available).
    """

    investigation_id: str
    state: str = "pending"
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    running_steps: int = 0
    agent_heartbeats: dict[str, AgentHeartbeat] = field(default_factory=dict)
    started_at: str | None = None
    estimated_completion: str | None = None

    @property
    def progress_percentage(self) -> float:
        """Overall progress as percentage."""
        if self.total_steps == 0:
            return 0.0
        return (self.completed_steps / self.total_steps) * 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "state": self.state,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "failed_steps": self.failed_steps,
            "running_steps": self.running_steps,
            "progress_percentage": round(self.progress_percentage, 1),
            "agent_heartbeats": {k: v.to_dict() for k, v in self.agent_heartbeats.items()},
            "started_at": self.started_at,
            "estimated_completion": self.estimated_completion,
        }


# Type alias for progress callback
ProgressCallback = Callable[[InvestigationProgress], Awaitable[None]]


class MonitorLoop:
    """Monitors investigation progress with a 5s heartbeat loop.

    Checks agent status via Redis and publishes progress updates.
    Supports multiple subscribers via callbacks.

    Usage::

        monitor = MonitorLoop(heartbeat_interval=5.0)
        monitor.subscribe(my_callback)
        await monitor.start_monitoring("investigation_123")
        # ... runs until stopped
        await monitor.stop_monitoring("investigation_123")
    """

    def __init__(self, heartbeat_interval: float = 5.0) -> None:
        self._heartbeat_interval = heartbeat_interval
        self._monitored: dict[str, InvestigationProgress] = {}
        self._callbacks: list[ProgressCallback] = []
        self._running: dict[str, bool] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def subscribe(self, callback: ProgressCallback) -> None:
        """Register a callback for progress updates.

        The callback receives an InvestigationProgress snapshot
        on each heartbeat.
        """
        self._callbacks.append(callback)

    def unsubscribe(self, callback: ProgressCallback) -> None:
        """Remove a progress callback."""
        self._callbacks = [cb for cb in self._callbacks if cb != callback]

    async def start_monitoring(self, investigation_id: str) -> None:
        """Start monitoring an investigation.

        Launches an async task that checks agent status every
        heartbeat_interval seconds.
        """
        if investigation_id in self._running and self._running[investigation_id]:
            logger.debug("Already monitoring investigation %s", investigation_id)
            return

        self._monitored[investigation_id] = InvestigationProgress(
            investigation_id=investigation_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._running[investigation_id] = True

        task = asyncio.create_task(self._monitor_loop(investigation_id))
        self._tasks[investigation_id] = task
        logger.info("Started monitoring investigation %s", investigation_id)

    async def stop_monitoring(self, investigation_id: str) -> None:
        """Stop monitoring an investigation."""
        self._running[investigation_id] = False
        task = self._tasks.get(investigation_id)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.pop(investigation_id, None)
        logger.info("Stopped monitoring investigation %s", investigation_id)

    async def stop_all(self) -> None:
        """Stop all monitoring loops."""
        for investigation_id in list(self._running.keys()):
            await self.stop_monitoring(investigation_id)

    def get_progress(self, investigation_id: str) -> InvestigationProgress | None:
        """Get current progress snapshot for an investigation."""
        return self._monitored.get(investigation_id)

    async def update_agent_heartbeat(
        self,
        investigation_id: str,
        heartbeat: AgentHeartbeat,
    ) -> None:
        """Update heartbeat data for a specific agent task.

        Called by the dispatcher when agent status changes.
        """
        progress = self._monitored.get(investigation_id)
        if progress:
            progress.agent_heartbeats[heartbeat.task_id] = heartbeat

    async def _monitor_loop(self, investigation_id: str) -> None:
        """Main monitoring loop — runs until stopped."""
        while self._running.get(investigation_id, False):
            try:
                await self._check_status(investigation_id)
                await self._notify_subscribers(investigation_id)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Monitor loop error for %s", investigation_id)

            await asyncio.sleep(self._heartbeat_interval)

    async def _check_status(self, investigation_id: str) -> None:
        """Check status of all agent tasks for an investigation."""
        progress = self._monitored.get(investigation_id)
        if not progress:
            return

        # Check Redis for agent status updates
        # Pattern: dispatch:{task_id} → DispatchResult
        completed = 0
        failed = 0
        running = 0

        for task_id, heartbeat in progress.agent_heartbeats.items():
            data = await redis_client.get_json(f"dispatch:{task_id}")
            if data:
                status = data.get("status", "queued")
                heartbeat.status = status
                heartbeat.last_heartbeat = datetime.now(timezone.utc).isoformat()

                if status == "completed":
                    completed += 1
                    heartbeat.progress = 100.0
                elif status == "failed":
                    failed += 1
                    heartbeat.error = data.get("error")
                elif status == "running":
                    running += 1
                    heartbeat.progress = min(heartbeat.progress + 10.0, 90.0)

        progress.completed_steps = completed
        progress.failed_steps = failed
        progress.running_steps = running

        # Publish to Redis channel for WebSocket subscribers
        await redis_client.publish_json(
            f"investigation:{investigation_id}:progress",
            progress.to_dict(),
        )

    async def _notify_subscribers(self, investigation_id: str) -> None:
        """Notify all registered callbacks with current progress."""
        progress = self._monitored.get(investigation_id)
        if not progress or not self._callbacks:
            return

        for callback in self._callbacks:
            try:
                await callback(progress)
            except Exception:
                logger.exception("Progress callback failed for %s", investigation_id)
