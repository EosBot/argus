"""APScheduler backend — persistent jobs for recurring scans.

Provides a persistent job scheduler using APScheduler with SQLAlchemy
job store for recurring scan tasks. Supports CRUD operations via API.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

# Default job store URL (SQLite for persistence)
_DEFAULT_JOBSTORE_URL = "sqlite:///scheduler_jobs.db"


class ScanScheduler:
    """Manage persistent scheduled scan jobs via APScheduler.

    Supports creating, updating, pausing, resuming, and deleting
    recurring scan jobs. Jobs persist across restarts via SQLite.

    Usage::

        scheduler = ScanScheduler()
        await scheduler.start()
        job_id = await scheduler.add_interval_job(
            func=scan_function,
            minutes=60,
            args=["http://example.onion"],
        )
        jobs = await scheduler.list_jobs()
        await scheduler.pause_job(job_id)
        await scheduler.remove_job(job_id)
    """

    def __init__(
        self,
        jobstore_url: str = _DEFAULT_JOBSTORE_URL,
        max_workers: int = 10,
    ) -> None:
        """Initialize the scheduler.

        Args:
            jobstore_url: SQLAlchemy connection string for job store.
            max_workers: Maximum concurrent job executions.
        """
        self._jobstore_url = jobstore_url
        self._scheduler: AsyncIOScheduler | None = None
        self._max_workers = max_workers

    async def start(self) -> None:
        """Start the scheduler with persistent job store."""
        jobstores = {
            "default": SQLAlchemyJobStore(url=self._jobstore_url),
        }
        self._scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            job_defaults={
                "coalesce": True,  # Combine missed runs
                "max_instances": 1,
                "misfire_grace_time": 300,
            },
        )
        self._scheduler.start()
        logger.info("Scan scheduler started (jobstore=%s)", self._jobstore_url)

    async def shutdown(self) -> None:
        """Shutdown the scheduler."""
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            logger.info("Scan scheduler shut down")

    async def add_interval_job(
        self,
        func: Any,
        minutes: int = 60,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        job_id: str | None = None,
        description: str | None = None,
    ) -> str:
        """Add an interval-based recurring job.

        Args:
            func: Async callable to execute.
            minutes: Interval in minutes between executions.
            args: Positional arguments for the function.
            kwargs: Keyword arguments for the function.
            job_id: Optional custom job ID (auto-generated if not provided).
            description: Optional job description.

        Returns:
            The job ID.
        """
        self._ensure_running()

        job_id = job_id or str(uuid.uuid4())
        trigger = IntervalTrigger(minutes=minutes)

        job = self._scheduler.add_job(
            func=func,
            trigger=trigger,
            id=job_id,
            name=description or f"interval_{minutes}m",
            args=args or [],
            kwargs=kwargs or {},
            replace_existing=True,
        )

        logger.info("Added interval job %s (every %d minutes)", job_id, minutes)
        return job.id

    async def add_cron_job(
        self,
        func: Any,
        cron_expression: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        job_id: str | None = None,
        description: str | None = None,
    ) -> str:
        """Add a cron-based recurring job.

        Args:
            func: Async callable to execute.
            cron_expression: Cron expression (e.g., "0 */6 * * *").
            args: Positional arguments for the function.
            kwargs: Keyword arguments for the function.
            job_id: Optional custom job ID.
            description: Optional job description.

        Returns:
            The job ID.
        """
        self._ensure_running()

        job_id = job_id or str(uuid.uuid4())
        trigger = CronTrigger.from_crontab(cron_expression)

        job = self._scheduler.add_job(
            func=func,
            trigger=trigger,
            id=job_id,
            name=description or f"cron_{cron_expression}",
            args=args or [],
            kwargs=kwargs or {},
            replace_existing=True,
        )

        logger.info("Added cron job %s (%s)", job_id, cron_expression)
        return job.id

    async def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job.

        Args:
            job_id: Job UUID.

        Returns:
            True if removed, False if not found.
        """
        self._ensure_running()

        try:
            self._scheduler.remove_job(job_id)
            logger.info("Removed job %s", job_id)
            return True
        except Exception:
            logger.debug("Job %s not found for removal", job_id)
            return False

    async def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job.

        Args:
            job_id: Job UUID.

        Returns:
            True if paused, False if not found.
        """
        self._ensure_running()

        try:
            self._scheduler.pause_job(job_id)
            logger.info("Paused job %s", job_id)
            return True
        except Exception:
            logger.debug("Job %s not found for pause", job_id)
            return False

    async def resume_job(self, job_id: str) -> bool:
        """Resume a paused job.

        Args:
            job_id: Job UUID.

        Returns:
            True if resumed, False if not found.
        """
        self._ensure_running()

        try:
            self._scheduler.resume_job(job_id)
            logger.info("Resumed job %s", job_id)
            return True
        except Exception:
            logger.debug("Job %s not found for resume", job_id)
            return False

    async def list_jobs(self) -> list[dict[str, Any]]:
        """List all scheduled jobs.

        Returns:
            List of job info dicts.
        """
        self._ensure_running()

        jobs = self._scheduler.get_jobs()
        return [
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
                "pending": job.pending,
            }
            for job in jobs
        ]

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Get details of a specific job.

        Args:
            job_id: Job UUID.

        Returns:
            Job info dict, or None if not found.
        """
        self._ensure_running()

        job = self._scheduler.get_job(job_id)
        if job is None:
            return None

        return {
            "id": job.id,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger),
            "pending": job.pending,
        }

    async def pause_all(self) -> None:
        """Pause all scheduled jobs."""
        self._ensure_running()
        self._scheduler.pause()
        logger.info("Paused all jobs")

    async def resume_all(self) -> None:
        """Resume all paused jobs."""
        self._ensure_running()
        self._scheduler.resume()
        logger.info("Resumed all jobs")

    def _ensure_running(self) -> None:
        """Ensure the scheduler is started."""
        if self._scheduler is None:
            raise RuntimeError("Scheduler not started. Call start() first.")
