"""Agent dispatcher — Celery-based background task execution.

Wraps the existing argus_engine AgentOrchestrator with Celery for distributed
background execution. Tasks are dispatched to Redis-backed Celery workers
and results are collected asynchronously.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    """Result of dispatching an agent task.

    Attributes:
        task_id: Unique task identifier.
        agent_name: Name of the dispatched agent.
        status: Dispatch status (queued, running, completed, failed).
        celery_task_id: Celery task ID for tracking.
        result: Task output (populated when complete).
        error: Error message if failed.
    """

    task_id: str
    agent_name: str
    status: str = "queued"
    celery_task_id: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    dispatched_at: str = ""
    completed_at: str | None = None
    owner_id: str | None = None

    def __post_init__(self) -> None:
        if not self.dispatched_at:
            self.dispatched_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "status": self.status,
            "celery_task_id": self.celery_task_id,
            "result": self.result,
            "error": self.error,
            "dispatched_at": self.dispatched_at,
            "completed_at": self.completed_at,
            "owner_id": self.owner_id,
        }


class AgentDispatcher:
    """Dispatches agent tasks via Celery for background execution.

    Falls back to in-process execution if Celery is not available.
    Uses Redis for task state tracking and result storage.

    Usage::

        dispatcher = AgentDispatcher()
        result = await dispatcher.dispatch("search", "investigate target.com", {})
        # Later...
        status = await dispatcher.get_status(result.task_id)
    """

    def __init__(self, use_celery: bool = False) -> None:
        self._use_celery = use_celery
        self._celery_app = None
        self._local_tasks: dict[str, DispatchResult] = {}

        if use_celery:
            self._init_celery()

    def _init_celery(self) -> None:
        """Initialize Celery app with Redis broker."""
        try:
            from celery import Celery

            self._celery_app = Celery(
                "argus_orchestrator",
                broker="redis://localhost:6379/0",
                backend="redis://localhost:6379/1",
            )
            self._celery_app.conf.update(
                task_serializer="json",
                result_serializer="json",
                accept_content=["json"],
                timezone="UTC",
                task_track_started=True,
                task_time_limit=600,  # 10 min hard limit
                task_soft_time_limit=540,  # 9 min soft limit
            )
            logger.info("Celery dispatcher initialized")
        except ImportError:
            logger.warning("Celery not available, falling back to in-process execution")
            self._use_celery = False

    async def dispatch(
        self,
        agent_name: str,
        task: str,
        context: dict[str, Any] | None = None,
    ) -> DispatchResult:
        """Dispatch an agent task for background execution.

        Args:
            agent_name: Registered agent name.
            task: Task description.
            context: Shared context dict.

        Returns:
            DispatchResult with task tracking info.
        """
        context = context or {}
        task_id = str(uuid.uuid4())[:12]
        result = DispatchResult(
            task_id=task_id,
            agent_name=agent_name,
            owner_id=str(context["operator_id"]) if context.get("operator_id") else None,
        )

        if self._use_celery and self._celery_app:
            celery_result = self._celery_app.send_task(
                "execute_agent_task",
                args=[agent_name, task, context],
                task_id=task_id,
            )
            result.celery_task_id = celery_result.id
            result.status = "queued"
        else:
            # In-process fallback: run in background
            result.status = "running"
            asyncio.create_task(self._run_agent_local(task_id, agent_name, task, context))

        # Track in Redis
        await redis_client.set_json(
            f"dispatch:{task_id}",
            result.to_dict(),
            ex=3600,
        )
        self._local_tasks[task_id] = result

        logger.info("Dispatched agent '%s' task %s", agent_name, task_id)
        return result

    async def dispatch_batch(
        self,
        tasks: list[tuple[str, str, dict[str, Any]]],
    ) -> list[DispatchResult]:
        """Dispatch multiple agent tasks in parallel.

        Args:
            tasks: List of (agent_name, task, context) tuples.

        Returns:
            List of DispatchResults in the same order.
        """
        results = []
        for agent_name, task, context in tasks:
            result = await self.dispatch(agent_name, task, context)
            results.append(result)
        return results

    async def get_status(self, task_id: str) -> DispatchResult | None:
        """Get current status of a dispatched task.

        Checks Redis first, then local cache.
        """
        # Check Redis
        data = await redis_client.get_json(f"dispatch:{task_id}")
        if data:
            return DispatchResult(**data)

        # Check local cache
        return self._local_tasks.get(task_id)

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task.

        Returns True if task was found and cancelled.
        """
        if self._use_celery and self._celery_app:
            from celery.result import AsyncResult

            celery_result = AsyncResult(task_id, app=self._celery_app)
            celery_result.revoke(terminate=True)

        task = self._local_tasks.get(task_id)
        if task:
            task.status = "cancelled"
            await redis_client.set_json(f"dispatch:{task_id}", task.to_dict(), ex=300)
            return True

        return False

    async def _run_agent_local(
        self,
        task_id: str,
        agent_name: str,
        task: str,
        context: dict[str, Any],
    ) -> None:
        """Run an agent task in-process (fallback when Celery unavailable)."""
        result = self._local_tasks.get(task_id)
        if result is None:
            return

        try:
            from backend.agents.registry import get_registry

            registry = get_registry()
            payload = {"query": task, "target": task, **context}
            agent_result = await registry.invoke_agent(agent_name, payload)
            raw_status = str(agent_result.get("status", "completed"))
            result.status = "completed" if raw_status in {"completed", "done", "degraded"} else "failed"
            result.result = agent_result
            result.error = agent_result.get("error")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            await self._persist_investigation_result(task_id, agent_name, context, agent_result)

        except Exception as exc:
            logger.exception("Local agent execution failed for task %s", task_id)
            result.status = "failed"
            result.error = str(exc)
            result.completed_at = datetime.now(timezone.utc).isoformat()

        # Update Redis
        await redis_client.set_json(f"dispatch:{task_id}", result.to_dict(), ex=3600)

    async def _persist_investigation_result(
        self,
        task_id: str,
        agent_name: str,
        context: dict[str, Any],
        agent_result: dict[str, Any],
    ) -> None:
        """Attach an immutable agent output to its case when one was supplied."""
        investigation_id = context.get("investigation_id")
        if not investigation_id:
            return
        try:
            from sqlalchemy import select

            from backend.core.database import AsyncSessionLocal
            from backend.db.models import Evidence, Finding, Investigation

            content = json.dumps(agent_result, ensure_ascii=False, sort_keys=True, default=str)
            async with AsyncSessionLocal() as session:
                investigation = await session.scalar(
                    select(Investigation).where(Investigation.id == str(investigation_id))
                )
                if investigation is None:
                    logger.warning("Investigation %s not found for task %s", investigation_id, task_id)
                    return
                session.add(Evidence(
                    investigation_id=str(investigation_id),
                    type="agent_result",
                    content=content,
                    content_hash=hashlib.sha256(content.encode()).hexdigest(),
                    metadata_={"agent": agent_name, "dispatch_task_id": task_id},
                ))
                session.add(Finding(
                    investigation_id=str(investigation_id),
                    title=f"Resultado de {agent_name.replace('_', ' ')}",
                    description="Saída produzida automaticamente por um agente e preservada como evidência.",
                    severity="info",
                    confidence="medium",
                    source=agent_name,
                    data={"dispatch_task_id": task_id, "status": agent_result.get("status")},
                ))
                await session.commit()
        except Exception:
            logger.exception("Could not persist task %s into investigation %s", task_id, investigation_id)



# One process-wide dispatcher keeps in-flight task state stable between create
# and poll requests. Redis remains the durable/read-through task store.
dispatcher = AgentDispatcher(use_celery=False)
