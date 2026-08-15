"""Base agent interface for ARGUS specialized investigation agents.

All agents inherit from BaseAgent and implement the unified
``async def run(task: dict) -> dict`` interface.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Result of an agent execution.

    Attributes:
        agent_name: Name of the agent that produced this result.
        status: Execution status (completed, failed, degraded).
        data: Result payload dict.
        error: Error message if failed.
        execution_time_ms: Wall-clock execution time in milliseconds.
        created_at: ISO timestamp of result creation.
    """

    agent_name: str
    status: str = "completed"
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    execution_time_ms: float = 0.0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self.status,
            "data": self.data,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
            "created_at": self.created_at,
        }


class BaseAgent:
    """Abstract base class for all specialized investigation agents.

    Subclasses must define:
        - name: Unique agent identifier string
        - description: Human-readable description
        - capabilities: List of capability strings
        - async def run(task: dict) -> dict: Execution logic

    Usage::

        class MyAgent(BaseAgent):
            name = "my_agent"
            description = "Does X"
            capabilities = ["x", "y"]

            async def run(self, task: dict) -> dict:
                return {"result": "data"}
    """

    name: str = "base"
    description: str = "Base agent"
    capabilities: list[str] = []

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute the agent's investigation task.

        Args:
            task: Task dictionary with task-specific parameters.
                Common keys:
                    - query: Search target (string)
                    - target: Host/IP/domain to investigate
                    - context: Shared context dict
                    - options: Agent-specific options

        Returns:
            Result dictionary with agent findings.
        """
        raise NotImplementedError(
            f"Agent '{self.name}' must implement run()"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return agent metadata as a dict."""
        return {
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
        }
