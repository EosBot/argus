"""AgentRegistry — dynamic discovery and invocation of specialized agents.

Provides a central registry where agents are registered by name and can
be discovered, listed, and invoked at runtime.

Usage::

    from backend.agents.registry import get_registry

    registry = get_registry()
    result = await registry.invoke_agent("dark_web_crawler", {"query": "target"})
"""

from __future__ import annotations

import logging
from typing import Any

from backend.agents.base import BaseAgent

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Central registry for specialized investigation agents.

    Supports dynamic registration, discovery by name, listing all
    registered agents, and invoking agents with a task dict.
    """

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        """Register an agent instance.

        Args:
            agent: The agent instance to register.

        Raises:
            TypeError: If agent is not a BaseAgent instance.
        """
        if not isinstance(agent, BaseAgent):
            raise TypeError(
                f"Expected BaseAgent instance, got {type(agent).__name__}"
            )
        self._agents[agent.name] = agent
        logger.debug("Registered agent: %s", agent.name)

    def unregister(self, name: str) -> bool:
        """Remove an agent from the registry.

        Args:
            name: Agent name to remove.

        Returns:
            True if the agent was removed, False if not found.
        """
        if name in self._agents:
            del self._agents[name]
            logger.debug("Unregistered agent: %s", name)
            return True
        return False

    def get_agent(self, name: str) -> BaseAgent | None:
        """Retrieve an agent by name.

        Args:
            name: Registered agent name.

        Returns:
            The agent instance, or None if not found.
        """
        return self._agents.get(name)

    def list_agents(self) -> list[dict[str, Any]]:
        """List all registered agents with their metadata.

        Returns:
            List of agent metadata dicts (name, description, capabilities).
        """
        return [agent.to_dict() for agent in self._agents.values()]

    async def invoke_agent(
        self, name: str, task: dict[str, Any]
    ) -> dict[str, Any]:
        """Invoke a registered agent with a task.

        Args:
            name: Registered agent name.
            task: Task dictionary to pass to the agent's run() method.

        Returns:
            Result dict from the agent execution. If the agent is not
            found, returns an error result dict.
        """
        agent = self._agents.get(name)
        if agent is None:
            available = list(self._agents.keys())
            logger.warning(
                "Agent '%s' not found. Available: %s", name, available
            )
            return {
                "agent_name": name,
                "status": "error",
                "data": {},
                "error": f"Agent '{name}' not found. Available: {available}",
            }

        logger.info("Invoking agent '%s' with task keys: %s", name, list(task.keys()))
        try:
            result = await agent.run(task)
            return result
        except Exception as exc:
            logger.exception("Agent '%s' execution failed", name)
            return {
                "agent_name": name,
                "status": "failed",
                "data": {},
                "error": f"Agent execution error: {str(exc)}",
            }

    def __contains__(self, name: str) -> bool:
        return name in self._agents

    def __len__(self) -> int:
        return len(self._agents)


def get_registry() -> AgentRegistry:
    """Get the singleton AgentRegistry with all default agents registered.

    Returns:
        The default AgentRegistry instance with all specialized agents.
    """
    from backend.agents import _default_registry

    return _default_registry
