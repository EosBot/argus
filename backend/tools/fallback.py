"""FallbackChain — automatic retry with fallback tool selection.

When a primary tool fails, the FallbackChain automatically tries alternative
tools from the registry to complete the task.

Usage::

    from backend.tools.fallback import FallbackChain

    chain = FallbackChain()
    result = await chain.execute_with_fallback("nmap_scanner", task)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from backend.tools.registry import ToolRegistry, get_tool_registry
from backend.tools.selection import ToolSelection, SelectionResult

logger = logging.getLogger(__name__)

# Type alias for tool execution function
ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass
class FallbackResult:
    """Result of a fallback chain execution.

    Attributes:
        success: Whether the execution succeeded.
        tool_used: Name of the tool that produced the result.
        attempts: List of (tool_name, success, error) tuples.
        data: Result data from the successful tool.
        error: Error message if all tools failed.
        execution_time_ms: Total execution time in milliseconds.
    """

    success: bool = False
    tool_used: str = ""
    attempts: list[tuple[str, bool, str | None]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "tool_used": self.tool_used,
            "attempts": [
                {"tool": t, "success": s, "error": e}
                for t, s, e in self.attempts
            ],
            "data": self.data,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
        }


class FallbackChain:
    """Automatic retry with fallback when a tool fails.

    Tries the primary tool first, then falls back to alternative tools
    selected by the ToolSelection engine.
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        selector: ToolSelection | None = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 60.0,
    ) -> None:
        """Initialize fallback chain.

        Args:
            registry: ToolRegistry instance.
            selector: ToolSelection instance.
            max_retries: Maximum number of fallback attempts.
            retry_delay: Delay between retries in seconds.
            timeout: Timeout per tool execution in seconds.
        """
        self._registry = registry or get_tool_registry()
        self._selector = selector or ToolSelection(registry=self._registry)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._timeout = timeout

    async def execute_with_fallback(
        self,
        primary_tool: str,
        task: dict[str, Any],
        executor: ToolExecutor | None = None,
        task_description: str | None = None,
    ) -> FallbackResult:
        """Execute a tool with automatic fallback on failure.

        Args:
            primary_tool: Name of the primary tool to try first.
            task: Task dict to pass to the tool.
            executor: Async function(tool_name, task) -> result dict.
                     If None, uses the agent invocation path.
            task_description: Optional description for selecting fallbacks.

        Returns:
            FallbackResult with execution details.
        """
        start = time.monotonic()
        result = FallbackResult()

        # Build the chain: primary + fallbacks
        tools_to_try = [primary_tool]
        fallbacks = await self._get_fallbacks(primary_tool, task_description, task)
        tools_to_try.extend(fallbacks)

        # Limit to max_retries
        tools_to_try = tools_to_try[: self._max_retries]

        for tool_name in tools_to_try:
            tool_meta = self._registry.get(tool_name)
            if tool_meta is None:
                result.attempts.append((tool_name, False, "Tool not found in registry"))
                continue

            try:
                if executor is not None:
                    tool_result = await asyncio.wait_for(
                        executor(tool_name, task),
                        timeout=self._timeout,
                    )
                else:
                    tool_result = await self._execute_via_agent(tool_name, task)

                # Check if result indicates success
                status = tool_result.get("status", "completed")
                if status in ("completed", "degraded"):
                    result.success = True
                    result.tool_used = tool_name
                    result.data = tool_result
                    result.attempts.append((tool_name, True, None))
                    break
                else:
                    error = tool_result.get("error", f"Tool returned status: {status}")
                    result.attempts.append((tool_name, False, error))

            except asyncio.TimeoutError:
                result.attempts.append((tool_name, False, f"Timeout after {self._timeout}s"))
            except Exception as exc:
                result.attempts.append((tool_name, False, str(exc)))
                logger.debug("Tool '%s' failed: %s", tool_name, exc)

            # Delay between retries
            if tool_name != tools_to_try[-1]:
                await asyncio.sleep(self._retry_delay)

        if not result.success:
            failed_tools = [t for t, _, _ in result.attempts]
            result.error = f"All tools failed: {', '.join(failed_tools)}"

        result.execution_time_ms = round((time.monotonic() - start) * 1000, 2)
        return result

    async def _get_fallbacks(
        self,
        primary_tool: str,
        task_description: str | None,
        task: dict[str, Any],
    ) -> list[str]:
        """Get fallback tool names for a primary tool."""
        fallbacks: list[str] = []

        # Strategy 1: Use task description for intelligent selection
        if task_description:
            selection = await self._selector.select(task_description, max_tools=5)
            fallbacks = [
                t for t in selection.selected_tools
                if t != primary_tool
            ]

        # Strategy 2: Find tools in same category with overlapping capabilities
        if not fallbacks:
            primary_meta = self._registry.get(primary_tool)
            if primary_meta:
                same_category = self._registry.find_by_category(primary_meta.category)
                for tool in same_category:
                    if tool.name == primary_tool:
                        continue
                    # Check capability overlap
                    overlap = set(tool.capabilities) & set(primary_meta.capabilities)
                    if overlap:
                        fallbacks.append(tool.name)

        # Strategy 3: Use task query for search-based fallback
        if not fallbacks and task.get("query"):
            search_results = self._registry.search(task["query"])
            fallbacks = [
                t.name for t in search_results
                if t.name != primary_tool
            ][:3]

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for t in fallbacks:
            if t not in seen:
                seen.add(t)
                unique.append(t)

        return unique[: self._max_retries - 1]

    async def _execute_via_agent(
        self, tool_name: str, task: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a tool via its associated agent."""
        tool_meta = self._registry.get(tool_name)
        if tool_meta and tool_meta.agent_name:
            from backend.agents.registry import get_registry as get_agent_registry

            agent_registry = get_agent_registry()
            result = await agent_registry.invoke_agent(
                tool_meta.agent_name, task
            )
            return result

        # No agent associated — return error
        return {
            "status": "failed",
            "error": f"No agent associated with tool '{tool_name}'",
            "data": {},
        }
