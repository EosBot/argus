"""ReAct loop planner — reasoning + acting cycle for investigation planning.

Implements the ReAct (Reasoning + Acting) pattern:
1. Thought: LLM analyzes the current situation and decides next action
2. Action: Execute the chosen action (spawn agent, query data, etc.)
3. Observation: Collect results and feed back into the loop

The loop continues until the investigation goal is achieved or max iterations reached.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import litellm

from backend.core.config import settings

logger = logging.getLogger(__name__)


class StepType(str, Enum):
    """Types of plan steps."""

    AGENT_TASK = "agent_task"
    CORRELATION = "correlation"
    REPORT = "report"
    DECISION = "decision"


@dataclass
class PlanStep:
    """A single step in an investigation plan.

    Attributes:
        step_id: Unique identifier for this step.
        step_type: Type of step (agent_task, correlation, report, decision).
        agent_name: Agent to invoke (for agent_task steps).
        task: Task description for the agent.
        context: Shared context dict.
        dependencies: List of step_ids that must complete before this step.
        status: Current status (pending, running, completed, failed).
        result: Output from step execution.
        priority: Execution priority (lower = higher priority).
    """

    step_id: str
    step_type: StepType
    agent_name: str = ""
    task: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    status: str = "pending"
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    priority: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    dispatch_task_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_type": self.step_type.value,
            "agent_name": self.agent_name,
            "task": self.task,
            "context": self.context,
            "dependencies": self.dependencies,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "priority": self.priority,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "dispatch_task_id": self.dispatch_task_id,
        }


@dataclass
class InvestigationPlan:
    """A complete investigation plan — DAG of agent tasks with dependencies.

    Attributes:
        plan_id: Unique plan identifier.
        investigation_id: Associated investigation ID.
        goal: High-level investigation goal.
        steps: Ordered list of plan steps.
        status: Plan status (draft, approved, executing, completed, failed).
        created_at: Creation timestamp.
        metadata: Additional plan metadata.
    """

    plan_id: str
    investigation_id: str
    goal: str
    steps: list[PlanStep] = field(default_factory=list)
    status: str = "draft"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_ready_steps(self) -> list[PlanStep]:
        """Return steps whose dependencies are all completed."""
        completed_ids = {s.step_id for s in self.steps if s.status == "completed"}
        return [
            s for s in self.steps
            if s.status == "pending"
            and all(dep in completed_ids for dep in s.dependencies)
        ]

    def get_next_step(self) -> PlanStep | None:
        """Return the next ready step with highest priority."""
        ready = self.get_ready_steps()
        if not ready:
            return None
        ready.sort(key=lambda s: s.priority)
        return ready[0]

    def is_complete(self) -> bool:
        """True if all steps are completed."""
        return all(s.status == "completed" for s in self.steps) and len(self.steps) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "investigation_id": self.investigation_id,
            "goal": self.goal,
            "steps": [s.to_dict() for s in self.steps],
            "status": self.status,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


# System prompt for the ReAct planner
_REACT_SYSTEM_PROMPT = """You are the ARGUS Prometheus Orchestrator — an AI investigation planner.
Your job is to decompose high-level investigation goals into a DAG of agent tasks.

Available agents (use these exact names):
- dark_web_crawler: Tor search, onion scraping and isolated browsing
- osint_collector: clear-web OSINT and content collection
- forensic_analyst: IOC extraction and forensic analysis
- infrastructure_mapper: authorized infrastructure mapping
- threat_intel_analyst: correlation, attribution and threat intelligence
- crypto_tracer: BTC/ETH tracing
- people_finder: username, email and identity OSINT
- report_writer: evidence-grounded report generation

For each plan, output JSON in this exact format:
{
  "steps": [
    {
      "step_id": "step_1",
      "step_type": "agent_task",
      "agent_name": "search",
      "task": "Search for information about target.com",
      "dependencies": [],
      "priority": 0
    },
    {
      "step_id": "step_2",
      "step_type": "agent_task",
      "agent_name": "scrape",
      "task": "Scrape the top 3 URLs from search results",
      "dependencies": ["step_1"],
      "priority": 1
    }
  ]
}

Rules:
1. Maximum 10 steps per plan
2. Steps with no dependencies run first (parallel)
3. Steps with dependencies wait for predecessors
4. Always end with a correlation step if multiple agents are involved
5. Be specific in task descriptions — agents need clear instructions
6. Use the investigation context (target, IOCs, previous findings) in tasks
"""


class ReActPlanner:
    """ReAct loop planner — uses LLM to create investigation plans.

    Implements the Thought → Action → Observation cycle:
    - Thought: LLM reasons about what needs to be done
    - Action: Creates plan steps based on reasoning
    - Observation: Validates the plan structure
    """

    def __init__(
        self,
        model: str | None = None,
        max_iterations: int = 5,
        max_steps_per_plan: int = 10,
        planning_timeout_seconds: float = 15.0,
    ) -> None:
        self._model = model or settings.litellm_model
        self._max_iterations = max_iterations
        self._max_steps_per_plan = max_steps_per_plan
        self._planning_timeout_seconds = planning_timeout_seconds

    async def create_plan(
        self,
        goal: str,
        investigation_id: str,
        context: dict[str, Any] | None = None,
    ) -> InvestigationPlan:
        """Create an investigation plan from a high-level goal.

        Uses ReAct loop: Thought → Action → Observation cycles
        to iteratively build and refine the plan.

        Args:
            goal: High-level investigation goal (e.g., "investigate target.com").
            investigation_id: Associated investigation ID.
            context: Additional context (target, IOCs, previous findings).

        Returns:
            InvestigationPlan with a DAG of agent tasks.
        """
        context = context or {}
        plan_id = f"plan_{investigation_id[:8]}"

        # Build the planning prompt
        messages = await self._build_planning_messages(goal, context)

        # ReAct loop: iterate to refine the plan
        plan: InvestigationPlan | None = None
        for iteration in range(self._max_iterations):
            logger.info(
                "ReAct planning iteration %d/%d for investigation %s",
                iteration + 1,
                self._max_iterations,
                investigation_id,
            )

            # Thought + Action: call LLM to generate/extend plan
            response: Any = None
            try:
                response = await asyncio.wait_for(
                    litellm.acompletion(
                        model=self._model,
                        messages=messages,
                        temperature=0.3,
                        max_tokens=1200,
                        response_format={"type": "json_object"},
                    ),
                    timeout=self._planning_timeout_seconds,
                )
                content = response.choices[0].message.content or "{}"
                plan_data = json.loads(content)
            except json.JSONDecodeError:
                logger.warning("ReAct iteration %d: invalid JSON, retrying", iteration + 1)
                raw_content = response.choices[0].message.content if response and hasattr(response, "choices") else "{}"
                messages.append({"role": "assistant", "content": raw_content})
                messages.append({
                    "role": "user",
                    "content": "Invalid JSON. Please respond with valid JSON only.",
                })
                continue
            except TimeoutError:
                logger.warning(
                    "Planning timed out after %.1fs; using deterministic fallback",
                    self._planning_timeout_seconds,
                )
                plan = self._create_fallback_plan(plan_id, investigation_id, goal, context)
                break
            except Exception:
                logger.exception("ReAct iteration %d: LLM call failed", iteration + 1)
                # Fallback: create a minimal plan
                plan = self._create_fallback_plan(plan_id, investigation_id, goal, context)
                break

            # Observation: validate and build plan
            plan = self._parse_plan_data(plan_id, investigation_id, goal, plan_data)

            if plan and plan.steps:
                logger.info(
                    "ReAct planning complete: %d steps for investigation %s",
                    len(plan.steps),
                    investigation_id,
                )
                break

            # If no valid steps, ask LLM to try again
            messages.append({"role": "assistant", "content": json.dumps(plan_data)})
            messages.append({
                "role": "user",
                "content": "The plan has no valid steps. Please create at least one step.",
            })

        if plan is None:
            plan = self._create_fallback_plan(plan_id, investigation_id, goal, context)

        # Trusted request context (ownership/case scope) is inherited by every
        # generated step and cannot be overridden by LLM-authored JSON.
        for step in plan.steps:
            step.context = {**step.context, **context}

        plan.status = "approved"
        return plan

    async def _build_planning_messages(
        self,
        goal: str,
        context: dict[str, Any],
    ) -> list[dict[str, str]]:
        """Build the message list for the planning LLM call."""
        context_str = json.dumps(context, default=str) if context else "{}"
        user_prompt = (
            f"Investigation goal: {goal}\n"
            f"Context: {context_str}\n\n"
            "Create a plan with up to 10 steps. Output JSON only."
        )

        return [
            {"role": "system", "content": _REACT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _parse_plan_data(
        self,
        plan_id: str,
        investigation_id: str,
        goal: str,
        data: dict[str, Any],
    ) -> InvestigationPlan | None:
        """Parse LLM response into an InvestigationPlan."""
        raw_steps = data.get("steps", [])
        if not raw_steps:
            return None

        aliases = {
            "search": "dark_web_crawler", "scrape": "osint_collector",
            "intel": "threat_intel_analyst", "pentest": "infrastructure_mapper",
            "geo": "forensic_analyst", "temporal": "threat_intel_analyst",
            "attribution": "threat_intel_analyst", "crypto": "crypto_tracer",
        }
        valid_agents = {
            "dark_web_crawler", "osint_collector", "forensic_analyst",
            "infrastructure_mapper", "threat_intel_analyst", "crypto_tracer",
            "people_finder", "report_writer",
        }
        steps: list[PlanStep] = []
        for i, raw in enumerate(raw_steps[:self._max_steps_per_plan]):
            agent_name = aliases.get(raw.get("agent_name", ""), raw.get("agent_name", ""))
            if raw.get("step_type", "agent_task") == "agent_task" and agent_name not in valid_agents:
                logger.warning("Ignoring plan step with unknown agent: %s", agent_name)
                continue
            step = PlanStep(
                step_id=raw.get("step_id", f"step_{i + 1}"),
                step_type=StepType(raw.get("step_type", "agent_task")),
                agent_name=agent_name,
                task=raw.get("task", ""),
                context=raw.get("context", {}),
                dependencies=raw.get("dependencies", []),
                priority=raw.get("priority", i),
            )
            steps.append(step)

        return InvestigationPlan(
            plan_id=plan_id,
            investigation_id=investigation_id,
            goal=goal,
            steps=steps,
        )

    def _create_fallback_plan(
        self,
        plan_id: str,
        investigation_id: str,
        goal: str,
        context: dict[str, Any],
    ) -> InvestigationPlan:
        """Create a minimal fallback plan when LLM planning fails."""
        logger.warning("Creating fallback plan for investigation %s", investigation_id)
        return InvestigationPlan(
            plan_id=plan_id,
            investigation_id=investigation_id,
            goal=goal,
            steps=[
                PlanStep(
                    step_id="step_1",
                    step_type=StepType.AGENT_TASK,
                    agent_name="dark_web_crawler",
                    task=f"Search for information related to: {goal}",
                    context={**context, "scrape_results": True},
                    dependencies=[],
                    priority=0,
                ),
                PlanStep(
                    step_id="step_2",
                    step_type=StepType.AGENT_TASK,
                    agent_name="threat_intel_analyst",
                    task="Analyze search results and extract key findings",
                    context=context,
                    dependencies=["step_1"],
                    priority=1,
                ),
            ],
            metadata={"fallback": True},
        )
