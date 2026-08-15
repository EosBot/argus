"""Dynamic adaptation — replan when agents fail or find new leads.

Monitors agent results and dynamically adjusts the investigation plan:
- On agent failure: retry with alternative agent or skip
- On new leads discovered: add new steps to investigate them
- On agent timeout: escalate or reassign
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from backend.orchestrator.planner import (
    InvestigationPlan,
    PlanStep,
    ReActPlanner,
    StepType,
)

logger = logging.getLogger(__name__)


@dataclass
class AdaptationDecision:
    """Decision made by the dynamic adapter.

    Attributes:
        action: What to do (retry, skip, replan, escalate, add_steps).
        reason: Human-readable reason for the decision.
        new_steps: New steps to add (if action is add_steps).
        modified_steps: Steps to modify in the plan.
    """

    action: str
    reason: str
    new_steps: list[PlanStep] | None = None
    modified_steps: list[PlanStep] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "new_steps": [s.to_dict() for s in self.new_steps] if self.new_steps else None,
            "modified_steps": [s.to_dict() for s in self.modified_steps] if self.modified_steps else None,
        }


class DynamicAdapter:
    """Adapts investigation plans dynamically based on agent results.

    Handles:
    - Agent failures: retry with fallback agent or skip
    - New leads: add investigation steps for newly discovered IOCs/entities
    - Timeouts: escalate priority or reassign to different agent
    - Partial results: continue with available data

    Usage::

        adapter = DynamicAdapter(planner=ReActPlanner())
        decision = await adapter.handle_agent_failure(plan, failed_step, error)
        if decision.action == "add_steps":
            plan.steps.extend(decision.new_steps)
    """

    # Mapping of agent → fallback agent when primary fails
    AGENT_FALLBACKS: dict[str, str] = {
        "dark_web_crawler": "osint_collector",
        "osint_collector": "dark_web_crawler",
        "threat_intel_analyst": "forensic_analyst",
        "infrastructure_mapper": "forensic_analyst",
        "people_finder": "osint_collector",
        "crypto_tracer": "threat_intel_analyst",
    }

    # Maximum retries per step
    MAX_RETRIES = 2

    def __init__(self, planner: ReActPlanner | None = None) -> None:
        self._planner = planner or ReActPlanner()
        self._retry_counts: dict[str, int] = {}

    async def handle_agent_failure(
        self,
        plan: InvestigationPlan,
        failed_step: PlanStep,
        error: str,
    ) -> AdaptationDecision:
        """Handle an agent task failure.

        Decides whether to retry, skip, or escalate based on:
        - Number of previous retries
        - Step criticality (priority)
        - Available fallback agents
        """
        retry_key = failed_step.step_id
        current_retries = self._retry_counts.get(retry_key, 0)

        if current_retries >= self.MAX_RETRIES:
            return AdaptationDecision(
                action="skip",
                reason=f"Step {failed_step.step_id} exceeded max retries ({self.MAX_RETRIES}). Error: {error}",
            )

        # Try fallback agent
        fallback_agent = self.AGENT_FALLBACKS.get(failed_step.agent_name)
        if fallback_agent:
            self._retry_counts[retry_key] = current_retries + 1
            retry_step = PlanStep(
                # Preserve the logical ID so downstream dependency edges remain valid.
                step_id=failed_step.step_id,
                step_type=failed_step.step_type,
                agent_name=fallback_agent,
                task=failed_step.task,
                context=failed_step.context,
                dependencies=failed_step.dependencies,
                priority=failed_step.priority,
            )
            return AdaptationDecision(
                action="retry",
                reason=f"Retrying with fallback agent '{fallback_agent}' (attempt {current_retries + 1})",
                modified_steps=[retry_step],
            )

        # No fallback available — skip if non-critical
        if failed_step.priority > 1:
            return AdaptationDecision(
                action="skip",
                reason=f"Non-critical step {failed_step.step_id} failed, skipping. Error: {error}",
            )

        # Critical step failed — escalate
        return AdaptationDecision(
            action="escalate",
            reason=f"Critical step {failed_step.step_id} failed after {current_retries} retries. Error: {error}",
        )

    async def handle_new_leads(
        self,
        plan: InvestigationPlan,
        agent_result: dict[str, Any],
        source_step: PlanStep,
    ) -> AdaptationDecision:
        """Handle new leads discovered by an agent.

        Analyzes agent output for new IOCs, entities, or indicators
        that warrant additional investigation steps.
        """
        new_steps = self._extract_new_leads(plan, agent_result, source_step)

        if not new_steps:
            return AdaptationDecision(
                action="none",
                reason="No actionable new leads found",
            )

        return AdaptationDecision(
            action="add_steps",
            reason=f"Adding {len(new_steps)} new steps for discovered leads",
            new_steps=new_steps,
        )

    async def handle_agent_timeout(
        self,
        plan: InvestigationPlan,
        timed_out_step: PlanStep,
    ) -> AdaptationDecision:
        """Handle an agent task that exceeded its timeout.

        Options:
        - Retry with longer timeout (escalate priority)
        - Reassign to a faster agent
        - Continue with partial results
        """
        # Try reassigning to a faster agent
        fast_alternatives = {
            "dark_web_crawler": "osint_collector",
            "osint_collector": "forensic_analyst",
            "infrastructure_mapper": "forensic_analyst",
        }
        alternative = fast_alternatives.get(timed_out_step.agent_name)

        if alternative:
            retry_step = PlanStep(
                step_id=timed_out_step.step_id,
                step_type=timed_out_step.step_type,
                agent_name=alternative,
                task=timed_out_step.task,
                context=timed_out_step.context,
                dependencies=timed_out_step.dependencies,
                priority=max(timed_out_step.priority - 1, 0),  # Higher priority
            )
            return AdaptationDecision(
                action="retry",
                reason=f"Reassigning from '{timed_out_step.agent_name}' to '{alternative}' due to timeout",
                modified_steps=[retry_step],
            )

        return AdaptationDecision(
            action="skip",
            reason=f"Step {timed_out_step.step_id} timed out, no alternative available",
        )

    async def adapt_plan(
        self,
        plan: InvestigationPlan,
        completed_steps: list[PlanStep],
        failed_steps: list[PlanStep],
    ) -> InvestigationPlan:
        """Adapt the full plan based on execution results.

        Called after a batch of steps completes. Applies all necessary
        adaptations (retries, new steps, skips) and returns the updated plan.
        """
        for failed in failed_steps:
            decision = await self.handle_agent_failure(plan, failed, failed.error or "Unknown error")
            if decision.action == "retry" and decision.modified_steps:
                # Replace failed step with retry step
                for i, step in enumerate(plan.steps):
                    if step.step_id == failed.step_id:
                        plan.steps[i] = decision.modified_steps[0]
                        break
            elif decision.action == "skip":
                # Mark step as failed permanently
                for step in plan.steps:
                    if step.step_id == failed.step_id:
                        step.status = "failed"
                        break

        # Check completed steps for new leads
        for completed in completed_steps:
            if completed.result:
                decision = await self.handle_new_leads(plan, completed.result, completed)
                if decision.action == "add_steps" and decision.new_steps:
                    plan.steps.extend(decision.new_steps)

        return plan

    def _extract_new_leads(
        self,
        plan: InvestigationPlan,
        agent_result: dict[str, Any],
        source_step: PlanStep,
    ) -> list[PlanStep]:
        """Extract new investigation leads from agent output."""
        new_steps: list[PlanStep] = []
        existing_tasks = {s.task for s in plan.steps}

        # Check for IOCs in the result
        iocs = agent_result.get("iocs", {})
        if isinstance(iocs, dict):
            for ioc_type, values in iocs.items():
                if isinstance(values, list):
                    for value in values[:3]:  # Limit to top 3 per type
                        task = f"Analyze {ioc_type}: {value}"
                        if task not in existing_tasks:
                            new_steps.append(PlanStep(
                                step_id=f"lead_{len(new_steps) + 1}_{source_step.step_id}",
                                step_type=StepType.AGENT_TASK,
                                agent_name="intel",
                                task=task,
                                context={"ioc_type": ioc_type, "ioc_value": value},
                                dependencies=[source_step.step_id],
                                priority=source_step.priority + 1,
                            ))
                            existing_tasks.add(task)

        # Check for discovered entities/URLs
        results = agent_result.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            task = f"Deep analysis of {len(results)} discovered items from {source_step.agent_name}"
            if task not in existing_tasks:
                new_steps.append(PlanStep(
                    step_id=f"deep_analysis_{source_step.step_id}",
                    step_type=StepType.AGENT_TASK,
                    agent_name="intel",
                    task=task,
                    context={"source_results": results[:5]},
                    dependencies=[source_step.step_id],
                    priority=source_step.priority + 1,
                ))

        return new_steps
