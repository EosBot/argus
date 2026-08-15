"""Prometheus Orchestrator — central investigation planning and execution.

The main orchestrator that ties together all components:
- State machine for lifecycle management
- ReAct planner for investigation planning
- Agent dispatcher for background execution
- Monitor loop for progress tracking
- Dynamic adapter for plan adaptation
- Correlation engine for cross-agent analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from backend.core.redis_client import redis_client
from backend.orchestrator.state_machine import InvestigationStateMachine, InvestigationStatus
from backend.orchestrator.planner import ReActPlanner, InvestigationPlan, PlanStep
from backend.orchestrator.dispatcher import AgentDispatcher, DispatchResult
from backend.orchestrator.monitor import MonitorLoop, InvestigationProgress, AgentHeartbeat
from backend.orchestrator.adapter import DynamicAdapter
from backend.orchestrator.correlation import CorrelationEngine, CorrelationReport

logger = logging.getLogger(__name__)


class PrometheusOrchestrator:
    """Central orchestrator for ARGUS investigations.

    Coordinates the full investigation lifecycle:
    1. Plan creation (ReAct loop)
    2. Agent dispatch (Celery/in-process)
    3. Progress monitoring (5s heartbeat)
    4. Dynamic adaptation (replan on failure/new leads)
    5. Correlation (cross-agent analysis)
    6. Reporting (final report generation)

    Usage::

        orch = PrometheusOrchestrator()
        await orch.run_investigation(
            investigation_id="abc123",
            goal="investigate target.com",
            context={"target": "target.com"},
        )
    """

    def __init__(
        self,
        use_celery: bool = False,
        heartbeat_interval: float = 5.0,
    ) -> None:
        self._state_machines: dict[str, InvestigationStateMachine] = {}
        self._plans: dict[str, InvestigationPlan] = {}
        self._planner = ReActPlanner()
        self._dispatcher = AgentDispatcher(use_celery=use_celery)
        self._monitor = MonitorLoop(heartbeat_interval=heartbeat_interval)
        self._adapter = DynamicAdapter(planner=self._planner)
        self._correlation = CorrelationEngine()
        self._execution_tasks: dict[str, asyncio.Task[None]] = {}

    async def create_plan(
        self,
        investigation_id: str,
        goal: str,
        context: dict[str, Any] | None = None,
    ) -> InvestigationPlan:
        """Create an investigation plan using the ReAct planner.

        Args:
            investigation_id: Investigation identifier.
            goal: High-level investigation goal.
            context: Additional context (target, IOCs, etc.).

        Returns:
            InvestigationPlan with DAG of agent tasks.
        """
        # Initialize state machine
        sm = InvestigationStateMachine(investigation_id)
        self._state_machines[investigation_id] = sm
        sm.start_planning()

        # Create plan
        plan = await self._planner.create_plan(
            goal=goal,
            investigation_id=investigation_id,
            context=context,
        )
        self._plans[investigation_id] = plan

        # Persist plan to Redis
        await redis_client.set_json(
            f"plan:{investigation_id}",
            plan.to_dict(),
            ex=7200,
        )

        return plan

    async def execute_plan(
        self,
        investigation_id: str,
    ) -> None:
        """Execute an investigation plan.

        Dispatches agents, monitors progress, and adapts the plan
        dynamically based on results.
        """
        plan = self._plans.get(investigation_id)
        sm = self._state_machines.get(investigation_id)

        if plan is None or sm is None:
            raise ValueError(f"No plan found for investigation {investigation_id}")

        sm.start_running()

        # Start monitoring
        await self._monitor.start_monitoring(investigation_id)

        # Execute plan steps
        task = asyncio.create_task(
            self._execute_plan_loop(investigation_id, plan, sm),
        )
        self._execution_tasks[investigation_id] = task

    async def run_investigation(
        self,
        investigation_id: str,
        goal: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run a complete investigation from start to finish.

        Convenience method that creates a plan and executes it.

        Args:
            investigation_id: Investigation identifier.
            goal: High-level investigation goal.
            context: Additional context.

        Returns:
            Final investigation results dict.
        """
        # Create plan
        plan = await self.create_plan(investigation_id, goal, context)
        logger.info(
            "Plan created for %s: %d steps",
            investigation_id,
            len(plan.steps),
        )

        # Execute plan
        await self.execute_plan(investigation_id)

        # Wait for completion
        task = self._execution_tasks.get(investigation_id)
        if task:
            await task

        # Return results
        return await self.get_results(investigation_id)

    async def pause_investigation(self, investigation_id: str) -> bool:
        """Pause a running investigation."""
        sm = self._state_machines.get(investigation_id)
        if sm and sm.can_pause:
            sm.pause()
            await self._monitor.stop_monitoring(investigation_id)
            return True
        return False

    async def resume_investigation(self, investigation_id: str) -> bool:
        """Resume a paused investigation."""
        sm = self._state_machines.get(investigation_id)
        if sm and sm.can_resume:
            sm.resume()
            await self._monitor.start_monitoring(investigation_id)
            # Re-execute remaining steps
            plan = self._plans.get(investigation_id)
            if plan:
                task = asyncio.create_task(
                    self._execute_plan_loop(investigation_id, plan, sm),
                )
                self._execution_tasks[investigation_id] = task
            return True
        return False

    async def get_status(self, investigation_id: str) -> dict[str, Any]:
        """Get current investigation status."""
        sm = self._state_machines.get(investigation_id)
        progress = self._monitor.get_progress(investigation_id)
        plan = self._plans.get(investigation_id)

        return {
            "investigation_id": investigation_id,
            "state": sm.state.value if sm else "unknown",
            "state_data": sm.to_dict() if sm else {},
            "progress": progress.to_dict() if progress else {},
            "plan": plan.to_dict() if plan else {},
        }

    async def get_results(self, investigation_id: str) -> dict[str, Any]:
        """Get final investigation results."""
        status = await self.get_status(investigation_id)

        # Collect agent results
        agent_results: dict[str, Any] = {}
        plan = self._plans.get(investigation_id)
        if plan:
            for step in plan.steps:
                if step.status == "completed" and step.result:
                    agent_results[f"{step.agent_name}:{step.step_id}"] = step.result

        # Get correlation report
        correlation_data = await redis_client.get_json(
            f"correlation:{investigation_id}",
        )

        return {
            **status,
            "agent_results": agent_results,
            "correlation_report": correlation_data,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _execute_plan_loop(
        self,
        investigation_id: str,
        plan: InvestigationPlan,
        sm: InvestigationStateMachine,
    ) -> None:
        """Main execution loop — dispatches steps and monitors progress."""
        plan.status = "executing"
        agent_results: dict[str, dict[str, Any]] = {}

        try:
            while not plan.is_complete() and sm.is_active:
                # Get ready steps (dependencies met)
                ready_steps = plan.get_ready_steps()

                if not ready_steps:
                    # Check if we're waiting for running steps
                    running = [s for s in plan.steps if s.status == "running"]
                    if not running:
                        # No ready steps and none running means an unsatisfied DAG.
                        blocked = [s for s in plan.steps if s.status != "completed"]
                        if blocked:
                            plan.status = "failed"
                            logger.error(
                                "Investigation %s has blocked steps: %s",
                                investigation_id,
                                [s.step_id for s in blocked],
                            )
                            sm.fail()
                        break
                    # Wait for running steps to complete
                    await asyncio.sleep(1)
                    continue

                # Dispatch ready steps
                for step in ready_steps:
                    step.status = "running"
                    dependency_results = {
                        dependency.step_id: dependency.result
                        for dependency in plan.steps
                        if dependency.step_id in step.dependencies and dependency.result
                    }
                    dispatch_result = await self._dispatcher.dispatch(
                        agent_name=step.agent_name,
                        task=step.task,
                        context={
                            **step.context,
                            "investigation_id": investigation_id,
                            "dependency_results": dependency_results,
                            "previous_results": list(dependency_results.values()),
                        },
                    )
                    step.dispatch_task_id = dispatch_result.task_id

                    # Update monitor with heartbeat
                    await self._monitor.update_agent_heartbeat(
                        investigation_id,
                        AgentHeartbeat(
                            task_id=dispatch_result.task_id,
                            agent_name=step.agent_name,
                            status="running",
                            started_at=datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                # Wait for dispatched steps to complete
                await self._wait_for_steps(ready_steps, agent_results)

                # Adapt plan based on results
                completed = [s for s in ready_steps if s.status == "completed"]
                failed = [s for s in ready_steps if s.status == "failed"]

                if failed or any(s.result for s in completed):
                    plan = await self._adapter.adapt_plan(plan, completed, failed)
                    await redis_client.set_json(f"plan:{investigation_id}", plan.to_dict(), ex=7200)

            # All steps complete → correlate
            if plan.is_complete():
                plan.status = "completed"
                await redis_client.set_json(f"plan:{investigation_id}", plan.to_dict(), ex=7200)
                await self._run_correlation(investigation_id, agent_results, sm)

        except asyncio.CancelledError:
            logger.info("Execution cancelled for investigation %s", investigation_id)
        except Exception as exc:
            logger.exception("Execution failed for investigation %s", investigation_id)
            sm.fail()

    async def _wait_for_steps(
        self,
        steps: list[PlanStep],
        agent_results: dict[str, dict[str, Any]],
        timeout: float = 120.0,
    ) -> None:
        """Wait for dispatched steps to complete."""
        start = asyncio.get_event_loop().time()

        while True:
            all_done = True
            for step in steps:
                if step.status in ("completed", "failed"):
                    continue

                # Check dispatch status
                dispatch_status = await self._dispatcher.get_status(step.dispatch_task_id or step.step_id)
                if dispatch_status and dispatch_status.status == "completed":
                    step.status = "completed"
                    step.result = dispatch_status.result or {}
                    step.completed_at = datetime.now(timezone.utc).isoformat()
                    agent_results[step.agent_name] = step.result
                elif dispatch_status and dispatch_status.status == "failed":
                    step.status = "failed"
                    step.error = dispatch_status.error
                    step.completed_at = datetime.now(timezone.utc).isoformat()
                else:
                    all_done = False

            if all_done:
                break

            # Check timeout
            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                for step in steps:
                    if step.status == "running":
                        step.status = "failed"
                        step.error = f"Timeout after {timeout}s"
                break

            await asyncio.sleep(0.5)

    async def _run_correlation(
        self,
        investigation_id: str,
        agent_results: dict[str, dict[str, Any]],
        sm: InvestigationStateMachine,
    ) -> None:
        """Run correlation analysis and generate report."""
        sm.start_correlating()

        # Run correlation
        report = await self._correlation.correlate_all(
            investigation_id=investigation_id,
            agent_results=agent_results,
        )

        # Store correlation report
        await redis_client.set_json(
            f"correlation:{investigation_id}",
            report.to_dict(),
            ex=7200,
        )

        # Generate final report
        sm.start_reporting()
        await self._generate_report(investigation_id, report, agent_results)

        # Mark complete
        sm.complete()

        # Stop monitoring
        await self._monitor.stop_monitoring(investigation_id)

    async def _generate_report(
        self,
        investigation_id: str,
        correlation_report: CorrelationReport,
        agent_results: dict[str, dict[str, Any]],
    ) -> str:
        """Generate final investigation report."""
        plan = self._plans.get(investigation_id)
        sm = self._state_machines.get(investigation_id)

        sections = [
            f"# Investigation Report: {investigation_id}",
            f"\n**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Goal:** {plan.goal if plan else 'N/A'}",
            f"**State:** {sm.state.value if sm else 'N/A'}",
            f"\n## Executive Summary\n",
            correlation_report.summary,
            f"\n## Risk Score: {correlation_report.risk_score:.0f}/100\n",
        ]

        # Correlations
        if correlation_report.correlations:
            sections.append("\n## Correlations\n")
            for corr in correlation_report.correlations:
                sections.append(f"- [{corr.correlation_type}] {corr.description} (confidence: {corr.confidence:.0%})")

        # Agent results
        sections.append("\n## Agent Findings\n")
        for agent_name, result in agent_results.items():
            sections.append(f"\n### {agent_name}\n")
            sections.append("```json")
            sections.append(json.dumps(result, indent=2, default=str)[:1000])
            sections.append("```")

        report_text = "\n".join(sections)

        # Store report
        await redis_client.set_json(
            f"report:{investigation_id}",
            {
                "investigation_id": investigation_id,
                "report": report_text,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            ex=7200,
        )

        return report_text
