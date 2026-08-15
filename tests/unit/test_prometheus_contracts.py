"""Regression tests for contracts between planner, dispatcher and registry."""

from __future__ import annotations

import pytest

pytest.importorskip("transitions", reason="backend runtime dependency is installed in the project .venv")

from backend.orchestrator.dispatcher import DispatchResult
from backend.orchestrator.orchestrator import PrometheusOrchestrator
from backend.orchestrator.planner import PlanStep, ReActPlanner, StepType


def test_planner_maps_legacy_agent_names_to_registered_agents() -> None:
    planner = ReActPlanner()
    plan = planner._parse_plan_data("plan-1", "inv-1", "goal", {
        "steps": [{"step_id": "step_1", "agent_name": "search", "task": "collect"}],
    })

    assert plan is not None
    assert plan.steps[0].agent_name == "dark_web_crawler"


def test_planner_drops_unknown_agents() -> None:
    planner = ReActPlanner()
    plan = planner._parse_plan_data("plan-1", "inv-1", "goal", {
        "steps": [{"step_id": "step_1", "agent_name": "invented_agent", "task": "collect"}],
    })

    assert plan is not None
    assert plan.steps == []


@pytest.mark.asyncio
async def test_orchestrator_polls_dispatch_id_not_plan_step_id() -> None:
    orchestrator = PrometheusOrchestrator()
    step = PlanStep(
        step_id="step_1",
        step_type=StepType.AGENT_TASK,
        agent_name="osint_collector",
        dispatch_task_id="dispatch-real-id",
    )
    requested: list[str] = []

    async def fake_status(task_id: str) -> DispatchResult:
        requested.append(task_id)
        return DispatchResult(
            task_id=task_id,
            agent_name="osint_collector",
            status="completed",
            result={"status": "completed", "results": []},
        )

    orchestrator._dispatcher.get_status = fake_status  # type: ignore[method-assign]
    results: dict[str, dict] = {}
    await orchestrator._wait_for_steps([step], results, timeout=0.1)

    assert requested == ["dispatch-real-id"]
    assert step.status == "completed"
