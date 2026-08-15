import asyncio

import pytest

from backend.orchestrator import planner as planner_module
from backend.orchestrator.planner import ReActPlanner


@pytest.mark.asyncio
async def test_planner_timeout_uses_executable_fallback(monkeypatch) -> None:
    async def never_completes(**_kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(planner_module.litellm, "acompletion", never_completes)
    planner = ReActPlanner(planning_timeout_seconds=0.01)

    plan = await planner.create_plan(
        goal="passive investigation",
        investigation_id="case-1",
        context={"operator_id": "operator-1"},
    )

    assert plan.metadata == {"fallback": True}
    assert [step.agent_name for step in plan.steps] == [
        "dark_web_crawler",
        "threat_intel_analyst",
    ]
    assert all(step.context["operator_id"] == "operator-1" for step in plan.steps)
