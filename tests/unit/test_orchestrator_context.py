"""Trusted case/operator context must survive autonomous LLM planning."""

import json
from types import SimpleNamespace

import pytest

from backend.orchestrator.planner import ReActPlanner


@pytest.mark.asyncio
async def test_trusted_context_is_inherited_and_overrides_llm_context(monkeypatch):
    plan_json = {
        "steps": [{
            "step_id": "step_1",
            "step_type": "agent_task",
            "agent_name": "dark_web_crawler",
            "task": "Pesquisar fontes relevantes",
            "dependencies": [],
            "context": {"operator_id": "attacker", "scrape_results": True},
        }]
    }

    async def completion(**_kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(plan_json)))])

    monkeypatch.setattr("backend.orchestrator.planner.litellm.acompletion", completion)
    planner = ReActPlanner(max_iterations=1)
    plan = await planner.create_plan(
        "investigar domínio autorizado",
        "case-123",
        {"operator_id": "operator-1", "investigation_id": "case-123"},
    )
    assert plan.steps[0].context["operator_id"] == "operator-1"
    assert plan.steps[0].context["investigation_id"] == "case-123"
    assert plan.steps[0].context["scrape_results"] is True
