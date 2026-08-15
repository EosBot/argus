"""Unified real-agent dispatch, polling and synthesis routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from backend.agents.registry import get_registry
from backend.api.models.requests import AgentInvokeRequest, AgentParallelRequest
from backend.api.models.responses import AgentInfo, AgentInvokeResponse, AgentResultResponse, AgentSynthesizeResponse
from backend.auth.rbac import require_permission
from backend.orchestrator.dispatcher import dispatcher

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("", response_model=list[AgentInfo])
async def list_agents(_user=Depends(require_permission("agents:invoke"))) -> list[AgentInfo]:
    return [AgentInfo(name=item["name"], description=item["description"], icon="🤖", status="ready") for item in get_registry().list_agents()]


async def _dispatch(name: str, task: str, context: dict[str, Any]) -> AgentInvokeResponse:
    if name not in get_registry():
        raise HTTPException(404, f"Agente '{name}' não registrado")
    result = await dispatcher.dispatch(name, task, context)
    return AgentInvokeResponse(task_id=result.task_id, agent_name=name, status=result.status)


@router.post("/invoke", response_model=AgentInvokeResponse)
async def invoke_agent(req: AgentInvokeRequest, _user=Depends(require_permission("agents:invoke"))) -> AgentInvokeResponse:
    return await _dispatch(req.agent_name, req.task, req.context)


@router.post("/invoke/parallel", response_model=list[AgentInvokeResponse])
async def invoke_parallel(req: AgentParallelRequest, _user=Depends(require_permission("agents:invoke"))) -> list[AgentInvokeResponse]:
    unknown = [item.agent_name for item in req.tasks if item.agent_name not in get_registry()]
    if unknown:
        raise HTTPException(404, f"Agentes não registrados: {unknown}")
    results = await dispatcher.dispatch_batch([(item.agent_name, item.task, item.context) for item in req.tasks])
    return [AgentInvokeResponse(task_id=item.task_id, agent_name=item.agent_name, status=item.status) for item in results]


@router.get("/{task_id}", response_model=AgentResultResponse)
async def get_agent_result(task_id: str, _user=Depends(require_permission("agents:invoke"))) -> AgentResultResponse:
    result = await dispatcher.get_status(task_id)
    if result is None:
        raise HTTPException(404, f"Task '{task_id}' não encontrada")
    return AgentResultResponse(task_id=result.task_id, agent_name=result.agent_name, status=result.status, output=result.result, error=result.error, created_at=result.dispatched_at)


@router.post("/synthesize", response_model=AgentSynthesizeResponse)
async def synthesize_results(task_ids: list[str] = Query(default_factory=list, min_length=1, max_length=20), _user=Depends(require_permission("agents:invoke"))) -> AgentSynthesizeResponse:
    statuses = [item for item in [await dispatcher.get_status(task_id) for task_id in task_ids] if item is not None]
    findings = [{"task_id": item.task_id, "agent_name": item.agent_name, "result": item.result} for item in statuses if item.status == "completed" and item.result]
    errors = [{"task_id": item.task_id, "error": item.error or "Falha sem detalhe"} for item in statuses if item.status == "failed"]
    return AgentSynthesizeResponse(synthesized_at=datetime.now(timezone.utc).isoformat(), total_tasks=len(task_ids), successful=len(findings), failed=len(errors), findings=findings, errors=errors)


@router.post("/{name}/invoke", response_model=AgentInvokeResponse)
async def invoke_agent_by_name(name: str = Path(...), req: AgentInvokeRequest | None = None, _user=Depends(require_permission("agents:invoke"))) -> AgentInvokeResponse:
    if req is None:
        raise HTTPException(422, "Informe task e context")
    return await _dispatch(name, req.task, req.context)
