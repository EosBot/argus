"""Authenticated collection routes with per-investigation ownership.

GET  /api/collections              → list all collection tasks (from Redis)
POST /api/collections              → dispatch a collection agent
GET  /api/collections/{id}         → poll a task's status
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.rbac import require_permission
from backend.core.database import get_db
from backend.core.redis_client import redis_client
from backend.db.models import AuditLog, Investigation
from backend.orchestrator.dispatcher import AgentDispatcher, dispatcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/collections", tags=["collections"], dependencies=[Depends(require_permission("agents:invoke"))])

# Valid collection agent names — must match ``Agent.name`` in backend/agents/.
VALID_AGENTS: set[str] = {"osint_collector", "dark_web_crawler"}

# TTL for stored collection records (seconds).
TASK_TTL = 7200


class CollectionCreate(BaseModel):
    """Request body to create a new collection task."""

    agent: str = Field(..., description="Agent name (osint_collector | dark_web_crawler)")
    query: str = Field(..., description="Search query for the agent")
    investigation_id: str | None = Field(default=None, description="Case receiving the collected evidence")
    params: dict[str, Any] = Field(
        default_factory=dict, description="Optional agent-specific parameters"
    )


def _get_dispatcher() -> AgentDispatcher:
    return dispatcher


@router.get("")
async def list_collections(user=Depends(require_permission("agents:invoke"))) -> dict[str, Any]:
    """List every collection task stored in Redis."""
    keys = await redis_client.keys("collection:*")
    items: list[dict[str, Any]] = []
    for key in keys:
        data = await redis_client.get_json(key)
        if data and (user.role == "admin" or data.get("owner_id") == user.sub):
            items.append(data)
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"items": items}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_collection(
    body: CollectionCreate,
    user=Depends(require_permission("agents:invoke")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Validate the agent, dispatch the task, and store it in Redis."""
    if body.agent not in VALID_AGENTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid agent '{body.agent}'. "
                f"Valid agents: {sorted(VALID_AGENTS)}"
            ),
        )

    if body.investigation_id:
        investigation = await db.scalar(select(Investigation).where(Investigation.id == body.investigation_id))
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigação não encontrada")
        if user.role != "admin" and investigation.owner_id != user.sub:
            raise HTTPException(status_code=403, detail="Esta investigação pertence a outro usuário")

    task_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    dispatcher = _get_dispatcher()
    result = await dispatcher.dispatch(
        agent_name=body.agent,
        task=body.query,
        context={**(body.params or {}), "investigation_id": body.investigation_id, "operator_id": user.sub},
    )

    record: dict[str, Any] = {
        "id": task_id,
        "agent": body.agent,
        "query": body.query,
        "params": body.params or {},
        "investigation_id": body.investigation_id,
        "owner_id": user.sub,
        "status": _ui_status(result.status),
        "dispatch_task_id": result.task_id,
        "created_at": now,
    }
    await redis_client.set_json(f"collection:{task_id}", record, ex=TASK_TTL)
    db.add(AuditLog(
        user_id=user.sub,
        action="collection.start",
        resource_type="investigation" if body.investigation_id else "collection",
        resource_id=body.investigation_id or task_id,
        details={"collection_id": task_id, "agent": body.agent, "dispatch_task_id": result.task_id, "query": body.query[:500]},
    ))

    logger.info(
        "Collection %s created: agent=%s query=%r dispatch=%s",
        task_id, body.agent, body.query, result.task_id,
    )
    return {
        "id": task_id,
        "status": _ui_status(result.status),
        "agent": body.agent,
        "query": body.query,
    }


@router.get("/{collection_id}")
async def get_collection(collection_id: str, user=Depends(require_permission("agents:invoke"))) -> dict[str, Any]:
    """Get a collection task by ID, polling the dispatcher for fresh status."""
    key = f"collection:{collection_id}"
    record = await redis_client.get_json(key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collection '{collection_id}' not found",
        )
    if user.role != "admin" and record.get("owner_id") != user.sub:
        raise HTTPException(status_code=403, detail="Esta coleta pertence a outro usuário")

    dispatch_task_id = record.get("dispatch_task_id")
    if dispatch_task_id and record.get("status") in ("queued", "running"):
        dispatcher = _get_dispatcher()
        current = await dispatcher.get_status(dispatch_task_id)
        if current is not None:
            record["status"] = _ui_status(current.status)
            if current.result is not None:
                record["result"] = current.result
            if current.error is not None:
                record["error"] = current.error
            await redis_client.set_json(key, record, ex=TASK_TTL)

    return record


def _ui_status(value: str) -> str:
    return {"queued": "pending", "completed": "done", "failed": "error"}.get(value, value)
