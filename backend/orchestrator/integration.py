"""Orchestrator integration — FastAPI routes and WebSocket for real-time updates.

Exposes the Prometheus Orchestrator via REST endpoints and WebSocket:
- POST /api/investigations/{id}/run — start investigation
- GET  /api/investigations/{id}/status — get status
- POST /api/investigations/{id}/pause — pause investigation
- POST /api/investigations/{id}/resume — resume investigation
- WS   /ws/investigations/{id} — real-time progress stream
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.rbac import require_permission
from backend.auth.jwt import TokenError, decode_token
from backend.core.redis_client import redis_client
from backend.core.database import AsyncSessionLocal, get_db
from backend.db.models import Investigation
from backend.orchestrator import PrometheusOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigations", tags=["orchestrator"])

ws_router = APIRouter(tags=["orchestrator"])  # sem prefix: frontend conecta em /ws/investigations/{id}

# Singleton orchestrator instance
_orchestrator = PrometheusOrchestrator(use_celery=False, heartbeat_interval=5.0)

# Active WebSocket connections: investigation_id → set of WebSockets
_ws_connections: dict[str, set[WebSocket]] = {}


def _get_orchestrator() -> PrometheusOrchestrator:
    """Get the singleton orchestrator instance."""
    return _orchestrator


async def _owned_investigation(db: AsyncSession, investigation_id: str, user: Any) -> Investigation:
    investigation = await db.scalar(select(Investigation).where(Investigation.id == investigation_id))
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if user.role != "admin" and investigation.owner_id != user.sub:
        raise HTTPException(status_code=403, detail="Esta investigação pertence a outro usuário")
    return investigation


@router.post("/{investigation_id}/run", response_model=dict[str, Any])
async def run_investigation(
    investigation_id: str,
    goal: str | None = None,
    context: dict[str, Any] | None = None,
    db: AsyncSession = Depends(get_db),
    orch: PrometheusOrchestrator = Depends(_get_orchestrator),
    user=Depends(require_permission("orchestrator:run")),
) -> dict[str, Any]:
    """Start an investigation run.

    Creates a plan and begins execution. The investigation runs
    in the background — use GET /status to check progress.
    """
    investigation = await _owned_investigation(db, investigation_id, user)

    # Check if already running
    status_data = await orch.get_status(investigation_id)
    if status_data.get("state") in ("running", "planning"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation {investigation_id} is already running",
        )

    # Get goal from investigation if not provided
    if goal is None:
        goal = investigation.title

    # Create plan
    plan = await orch.create_plan(
        investigation_id=investigation_id,
        goal=goal or f"Investigation {investigation_id}",
        context={**(context or {}), "operator_id": user.sub, "investigation_id": investigation_id},
    )

    # Start execution in background
    await orch.execute_plan(investigation_id)

    return {
        "investigation_id": investigation_id,
        "status": "started",
        "plan_id": plan.plan_id,
        "steps_count": len(plan.steps),
        "message": "Investigation started. Use GET /status for progress.",
    }


@router.get("/{investigation_id}/status", response_model=dict[str, Any])
async def get_investigation_status(
    investigation_id: str,
    orch: PrometheusOrchestrator = Depends(_get_orchestrator),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("investigations:read")),
) -> dict[str, Any]:
    """Get current investigation status and progress."""
    await _owned_investigation(db, investigation_id, user)
    status_data = await orch.get_status(investigation_id)

    if status_data.get("state") == "unknown":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found",
        )

    return status_data


@router.post("/{investigation_id}/pause", response_model=dict[str, Any])
async def pause_investigation(
    investigation_id: str,
    orch: PrometheusOrchestrator = Depends(_get_orchestrator),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("orchestrator:run")),
) -> dict[str, Any]:
    """Pause a running investigation."""
    await _owned_investigation(db, investigation_id, user)
    success = await orch.pause_investigation(investigation_id)

    if not success:
        status_data = await orch.get_status(investigation_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot pause investigation in state: {status_data.get('state')}",
        )

    return {
        "investigation_id": investigation_id,
        "status": "paused",
        "message": "Investigation paused. Use POST /resume to continue.",
    }


@router.post("/{investigation_id}/resume", response_model=dict[str, Any])
async def resume_investigation(
    investigation_id: str,
    orch: PrometheusOrchestrator = Depends(_get_orchestrator),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("orchestrator:run")),
) -> dict[str, Any]:
    """Resume a paused investigation."""
    await _owned_investigation(db, investigation_id, user)
    success = await orch.resume_investigation(investigation_id)

    if not success:
        status_data = await orch.get_status(investigation_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot resume investigation in state: {status_data.get('state')}",
        )

    return {
        "investigation_id": investigation_id,
        "status": "running",
        "message": "Investigation resumed.",
    }


@router.get("/{investigation_id}/results", response_model=dict[str, Any])
async def get_investigation_results(
    investigation_id: str,
    orch: PrometheusOrchestrator = Depends(_get_orchestrator),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("investigations:read")),
) -> dict[str, Any]:
    """Get final investigation results (after completion)."""
    await _owned_investigation(db, investigation_id, user)
    results = await orch.get_results(investigation_id)

    if results.get("state") == "unknown":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found",
        )

    return results


@ws_router.websocket("/ws/investigations/{investigation_id}")
async def investigation_websocket(
    ws: WebSocket,
    investigation_id: str,
) -> None:
    """WebSocket endpoint for real-time investigation progress.

    Streams progress updates as JSON messages:
      {"type": "progress", "data": {...}}
      {"type": "state_change", "data": {...}}
      {"type": "complete", "data": {...}}
      {"type": "error", "message": "..."}
    """
    try:
        user = decode_token(ws.query_params.get("token", ""))
        if user.is_expired or user.token_type != "access":
            raise TokenError("Token inválido")
        async with AsyncSessionLocal() as db:
            await _owned_investigation(db, investigation_id, user)
    except (TokenError, HTTPException):
        await ws.close(code=4403, reason="Authentication or case access denied")
        return
    await ws.accept()

    # Register connection
    if investigation_id not in _ws_connections:
        _ws_connections[investigation_id] = set()
    _ws_connections[investigation_id].add(ws)

    try:
        # Send initial status
        status_data = await _orchestrator.get_status(investigation_id)
        await ws.send_json({
            "type": "connected",
            "investigation_id": investigation_id,
            "data": status_data,
        })

        # Subscribe to progress updates
        async def send_progress(progress: Any) -> None:
            await ws.send_json({
                "type": "progress",
                "data": progress.to_dict(),
            })

        _orchestrator._monitor.subscribe(send_progress)

        # Listen for client messages (ping, etc.)
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                data = json.loads(raw)

                if data.get("type") == "ping":
                    await ws.send_json({"type": "pong"})
                elif data.get("type") == "get_status":
                    status_data = await _orchestrator.get_status(investigation_id)
                    await ws.send_json({"type": "status", "data": status_data})

            except asyncio.TimeoutError:
                # Send keepalive
                await ws.send_json({"type": "keepalive"})
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "message": "Invalid JSON"})

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for investigation %s", investigation_id)
    except Exception as exc:
        logger.exception("WebSocket error for investigation %s", investigation_id)
        try:
            await ws.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        # Unregister connection
        _ws_connections.get(investigation_id, set()).discard(ws)
        if not _ws_connections.get(investigation_id):
            _ws_connections.pop(investigation_id, None)


async def broadcast_to_investigation(investigation_id: str, message: dict[str, Any]) -> None:
    """Broadcast a message to all WebSocket subscribers of an investigation."""
    connections = _ws_connections.get(investigation_id, set())
    dead_connections: set[WebSocket] = set()

    for ws in connections:
        try:
            await ws.send_json(message)
        except Exception:
            dead_connections.add(ws)

    # Clean up dead connections
    for ws in dead_connections:
        connections.discard(ws)
