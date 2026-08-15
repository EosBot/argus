"""Threat intelligence routes.

GET  /api/threats       → list threat records (paginated)
POST /api/threats       → create threat record
GET  /api/threats/{id}  → get threat detail
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.rbac import require_permission
from backend.core.database import get_db

from backend.api.models.requests import ThreatCreateRequest
from backend.api.models.responses import ThreatListResponse, ThreatResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["threats"])

# In-memory threat store (until threats table is migrated)
# In production, this would be a proper SQLAlchemy model
_threats: dict[str, dict] = {}


@router.get("", response_model=ThreatListResponse)
async def list_threats(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    _user=Depends(require_permission("threats:read")),
) -> ThreatListResponse:
    """List threat intelligence records."""
    all_threats = sorted(
        _threats.values(),
        key=lambda t: t.get("created_at", ""),
        reverse=True,
    )
    total = len(all_threats)
    start = (page - 1) * page_size
    items = all_threats[start:start + page_size]

    return ThreatListResponse(
        items=[ThreatResponse(**t) for t in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    req: ThreatCreateRequest,
    _user=Depends(require_permission("threats:write")),
) -> ThreatResponse:
    """Create a new threat intelligence record."""
    threat_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    threat = {
        "id": threat_id,
        "name": req.name,
        "description": req.description,
        "severity": req.severity,
        "threat_type": req.threat_type,
        "source": req.source,
        "indicators": req.indicators,
        "context": req.context,
        "created_at": now,
    }
    _threats[threat_id] = threat

    return ThreatResponse(**threat)


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: str,
    _user=Depends(require_permission("threats:read")),
) -> ThreatResponse:
    """Get threat by ID."""
    threat = _threats.get(threat_id)
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat '{threat_id}' not found",
        )
    return ThreatResponse(**threat)
