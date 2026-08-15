"""IOC (Indicator of Compromise) routes.

GET  /api/iocs            → list IOCs (paginated, filterable by type/investigation)
POST /api/iocs            → create IOC record
GET  /api/iocs/{id}       → get IOC detail
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.rbac import require_permission
from backend.core.database import get_db
from backend.db.models import IOC

from backend.api.models.requests import IOCCreateRequest
from backend.api.models.responses import IOCListResponse, IOCResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    ioc_type: str | None = Query(default=None, alias="type"),
    investigation_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_permission("iocs:read")),
) -> IOCListResponse:
    """List IOCs with pagination and optional filters."""
    query = select(IOC)
    count_query = select(func.count(IOC.id))

    if ioc_type:
        query = query.where(IOC.type == ioc_type)
        count_query = count_query.where(IOC.type == ioc_type)
    if investigation_id:
        query = query.where(IOC.investigation_id == investigation_id)
        count_query = count_query.where(IOC.investigation_id == investigation_id)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = (
        query
        .order_by(IOC.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    iocs = result.scalars().all()

    return IOCListResponse(
        items=[_ioc_to_response(i) for i in iocs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    req: IOCCreateRequest,
    investigation_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_permission("iocs:write")),
) -> IOCResponse:
    """Create a new IOC record."""
    ioc = IOC(
        type=req.type,
        value=req.value,
        threat_type=req.threat_type,
        severity=req.severity,
        source=req.source,
        context=req.context,
        investigation_id=investigation_id or "default",
    )
    db.add(ioc)
    await db.flush()
    await db.refresh(ioc)

    return _ioc_to_response(ioc)


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_permission("iocs:read")),
) -> IOCResponse:
    """Get IOC by ID."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()

    if ioc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{ioc_id}' not found",
        )

    return _ioc_to_response(ioc)


def _ioc_to_response(ioc: IOC) -> IOCResponse:
    """Convert ORM IOC to response model."""
    return IOCResponse(
        id=ioc.id,
        investigation_id=ioc.investigation_id,
        type=ioc.type,
        value=ioc.value,
        threat_type=ioc.threat_type,
        severity=ioc.severity,
        source=ioc.source,
        context=ioc.context,
        created_at=ioc.created_at,
    )
