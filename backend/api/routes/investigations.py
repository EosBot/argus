"""Investigation CRUD routes.

GET    /api/investigations           → list investigations (paginated)
POST   /api/investigations           → create investigation
GET    /api/investigations/{id}      → get investigation detail
PATCH  /api/investigations/{id}      → update investigation
DELETE /api/investigations/{id}      → delete investigation
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.auth.rbac import require_permission
from backend.core.database import get_db
from backend.db.models import Evidence, Finding, Investigation, IOC

from backend.api.models.requests import InvestigationCreateRequest, InvestigationUpdateRequest
from backend.api.models.responses import (
    InvestigationListResponse,
    InvestigationResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
    token_data=Depends(require_permission("investigations:read")),
) -> InvestigationListResponse:
    """List investigations with pagination and optional status filter."""
    query = select(Investigation).options(
        selectinload(Investigation.findings),
        selectinload(Investigation.iocs),
        selectinload(Investigation.evidence),
    )
    count_query = select(func.count(Investigation.id))

    if token_data.role != "admin":
        query = query.where(Investigation.owner_id == token_data.sub)
        count_query = count_query.where(Investigation.owner_id == token_data.sub)

    if status_filter:
        query = query.where(Investigation.status == status_filter)
        count_query = count_query.where(Investigation.status == status_filter)

    # Execute count and fetch in parallel
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = (
        query
        .order_by(Investigation.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    investigations = result.scalars().all()

    return InvestigationListResponse(
        items=[_investigation_to_response(i) for i in investigations],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    req: InvestigationCreateRequest,
    db: AsyncSession = Depends(get_db),
    token_data=Depends(require_permission("investigations:write")),
) -> InvestigationResponse:
    """Create a new investigation."""
    investigation = Investigation(
        title=req.title,
        description=req.description,
        priority=req.priority,
        tags=req.tags,
        owner_id=token_data.sub,
        status="open",
    )
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)

    return _investigation_to_response(investigation)


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    token_data=Depends(require_permission("investigations:read")),
) -> InvestigationResponse:
    """Get investigation by ID with related counts."""
    result = await db.execute(
        select(Investigation).options(
            selectinload(Investigation.findings),
            selectinload(Investigation.iocs),
            selectinload(Investigation.evidence),
        ).where(Investigation.id == investigation_id),
    )
    investigation = result.scalar_one_or_none()

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    if token_data.role != "admin" and investigation.owner_id != token_data.sub:
        raise HTTPException(status_code=403, detail="Esta investigação pertence a outro usuário")

    return _investigation_to_response(investigation)


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation_id: str,
    req: InvestigationUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token_data=Depends(require_permission("investigations:write")),
) -> InvestigationResponse:
    """Update an existing investigation."""
    result = await db.execute(
        select(Investigation).where(Investigation.id == investigation_id),
    )
    investigation = result.scalar_one_or_none()

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    if token_data.role != "admin" and investigation.owner_id != token_data.sub:
        raise HTTPException(status_code=403, detail="Esta investigação pertence a outro usuário")

    # Apply partial updates
    update_data = req.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(investigation, field, value)

    await db.commit()
    await db.refresh(investigation)

    return _investigation_to_response(investigation)


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    token_data=Depends(require_permission("investigations:delete")),
) -> None:
    """Delete an investigation and all related data."""
    result = await db.execute(
        select(Investigation).where(Investigation.id == investigation_id),
    )
    investigation = result.scalar_one_or_none()

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    if token_data.role != "admin" and investigation.owner_id != token_data.sub:
        raise HTTPException(status_code=403, detail="Esta investigação pertence a outro usuário")

    await db.delete(investigation)
    await db.commit()


def _investigation_to_response(inv: Investigation) -> InvestigationResponse:
    """Convert ORM Investigation to response model."""
    findings = []
    loaded_findings = inv.__dict__.get("findings", [])
    loaded_iocs = inv.__dict__.get("iocs", [])
    loaded_evidence = inv.__dict__.get("evidence", [])
    for finding in loaded_findings:
        source_iocs = [ioc for ioc in loaded_iocs if not ioc.source or ioc.source == finding.source]
        findings.append({
            "type": "finding", "id": finding.id, "title": finding.title,
            "severity": finding.severity, "status": "complete",
            "iocs": [{"type": "ioc", "id": i.id, "value": i.value, "kind": i.type, "risk": i.severity if i.severity in {"low", "medium", "high"} else "medium"} for i in source_iocs],
            "evidence": [],
        })
    evidence = [{"type": "evidence", "id": e.id, "title": e.source_url or e.type, "kind": e.type, "status": "complete"} for e in loaded_evidence]
    if evidence and not findings:
        findings.append({"type": "finding", "id": f"evidence-{inv.id}", "title": "Evidências coletadas", "severity": "info", "status": "complete", "iocs": [], "evidence": evidence})
    targets = [{"type": "target", "id": f"case-{inv.id}", "name": inv.description or inv.title, "status": "active" if inv.status == "open" else "complete", "findings": findings}]
    return InvestigationResponse(
        id=inv.id,
        title=inv.title,
        description=inv.description,
        status=inv.status,
        priority=inv.priority,
        owner_id=inv.owner_id,
        tags=inv.tags or [],
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        closed_at=inv.closed_at,
        targets=targets,
    )
