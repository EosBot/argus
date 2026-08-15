"""Monitoring and system status routes.

GET  /api/monitoring/health  → comprehensive health check
GET  /api/monitoring/stats   → system statistics
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.rbac import require_permission
from backend.core.config import settings
from backend.core.database import get_db
from backend.core.neo4j_client import neo4j_client
from backend.core.redis_client import redis_client
from backend.db.models import Evidence, Finding, Investigation, IOC

from backend.api.models.responses import HealthResponse, SystemStatsResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Comprehensive health check including all service dependencies."""
    # Check Redis
    redis_ok = await redis_client.ping()

    # Check Neo4j
    neo4j_ok = await neo4j_client.verify_connectivity()

    # Check database (lazy — only if we can get a session)
    db_ok = False
    try:
        from backend.core.database import engine
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    return HealthResponse(
        status="ok" if redis_ok and neo4j_ok and db_ok else "degraded",
        service="argus-backend",
        version=settings.app_version,
        litellm_base_url=settings.litellm_base_url,
        model=settings.litellm_model,
        redis_connected=redis_ok,
        neo4j_connected=neo4j_ok,
        database_connected=db_ok,
    )


@router.get("/stats", response_model=SystemStatsResponse)
async def system_stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_permission("monitoring:read")),
) -> SystemStatsResponse:
    """Return system-wide statistics."""
    # Investigation counts
    inv_total = await db.execute(select(func.count(Investigation.id)))
    inv_open = await db.execute(
        select(func.count(Investigation.id)).where(Investigation.status == "open"),
    )

    # IOC count
    ioc_total = await db.execute(select(func.count(IOC.id)))

    # Finding count
    finding_total = await db.execute(select(func.count(Finding.id)))

    # Evidence count
    evidence_total = await db.execute(select(func.count(Evidence.id)))

    return SystemStatsResponse(
        investigations_total=inv_total.scalar_one(),
        investigations_open=inv_open.scalar_one(),
        iocs_total=ioc_total.scalar_one(),
        findings_total=finding_total.scalar_one(),
        evidence_total=evidence_total.scalar_one(),
    )
