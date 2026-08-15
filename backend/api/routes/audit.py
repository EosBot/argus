"""Security audit route.

GET /api/audit/security → run unified security audit and return scored report
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from backend.auth.rbac import require_permission
from backend.opsec.security_audit import SecurityAuditor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/security")
async def security_audit(
    _user=Depends(require_permission("audit:read")),
) -> dict[str, Any]:
    """Run unified security audit.

    Returns a scored report with individual check results and
    actionable recommendations. Requires ``audit:read`` permission.
    """
    auditor = SecurityAuditor()
    try:
        return await auditor.run_audit()
    except Exception as exc:
        logger.exception("Security audit failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {exc}",
        ) from exc
