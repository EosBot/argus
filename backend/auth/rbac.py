"""Role-Based Access Control (RBAC).

Defines roles, permissions, and dependency injectors for FastAPI routes.
Three roles with increasing privilege:

    viewer      → read-only access to investigations and findings
    investigator → can create/update investigations, run scans
    admin       → full access including user management
"""

from __future__ import annotations

import logging
from enum import Enum
from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.auth.jwt import TokenData, TokenError, decode_token

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """User roles ordered by privilege level."""

    VIEWER = "viewer"
    INVESTIGATOR = "investigator"
    ADMIN = "admin"


# -- Permission matrix ---------------------------------------------------------

ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {
        "investigations:read",
        "findings:read",
        "iocs:read",
        "threats:read",
        "monitoring:read",
    },
    Role.INVESTIGATOR: {
        "investigations:read",
        "investigations:write",
        "findings:read",
        "findings:write",
        "iocs:read",
        "iocs:write",
        "threats:read",
        "threats:write",
        "search:execute",
        "scrape:execute",
        "pentest:execute",
        "agents:invoke",
        "monitoring:read",
        "orchestrator:run",
    },
    Role.ADMIN: {
        # Admin has all permissions
        "investigations:read",
        "investigations:write",
        "investigations:delete",
        "findings:read",
        "findings:write",
        "findings:delete",
        "iocs:read",
        "iocs:write",
        "iocs:delete",
        "threats:read",
        "threats:write",
        "threats:delete",
        "search:execute",
        "scrape:execute",
        "pentest:execute",
        "agents:invoke",
        "orchestrator:run",
        "monitoring:read",
        "monitoring:write",
        "users:manage",
        "audit:read",
    },
}

# Security scheme for FastAPI docs
bearer_scheme = HTTPBearer(auto_error=False)


def has_permission(role: Role, permission: str) -> bool:
    """Check whether *role* grants *permission*."""
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_permission(permission: str) -> Callable:
    """FastAPI dependency factory: enforce that the user has *permission*.

    Usage::

        @app.get("/api/investigations")
        async def list_investigations(
            user: TokenData = Depends(require_permission("investigations:read")),
        ):
            ...
    """

    async def _dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> TokenData:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            token_data = decode_token(credentials.credentials)
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        if token_data.is_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not has_permission(Role(token_data.role), permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: '{permission}' required",
            )

        return token_data

    return _dependency


def require_role(min_role: Role) -> Callable:
    """FastAPI dependency factory: enforce a minimum role level.

    Usage::

        @app.delete("/api/users/{user_id}")
        async def delete_user(
            user: TokenData = Depends(require_role(Role.ADMIN)),
        ):
            ...
    """
    role_hierarchy = [Role.VIEWER, Role.INVESTIGATOR, Role.ADMIN]

    async def _dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> TokenData:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            token_data = decode_token(credentials.credentials)
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        if token_data.is_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_rank = role_hierarchy.index(Role(token_data.role)) if token_data.role in [r.value for r in role_hierarchy] else -1
        required_rank = role_hierarchy.index(min_role)

        if user_rank < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{min_role.value}' or higher required",
            )

        return token_data

    return _dependency
