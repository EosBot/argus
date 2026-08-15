"""Authentication middleware (ASGI).

Wraps the application to extract and validate JWT tokens from the
Authorization header, attaching the decoded TokenData to the request
scope for downstream handlers. Also handles the login endpoint logic.
"""

from __future__ import annotations

import logging
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.auth.jwt import TokenError, decode_token

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that validates JWT tokens and attaches user info.

    This middleware does NOT reject unauthenticated requests — it only
    attaches ``request.state.user`` when a valid token is present.
    Individual routes enforce authentication via the RBAC dependencies.
    """

    # Paths that never require token validation
    EXEMPT_PATHS = {
        "/",
        "/health",
        "/ready",
        "/docs",
        "/openapi.json",
        "/api/auth/login",
        "/api/auth/register",
    }

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        """Process the request, attaching user info if a valid token exists."""
        path = request.url.path

        # Try to extract and validate token
        user = self._extract_user(request)
        request.state.user = user

        response = await call_next(request)
        return response

    def _extract_user(self, request: Request) -> Any | None:
        """Extract and decode JWT from Authorization header."""
        auth_header = request.headers.get("authorization")
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None

        token = parts[1]
        try:
            return decode_token(token)
        except TokenError:
            return None
